"""Archipel TCP client for secure peer-to-peer communication.

Implements the client side of the Archipel protocol:
1. Establishes a TCP connection to a remote node.
2. Performs a Noise-inspired handshake (HELLO / HELLO_REPLY / AUTH /
   AUTH_OK) using X25519 ephemeral key exchange and Ed25519 identity
   verification.
3. Derives an AES-256-GCM session key via HKDF-SHA256.
4. Sends encrypted messages and chunked file transfers over the
   established secure tunnel.
"""

import asyncio
import hashlib
import struct
import time
from pathlib import Path
from typing import Optional

from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError
from nacl.public import PublicKey

from src.crypto.session import (
    generate_ephemeral_keypair,
    derive_shared_secret,
    derive_session_key,
    encrypt_message,
    decrypt_message,
)
from src.network.constants import PacketType, HEADER_SIZE, HMAC_SIZE, HEADER_FORMAT
from src.network.packet import ArchipelPacket
from src.transfer.manifest import Manifest, build_manifest
from src.transfer.chunking import read_chunk


class ArchipelTcpClient:
    """Client-side handler for the Archipel TCP protocol.

    Typical usage::

        client = ArchipelTcpClient(node_id, hmac_key, priv_key)
        if await client.connect("192.168.1.10", 7777):
            await client.send_msg("Hello!")
            await client.send_file(Path("report.pdf"))
            client.close()

    Attributes:
        node_id: Raw 32-byte Ed25519 public key (local identity).
        hmac_key: Shared HMAC key for packet integrity.
        priv_key: Ed25519 private key for signing.
        session_key: AES-256-GCM key derived after handshake.
    """

    def __init__(self, node_id: bytes, hmac_key: bytes, priv_key: SigningKey):
        """Initialise the client with local node credentials.

        Args:
            node_id: Raw 32-byte Ed25519 public key.
            hmac_key: HMAC key for packet authentication.
            priv_key: Ed25519 signing key.
        """
        self.node_id = node_id
        self.hmac_key = hmac_key
        self.priv_key = priv_key
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.session_key: Optional[bytes] = None

    # ----- Connection & handshake -------------------------------------------

    async def connect(self, host: str, port: int) -> bool:
        """Open a TCP connection and perform the handshake.

        Args:
            host: Remote IP address or hostname.
            port: Remote TCP port number.

        Returns:
            ``True`` if the handshake succeeded and the tunnel is ready.
        """
        try:
            self.reader, self.writer = await asyncio.open_connection(host, port)
            success = await self._perform_handshake()
            if not success:
                self.close()
                return False
            return True
        except Exception as e:
            print(f"[CLIENT] Connection error: {e}")
            if self.writer:
                self.close()
            return False

    async def _perform_handshake(self) -> bool:
        """Execute the 4-step Noise-inspired handshake.

        Steps:
            1. Send HELLO with our ephemeral X25519 public key.
            2. Receive HELLO_REPLY with peer's ephemeral key + Ed25519
               signature proving their identity.
            3. Derive shared secret via X25519, then session key via HKDF.
            4. Send AUTH (signature over shared secret) and await AUTH_OK.

        Returns:
            ``True`` on successful mutual authentication.
        """
        # Step 1: Generate ephemeral keypair and send HELLO.
        e_priv, e_pub = generate_ephemeral_keypair()
        timestamp = int(time.time())
        hello_payload = bytes(e_pub) + struct.pack("!Q", timestamp)
        await self._send_packet(PacketType.HELLO, hello_payload)

        # Step 2: Receive and verify HELLO_REPLY.
        reply = await self._recv_packet()
        if reply.packet_type != PacketType.HELLO_REPLY:
            print("[CLIENT] Expected HELLO_REPLY")
            return False

        peer_node_id = reply.node_id
        if len(reply.payload) < 32:
            return False

        # Extract peer's ephemeral public key and identity signature.
        e_peer_pub_bytes = reply.payload[:32]
        sig_b = reply.payload[32:]
        e_peer_pub = PublicKey(e_peer_pub_bytes)

        # Verify that the peer signed their ephemeral key.
        verify_key = VerifyKey(peer_node_id)
        try:
            verify_key.verify(e_peer_pub_bytes, sig_b)
        except BadSignatureError:
            print("[CLIENT] Invalid signature from peer")
            return False

        # Step 3: Derive shared secret and session key.
        shared_secret = derive_shared_secret(e_priv, e_peer_pub)
        self.session_key = derive_session_key(shared_secret)

        # Step 4: Prove our identity by signing the shared secret.
        sig_a = self.priv_key.sign(shared_secret).signature
        await self._send_packet(PacketType.AUTH, sig_a)

        # Wait for server confirmation.
        auth_ok = await self._recv_packet()
        if auth_ok.packet_type != PacketType.AUTH_OK:
            print("[CLIENT] Expected AUTH_OK")
            return False

        print(f"[CLIENT] Handshake complete with {peer_node_id.hex()[:12]}...")
        return True

    # ----- Packet I/O -------------------------------------------------------

    async def _send_packet(self, packet_type: PacketType, payload: bytes):
        """Serialise and send a single Archipel packet.

        Args:
            packet_type: Type enum value for the packet header.
            payload: Raw payload bytes.
        """
        if not self.writer:
            return
        pkt = ArchipelPacket(
            packet_type=packet_type, node_id=self.node_id, payload=payload
        )
        data = pkt.pack(self.hmac_key)
        self.writer.write(data)
        await self.writer.drain()

    async def _recv_packet(self) -> ArchipelPacket:
        """Read and deserialise a single Archipel packet from the stream.

        Returns:
            A validated :class:`ArchipelPacket` instance.

        Raises:
            ConnectionError: If the stream is not connected.
        """
        if not self.reader:
            raise ConnectionError("Not connected")
        # Read the fixed-size header to learn the payload length.
        header = await self.reader.readexactly(HEADER_SIZE)
        magic, p_type, sender_node_id, payload_len = struct.unpack(
            HEADER_FORMAT, header
        )
        # Read the variable-length payload plus the trailing HMAC.
        rest = await self.reader.readexactly(payload_len + HMAC_SIZE)
        raw_packet = header + rest
        return ArchipelPacket.unpack(raw_packet, self.hmac_key)

    # ----- High-level operations --------------------------------------------

    async def send_msg(self, text: str):
        """Encrypt and send a text message over the secure tunnel.

        Args:
            text: Plain-text message string.

        Raises:
            ValueError: If the session key has not been established.
        """
        if not self.session_key:
            raise ValueError("Session key not established")
        nonce, ciphertext, tag = encrypt_message(
            self.session_key, text.encode("utf-8")
        )
        # Payload layout: nonce (12 B) + tag (16 B) + ciphertext.
        payload = nonce + tag + ciphertext
        await self._send_packet(PacketType.MSG, payload)

    async def send_file(self, filepath: Path):
        """Send an entire file as a manifest followed by encrypted chunks.

        Workflow:
            1. Build a signed manifest (SHA-256 per chunk + Ed25519 sig).
            2. Send the manifest encrypted with AES-GCM.
            3. Stream each 512 KB chunk, wait for an ACK after every one.
            4. On HASH_MISMATCH ACK, automatically resend the chunk.

        Args:
            filepath: Path to the file to send.

        Raises:
            ValueError: If the session key has not been established.
        """
        if not self.session_key:
            raise ValueError("Session key not established")

        filepath = Path(filepath)
        if not filepath.exists():
            print(f"[CLIENT] File not found: {filepath}")
            return

        # Build and sign the manifest.
        print(f"[CLIENT] Building manifest for '{filepath.name}'...")
        manifest = build_manifest(filepath, self.node_id, self.priv_key)
        manifest_json = manifest.to_json()

        # Send the encrypted manifest packet.
        nonce, ciphertext, tag = encrypt_message(
            self.session_key, manifest_json.encode("utf-8")
        )
        await self._send_packet(PacketType.MANIFEST, nonce + tag + ciphertext)
        print(f"[CLIENT] Manifest sent ({manifest.nb_chunks} chunks, {manifest.size} bytes)")

        # Stream each chunk with ACK-based flow control.
        start_time = time.time()
        for i, chunk_info in enumerate(manifest.chunks):
            # Read the chunk from disk and compute its hash.
            chunk_data = read_chunk(filepath, i, manifest.chunk_size)
            chunk_hash = hashlib.sha256(chunk_data).hexdigest()

            # Assemble the raw payload:
            #   file_id (64 B hex) + chunk_idx (4 B uint32) +
            #   chunk_hash (64 B hex) + chunk data.
            raw = (
                manifest.file_id.encode("ascii")
                + struct.pack("!I", i)
                + chunk_hash.encode("ascii")
                + chunk_data
            )

            # Encrypt and send the chunk.
            nonce, ciphertext, tag = encrypt_message(self.session_key, raw)
            await self._send_packet(
                PacketType.CHUNK_DATA, nonce + tag + ciphertext
            )

            # Wait for the receiver's ACK.
            try:
                ack = await asyncio.wait_for(self._recv_packet(), timeout=30.0)
                if ack.packet_type == PacketType.ACK:
                    ack_idx = struct.unpack("!I", ack.payload[:4])[0]
                    status = ack.payload[4]
                    if status == 0x01:  # HASH_MISMATCH -> resend once.
                        print(f"\n[CLIENT] Hash mismatch on chunk {i}, resending...")
                        nonce, ciphertext, tag = encrypt_message(
                            self.session_key, raw
                        )
                        await self._send_packet(
                            PacketType.CHUNK_DATA, nonce + tag + ciphertext
                        )
                        ack = await asyncio.wait_for(
                            self._recv_packet(), timeout=30.0
                        )
            except asyncio.TimeoutError:
                print(f"\n[CLIENT] Timeout waiting for ACK on chunk {i}")

            # Display progress.
            pct = ((i + 1) / manifest.nb_chunks) * 100
            print(
                f"\r[CLIENT] Sending: {i+1}/{manifest.nb_chunks} ({pct:.1f}%)",
                end="", flush=True,
            )

        # Print transfer summary.
        elapsed = time.time() - start_time
        speed = manifest.size / elapsed / 1024 / 1024 if elapsed > 0 else 0
        print(
            f"\n[CLIENT] Transfer complete! "
            f"{manifest.size} bytes in {elapsed:.1f}s ({speed:.2f} MB/s)"
        )

    # ----- Teardown ---------------------------------------------------------

    def close(self):
        """Close the underlying TCP connection."""
        if self.writer:
            self.writer.close()
