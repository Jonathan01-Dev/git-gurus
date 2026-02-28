import asyncio
import hashlib
import struct
import time
from pathlib import Path
from typing import Optional

from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError
from nacl.public import PublicKey

from src.crypto.session import generate_ephemeral_keypair, derive_shared_secret, derive_session_key, encrypt_message, decrypt_message
from src.network.constants import PacketType, HEADER_SIZE, HMAC_SIZE, HEADER_FORMAT
from src.network.packet import ArchipelPacket
from src.transfer.manifest import Manifest, build_manifest
from src.transfer.chunking import read_chunk


class ArchipelTcpClient:
    def __init__(self, node_id: bytes, hmac_key: bytes, priv_key: SigningKey):
        self.node_id = node_id
        self.hmac_key = hmac_key
        self.priv_key = priv_key
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.session_key: Optional[bytes] = None

    async def connect(self, host: str, port: int) -> bool:
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

    async def _send_packet(self, packet_type: PacketType, payload: bytes):
        if not self.writer:
            return
        pkt = ArchipelPacket(packet_type=packet_type, node_id=self.node_id, payload=payload)
        data = pkt.pack(self.hmac_key)
        self.writer.write(data)
        await self.writer.drain()

    async def _recv_packet(self) -> ArchipelPacket:
        if not self.reader:
            raise ConnectionError("Not connected")
        header = await self.reader.readexactly(HEADER_SIZE)
        magic, p_type, sender_node_id, payload_len = struct.unpack(HEADER_FORMAT, header)
        rest = await self.reader.readexactly(payload_len + HMAC_SIZE)
        raw_packet = header + rest
        return ArchipelPacket.unpack(raw_packet, self.hmac_key)

    async def _perform_handshake(self) -> bool:
        e_priv, e_pub = generate_ephemeral_keypair()
        timestamp = int(time.time())
        hello_payload = bytes(e_pub) + struct.pack("!Q", timestamp)
        await self._send_packet(PacketType.HELLO, hello_payload)

        reply = await self._recv_packet()
        if reply.packet_type != PacketType.HELLO_REPLY:
            print("[CLIENT] Expected HELLO_REPLY")
            return False

        peer_node_id = reply.node_id
        if len(reply.payload) < 32:
            return False

        e_peer_pub_bytes = reply.payload[:32]
        sig_b = reply.payload[32:]
        e_peer_pub = PublicKey(e_peer_pub_bytes)

        verify_key = VerifyKey(peer_node_id)
        try:
            verify_key.verify(e_peer_pub_bytes, sig_b)
        except BadSignatureError:
            print("[CLIENT] Invalid signature from peer")
            return False

        shared_secret = derive_shared_secret(e_priv, e_peer_pub)
        self.session_key = derive_session_key(shared_secret)

        sig_a = self.priv_key.sign(shared_secret).signature
        await self._send_packet(PacketType.AUTH, sig_a)

        auth_ok = await self._recv_packet()
        if auth_ok.packet_type != PacketType.AUTH_OK:
            print("[CLIENT] Expected AUTH_OK")
            return False

        print(f"[CLIENT] Handshake complete with {peer_node_id.hex()[:12]}...")
        return True

    async def send_msg(self, text: str):
        if not self.session_key:
            raise ValueError("Session key not established")
        nonce, ciphertext, tag = encrypt_message(self.session_key, text.encode("utf-8"))
        payload = nonce + tag + ciphertext
        await self._send_packet(PacketType.MSG, payload)

    async def send_file(self, filepath: Path):
        """Send an entire file: manifest first, then all chunks."""
        if not self.session_key:
            raise ValueError("Session key not established")

        filepath = Path(filepath)
        if not filepath.exists():
            print(f"[CLIENT] File not found: {filepath}")
            return

        print(f"[CLIENT] Building manifest for '{filepath.name}'...")
        manifest = build_manifest(filepath, self.node_id, self.priv_key)
        manifest_json = manifest.to_json()

        # Send manifest (encrypted)
        nonce, ciphertext, tag = encrypt_message(self.session_key, manifest_json.encode("utf-8"))
        await self._send_packet(PacketType.MANIFEST, nonce + tag + ciphertext)
        print(f"[CLIENT] Manifest sent ({manifest.nb_chunks} chunks, {manifest.size} bytes)")

        # Send each chunk
        start_time = time.time()
        for i, chunk_info in enumerate(manifest.chunks):
            chunk_data = read_chunk(filepath, i, manifest.chunk_size)
            chunk_hash = hashlib.sha256(chunk_data).hexdigest()

            # raw = file_id(64) + chunk_idx(4) + chunk_hash(64) + data
            raw = manifest.file_id.encode("ascii") + struct.pack("!I", i) + chunk_hash.encode("ascii") + chunk_data

            nonce, ciphertext, tag = encrypt_message(self.session_key, raw)
            await self._send_packet(PacketType.CHUNK_DATA, nonce + tag + ciphertext)

            # Wait for ACK
            try:
                ack = await asyncio.wait_for(self._recv_packet(), timeout=30.0)
                if ack.packet_type == PacketType.ACK:
                    ack_idx = struct.unpack("!I", ack.payload[:4])[0]
                    status = ack.payload[4]
                    if status == 0x01:  # HASH_MISMATCH, resend
                        print(f"\n[CLIENT] Hash mismatch on chunk {i}, resending...")
                        nonce, ciphertext, tag = encrypt_message(self.session_key, raw)
                        await self._send_packet(PacketType.CHUNK_DATA, nonce + tag + ciphertext)
                        ack = await asyncio.wait_for(self._recv_packet(), timeout=30.0)
            except asyncio.TimeoutError:
                print(f"\n[CLIENT] Timeout waiting for ACK on chunk {i}")

            pct = ((i + 1) / manifest.nb_chunks) * 100
            print(f"\r[CLIENT] Sending: {i+1}/{manifest.nb_chunks} ({pct:.1f}%)", end="", flush=True)

        elapsed = time.time() - start_time
        speed = manifest.size / elapsed / 1024 / 1024 if elapsed > 0 else 0
        print(f"\n[CLIENT] Transfer complete! {manifest.size} bytes in {elapsed:.1f}s ({speed:.2f} MB/s)")

    def close(self):
        if self.writer:
            self.writer.close()
