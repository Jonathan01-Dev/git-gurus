"""Archipel TCP server for secure peer-to-peer communication.

Implements the server side of the Archipel protocol:
1. Listens for incoming TCP connections.
2. Performs a Noise-inspired handshake (HELLO / HELLO_REPLY / AUTH /
   AUTH_OK) using X25519 ephemeral key exchange and Ed25519 identity
   verification with TOFU-based trust.
3. Derives an AES-256-GCM session key via HKDF-SHA256.
4. Enters a packet loop that handles encrypted messages, manifest
   reception, chunk data storage with SHA-256 verification, chunk
   request serving, and automatic file reassembly.
"""

import asyncio
import hashlib
import json
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
from src.crypto.trust_store import TrustStore
from src.network.constants import PacketType, HEADER_SIZE, HMAC_SIZE, HEADER_FORMAT
from src.network.packet import ArchipelPacket
from src.transfer.chunk_store import ChunkStore
from src.transfer.manifest import Manifest
from src.network.message_history import MessageHistory
from src.ai.gemini_service import GeminiService


class ArchipelTcpServer:
    """Server-side handler for the Archipel TCP protocol.

    The server accepts multiple concurrent clients.  Each client
    connection goes through the handshake, then enters an event loop
    that multiplexes MSG, MANIFEST, CHUNK_DATA, and CHUNK_REQ packets.

    Attributes:
        node_id: Raw 32-byte Ed25519 public key (local identity).
        hmac_key: Shared HMAC key for packet integrity.
        priv_key: Ed25519 private key for signing.
        trust_store: TOFU trust database.
        port: TCP port to listen on.
        chunk_store: Local storage for received file chunks.
        source_files: Mapping of file_id -> Path for files we serve.
    """

    def __init__(
        self,
        node_id: bytes,
        hmac_key: bytes,
        priv_key: SigningKey,
        trust_store: TrustStore,
        port: int = 7777,
        api_key: Optional[str] = None,
        no_ai: bool = False,
    ):
        """Initialise the server with node credentials and storage.

        Args:
            node_id: Raw 32-byte Ed25519 public key.
            hmac_key: HMAC key for packet authentication.
            priv_key: Ed25519 signing key.
            trust_store: Pre-loaded TOFU trust store.
            port: TCP port to bind to (default 7777).
            api_key: Optional Gemini API key.
            no_ai: If True, AI features are disabled.
        """
        self.node_id = node_id
        self.hmac_key = hmac_key
        self.priv_key = priv_key
        self.trust_store = trust_store
        self.port = port
        self._server: Optional[asyncio.AbstractServer] = None
        self.no_ai = no_ai

        # Initialise chunk storage.
        self.chunk_store = ChunkStore(Path(".archipel"))
        self.chunk_store.load_index()

        # Initialise AI and History
        self.history = MessageHistory(max_size=20)
        self.ai = GeminiService(api_key=api_key)

        # Maps file_id -> local filepath for files we can serve directly.
        self.source_files: dict[str, Path] = {}

    # ----- Lifecycle --------------------------------------------------------

    async def start(self):
        """Start listening for incoming connections (blocking)."""
        self._server = await asyncio.start_server(
            self._handle_client, "0.0.0.0", self.port
        )
        print(f"[SERVER] Listening on 0.0.0.0:{self.port}")
        async with self._server:
            await self._server.serve_forever()

    def register_source_file(self, file_id: str, filepath: Path):
        """Register a local file so we can serve its chunks on request.

        Args:
            file_id: SHA-256 hex digest of the file.
            filepath: Local path to the original file.
        """
        self.source_files[file_id] = filepath

    # ----- Packet I/O -------------------------------------------------------

    async def _send_packet(
        self, writer: asyncio.StreamWriter, packet_type: PacketType, payload: bytes
    ):
        """Serialise and send a single Archipel packet.

        Args:
            writer: asyncio stream to write to.
            packet_type: Packet type enum value.
            payload: Raw payload bytes.
        """
        pkt = ArchipelPacket(
            packet_type=packet_type, node_id=self.node_id, payload=payload
        )
        data = pkt.pack(self.hmac_key)
        writer.write(data)
        await writer.drain()

    async def _recv_packet(self, reader: asyncio.StreamReader) -> ArchipelPacket:
        """Read and deserialise a single Archipel packet.

        Args:
            reader: asyncio stream to read from.

        Returns:
            A validated :class:`ArchipelPacket`.
        """
        header = await reader.readexactly(HEADER_SIZE)
        magic, p_type, sender_node_id, payload_len = struct.unpack(
            HEADER_FORMAT, header
        )
        rest = await reader.readexactly(payload_len + HMAC_SIZE)
        raw_packet = header + rest
        return ArchipelPacket.unpack(raw_packet, self.hmac_key)

    # ----- Handshake --------------------------------------------------------

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        """Handle a single client connection: handshake, then packet loop.

        Called automatically by asyncio for every new connection.

        Args:
            reader: asyncio stream reader.
            writer: asyncio stream writer.
        """
        peer_addr = writer.get_extra_info("peername")
        try:
            # Step 1: Expect HELLO from the client.
            hello = await asyncio.wait_for(
                self._recv_packet(reader), timeout=10.0
            )
            if hello.packet_type != PacketType.HELLO:
                return

            peer_node_id = hello.node_id
            e_peer_pub_bytes = hello.payload[:32]
            e_peer_pub = PublicKey(e_peer_pub_bytes)

            # Step 2: Reply with our ephemeral key + identity signature.
            e_priv, e_pub = generate_ephemeral_keypair()
            e_pub_bytes = bytes(e_pub)
            sig_b = self.priv_key.sign(e_pub_bytes).signature
            reply_payload = e_pub_bytes + sig_b
            await self._send_packet(writer, PacketType.HELLO_REPLY, reply_payload)

            # Derive shared secret and session key.
            shared_secret = derive_shared_secret(e_priv, e_peer_pub)
            session_key = derive_session_key(shared_secret)

            # Step 3: Verify client AUTH signature.
            auth = await asyncio.wait_for(
                self._recv_packet(reader), timeout=10.0
            )
            if auth.packet_type != PacketType.AUTH:
                return
            if auth.node_id != peer_node_id:
                return

            sig_a = auth.payload
            verify_key = VerifyKey(peer_node_id)
            try:
                verify_key.verify(shared_secret, sig_a)
            except BadSignatureError:
                print(f"[SERVER] Handshake failed: Invalid AUTH from {peer_addr}")
                return

            # TOFU: Trust the peer if first encounter.
            if not self.trust_store.is_trusted(peer_node_id):
                self.trust_store.trust_node(peer_node_id)

            # Step 4: Confirm successful authentication.
            await self._send_packet(writer, PacketType.AUTH_OK, b"")
            print(f"[SERVER] Session established with {peer_node_id.hex()[:12]}...")

            # Enter the main packet processing loop.
            await self._packet_loop(reader, writer, session_key, peer_node_id)

        except Exception as e:
            print(f"[SERVER] Error handling client {peer_addr}: {e}")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    # ----- Main packet loop -------------------------------------------------

    async def _packet_loop(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        session_key: bytes,
        peer_node_id: bytes,
    ):
        """Process incoming packets until the connection drops.

        Supported packet types:
        - **MSG**: Decrypt and display a text message.
        - **MANIFEST**: Store the file manifest for an incoming transfer.
        - **CHUNK_DATA**: Verify, store, and ACK a received chunk.
          When all chunks arrive, auto-reassemble and verify SHA-256.
        - **CHUNK_REQ**: Serve a requested chunk from local storage.

        Args:
            reader: asyncio stream reader.
            writer: asyncio stream writer.
            session_key: AES-256-GCM key for this session.
            peer_node_id: Raw 32-byte public key of the connected peer.
        """
        while True:
            try:
                pkt = await self._recv_packet(reader)

                # --- Encrypted text message ---------------------------------
                if pkt.packet_type == PacketType.MSG:
                    nonce = pkt.payload[:12]
                    tag = pkt.payload[12:28]
                    ciphertext = pkt.payload[28:]
                    try:
                        plaintext = decrypt_message(session_key, nonce, ciphertext, tag)
                        msg_text = plaintext.decode('utf-8')
                        print(f"\n[MSG from {peer_node_id.hex()[:12]}] {msg_text}")
                        
                        # Add to history
                        self.history.add_message(peer_node_id.hex(), msg_text)

                        # Check for AI trigger
                        if not self.no_ai and ("/ask" in msg_text or "@archipel-ai" in msg_text):
                            asyncio.create_task(self._respond_with_ai(writer, session_key, msg_text))

                    except ValueError:
                        print(f"[SERVER] Failed to decrypt message from {peer_node_id.hex()[:12]}")

                # --- File manifest ------------------------------------------
                elif pkt.packet_type == PacketType.MANIFEST:
                    nonce = pkt.payload[:12]
                    tag = pkt.payload[12:28]
                    ciphertext = pkt.payload[28:]
                    try:
                        manifest_json = decrypt_message(
                            session_key, nonce, ciphertext, tag
                        ).decode("utf-8")
                        manifest = Manifest.from_json(manifest_json)
                        self.chunk_store.store_manifest_json(
                            manifest.file_id, manifest_json
                        )
                        print(
                            f"\n[MANIFEST] File '{manifest.filename}' "
                            f"({manifest.size} bytes, {manifest.nb_chunks} chunks)"
                        )
                        print(f"  file_id: {manifest.file_id[:16]}...")
                    except Exception as e:
                        print(f"[SERVER] Failed to process manifest: {e}")

                # --- Incoming chunk data ------------------------------------
                elif pkt.packet_type == PacketType.CHUNK_DATA:
                    await self._process_chunk_data(pkt, writer, session_key)

                # --- Chunk request from peer --------------------------------
                elif pkt.packet_type == PacketType.CHUNK_REQ:
                    await self._handle_chunk_req(pkt, writer, session_key)

                else:
                    # Unknown packet type; close the connection.
                    break

            except asyncio.IncompleteReadError:
                break
            except Exception as e:
                print(f"[SERVER] Packet loop error: {e}")
                break

    async def _respond_with_ai(self, writer: asyncio.StreamWriter, session_key: bytes, user_query: str):
        """Query Gemini and send response back to peer."""
        clean_query = user_query.replace("/ask", "").replace("@archipel-ai", "").strip()
        print(f"[AI] Processing query: {clean_query}...")
        
        context = self.history.get_context_for_ai()
        response_text = await self.ai.query(clean_query, context)
        
        # Add AI response to local history
        self.history.add_message(self.node_id.hex(), response_text, role="model")
        
        # Send back as MSG packet
        print(f"[AI] Response ready.")
        nonce, ciphertext, tag = encrypt_message(session_key, response_text.encode("utf-8"))
        payload = nonce + tag + ciphertext
        await self._send_packet(writer, PacketType.MSG, payload)

    # ----- Chunk data handler -----------------------------------------------

    async def _process_chunk_data(
        self,
        pkt: ArchipelPacket,
        writer: asyncio.StreamWriter,
        session_key: bytes,
    ):
        """Decrypt, verify, store an incoming chunk, and send an ACK.

        Payload layout (after AES-GCM decryption):
            file_id (64 B hex) + chunk_idx (4 B uint32) +
            chunk_hash (64 B hex) + raw chunk data.

        On successful storage of the final chunk, the file is
        automatically reassembled and its global SHA-256 verified.

        Args:
            pkt: The CHUNK_DATA packet.
            writer: Stream to send the ACK on.
            session_key: AES-256-GCM session key.
        """
        nonce = pkt.payload[:12]
        tag = pkt.payload[12:28]
        enc_data = pkt.payload[28:]
        try:
            raw = decrypt_message(session_key, nonce, enc_data, tag)

            # Parse the binary payload fields.
            file_id = raw[:64].decode("ascii")
            chunk_idx = struct.unpack("!I", raw[64:68])[0]
            chunk_hash = raw[68:132].decode("ascii")
            chunk_data = raw[132:]

            # Store with SHA-256 verification.
            ok = self.chunk_store.store_chunk(
                file_id, chunk_idx, chunk_data, chunk_hash
            )

            # Send ACK: 0x00 = OK, 0x01 = HASH_MISMATCH.
            status = 0x00 if ok else 0x01
            ack_payload = struct.pack("!IB", chunk_idx, status)
            await self._send_packet(writer, PacketType.ACK, ack_payload)

            # Check whether all chunks have been received.
            mj = self.chunk_store.get_manifest_json(file_id)
            if mj:
                m = Manifest.from_json(mj)
                received = len(self.chunk_store.get_available_chunks(file_id))
                pct = (received / m.nb_chunks) * 100
                print(
                    f"\r[TRANSFER] {received}/{m.nb_chunks} chunks ({pct:.1f}%)",
                    end="", flush=True,
                )

                # Auto-reassemble when transfer is complete.
                if received == m.nb_chunks:
                    print(f"\n[TRANSFER] All chunks received for '{m.filename}'!")
                    out_path = Path("downloads") / m.filename
                    if self.chunk_store.reassemble(file_id, m.nb_chunks, out_path):
                        from src.transfer.manifest import file_sha256

                        actual = file_sha256(out_path)
                        if actual == file_id:
                            print(f"[TRANSFER] SHA-256 verified OK! File saved: {out_path}")
                        else:
                            print(
                                f"[TRANSFER] SHA-256 MISMATCH! "
                                f"Expected {file_id[:16]}... got {actual[:16]}..."
                            )
        except Exception as e:
            print(f"[SERVER] CHUNK_DATA error: {e}")

    # ----- Chunk request handler --------------------------------------------

    async def _handle_chunk_req(
        self,
        pkt: ArchipelPacket,
        writer: asyncio.StreamWriter,
        session_key: bytes,
    ):
        """Serve a chunk requested by a peer.

        Looks up the chunk in source files first (original sender),
        then in the local chunk store (relay / re-seeder).
        Sends a CHUNK_DATA response or a NOT_FOUND ACK.

        Args:
            pkt: The CHUNK_REQ packet.
            writer: Stream to send the response on.
            session_key: AES-256-GCM session key.
        """
        file_id = pkt.payload[:64].decode("ascii")
        chunk_idx = struct.unpack("!I", pkt.payload[64:68])[0]

        chunk_data = None

        # Priority 1: Serve from the original source file on disk.
        if file_id in self.source_files:
            from src.transfer.chunking import read_chunk

            chunk_data = read_chunk(self.source_files[file_id], chunk_idx)

        # Priority 2: Serve from the local chunk store.
        if chunk_data is None:
            chunk_data = self.chunk_store.get_chunk(file_id, chunk_idx)

        if chunk_data:
            # Build and encrypt the CHUNK_DATA response.
            chunk_hash = hashlib.sha256(chunk_data).hexdigest()
            raw = (
                file_id.encode("ascii")
                + struct.pack("!I", chunk_idx)
                + chunk_hash.encode("ascii")
                + chunk_data
            )
            nonce, ciphertext, tag_enc = encrypt_message(session_key, raw)
            await self._send_packet(
                writer, PacketType.CHUNK_DATA, nonce + tag_enc + ciphertext
            )
        else:
            # Chunk not available locally: reply NOT_FOUND (0x02).
            ack_payload = struct.pack("!IB", chunk_idx, 0x02)
            await self._send_packet(writer, PacketType.ACK, ack_payload)
