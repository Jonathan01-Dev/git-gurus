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

from src.crypto.session import generate_ephemeral_keypair, derive_shared_secret, derive_session_key, encrypt_message, decrypt_message
from src.crypto.trust_store import TrustStore
from src.network.constants import PacketType, HEADER_SIZE, HMAC_SIZE, HEADER_FORMAT
from src.network.packet import ArchipelPacket
from src.transfer.chunk_store import ChunkStore
from src.transfer.manifest import Manifest


class ArchipelTcpServer:
    def __init__(self, node_id: bytes, hmac_key: bytes, priv_key: SigningKey, trust_store: TrustStore, port: int = 7777):
        self.node_id = node_id
        self.hmac_key = hmac_key
        self.priv_key = priv_key
        self.trust_store = trust_store
        self.port = port
        self._server: Optional[asyncio.AbstractServer] = None
        self.chunk_store = ChunkStore(Path(".archipel"))
        self.chunk_store.load_index()
        # source_files maps file_id -> filepath for files we are serving from disk
        self.source_files: dict[str, Path] = {}

    async def start(self):
        self._server = await asyncio.start_server(self._handle_client, "0.0.0.0", self.port)
        print(f"[SERVER] Listening on 0.0.0.0:{self.port}")
        async with self._server:
            await self._server.serve_forever()

    def register_source_file(self, file_id: str, filepath: Path):
        self.source_files[file_id] = filepath

    async def _send_packet(self, writer: asyncio.StreamWriter, packet_type: PacketType, payload: bytes):
        pkt = ArchipelPacket(packet_type=packet_type, node_id=self.node_id, payload=payload)
        data = pkt.pack(self.hmac_key)
        writer.write(data)
        await writer.drain()

    async def _recv_packet(self, reader: asyncio.StreamReader) -> ArchipelPacket:
        header = await reader.readexactly(HEADER_SIZE)
        magic, p_type, sender_node_id, payload_len = struct.unpack(HEADER_FORMAT, header)
        rest = await reader.readexactly(payload_len + HMAC_SIZE)
        raw_packet = header + rest
        return ArchipelPacket.unpack(raw_packet, self.hmac_key)

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer_addr = writer.get_extra_info('peername')
        try:
            hello = await asyncio.wait_for(self._recv_packet(reader), timeout=10.0)
            if hello.packet_type != PacketType.HELLO:
                return

            peer_node_id = hello.node_id
            e_peer_pub_bytes = hello.payload[:32]
            e_peer_pub = PublicKey(e_peer_pub_bytes)

            e_priv, e_pub = generate_ephemeral_keypair()
            e_pub_bytes = bytes(e_pub)
            sig_b = self.priv_key.sign(e_pub_bytes).signature
            reply_payload = e_pub_bytes + sig_b
            await self._send_packet(writer, PacketType.HELLO_REPLY, reply_payload)

            shared_secret = derive_shared_secret(e_priv, e_peer_pub)
            session_key = derive_session_key(shared_secret)

            auth = await asyncio.wait_for(self._recv_packet(reader), timeout=10.0)
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

            if not self.trust_store.is_trusted(peer_node_id):
                self.trust_store.trust_node(peer_node_id)

            await self._send_packet(writer, PacketType.AUTH_OK, b"")
            print(f"[SERVER] Session established with {peer_node_id.hex()[:12]}...")

            await self._packet_loop(reader, writer, session_key, peer_node_id)

        except Exception as e:
            print(f"[SERVER] Error handling client {peer_addr}: {e}")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    async def _packet_loop(self, reader, writer, session_key: bytes, peer_node_id: bytes):
        while True:
            try:
                pkt = await self._recv_packet(reader)

                if pkt.packet_type == PacketType.MSG:
                    nonce = pkt.payload[:12]
                    tag = pkt.payload[12:28]
                    ciphertext = pkt.payload[28:]
                    try:
                        plaintext = decrypt_message(session_key, nonce, ciphertext, tag)
                        print(f"\n[MSG from {peer_node_id.hex()[:12]}] {plaintext.decode('utf-8')}")
                    except ValueError:
                        print(f"[SERVER] Failed to decrypt message from {peer_node_id.hex()[:12]}")

                elif pkt.packet_type == PacketType.MANIFEST:
                    nonce = pkt.payload[:12]
                    tag = pkt.payload[12:28]
                    ciphertext = pkt.payload[28:]
                    try:
                        manifest_json = decrypt_message(session_key, nonce, ciphertext, tag).decode("utf-8")
                        manifest = Manifest.from_json(manifest_json)
                        self.chunk_store.store_manifest_json(manifest.file_id, manifest_json)
                        print(f"\n[MANIFEST] File '{manifest.filename}' ({manifest.size} bytes, {manifest.nb_chunks} chunks)")
                        print(f"  file_id: {manifest.file_id[:16]}...")
                    except Exception as e:
                        print(f"[SERVER] Failed to process manifest: {e}")

                elif pkt.packet_type == PacketType.CHUNK_DATA:
                    nonce = pkt.payload[:12]
                    tag = pkt.payload[12:28]
                    enc_data = pkt.payload[28:]
                    try:
                        raw = decrypt_message(session_key, nonce, enc_data, tag)
                        # raw = file_id(32 hex = 64 bytes) + chunk_idx(4) + chunk_hash(64 bytes hex) + data
                        file_id = raw[:64].decode("ascii")
                        chunk_idx = struct.unpack("!I", raw[64:68])[0]
                        chunk_hash = raw[68:132].decode("ascii")
                        chunk_data = raw[132:]

                        ok = self.chunk_store.store_chunk(file_id, chunk_idx, chunk_data, chunk_hash)

                        # Send ACK
                        status = 0x00 if ok else 0x01
                        ack_payload = struct.pack("!IB", chunk_idx, status)
                        await self._send_packet(writer, PacketType.ACK, ack_payload)

                        mj = self.chunk_store.get_manifest_json(file_id)
                        if mj:
                            m = Manifest.from_json(mj)
                            received = len(self.chunk_store.get_available_chunks(file_id))
                            pct = (received / m.nb_chunks) * 100
                            print(f"\r[TRANSFER] {received}/{m.nb_chunks} chunks ({pct:.1f}%)", end="", flush=True)
                            if received == m.nb_chunks:
                                print(f"\n[TRANSFER] All chunks received for '{m.filename}'!")
                                out_path = Path("downloads") / m.filename
                                if self.chunk_store.reassemble(file_id, m.nb_chunks, out_path):
                                    # Verify final hash
                                    from src.transfer.manifest import file_sha256
                                    actual = file_sha256(out_path)
                                    if actual == file_id:
                                        print(f"[TRANSFER] SHA-256 verified OK! File saved: {out_path}")
                                    else:
                                        print(f"[TRANSFER] SHA-256 MISMATCH! Expected {file_id[:16]}... got {actual[:16]}...")
                    except Exception as e:
                        print(f"[SERVER] CHUNK_DATA error: {e}")

                elif pkt.packet_type == PacketType.CHUNK_REQ:
                    # Respond to chunk requests (we are serving chunks)
                    file_id = pkt.payload[:64].decode("ascii")
                    chunk_idx = struct.unpack("!I", pkt.payload[64:68])[0]

                    chunk_data = None
                    # Try source file first
                    if file_id in self.source_files:
                        from src.transfer.chunking import read_chunk
                        chunk_data = read_chunk(self.source_files[file_id], chunk_idx)
                    # Then try chunk store
                    if chunk_data is None:
                        chunk_data = self.chunk_store.get_chunk(file_id, chunk_idx)

                    if chunk_data:
                        chunk_hash = hashlib.sha256(chunk_data).hexdigest()
                        raw = file_id.encode("ascii") + struct.pack("!I", chunk_idx) + chunk_hash.encode("ascii") + chunk_data
                        nonce, ciphertext, tag_enc = encrypt_message(session_key, raw)
                        await self._send_packet(writer, PacketType.CHUNK_DATA, nonce + tag_enc + ciphertext)
                    else:
                        ack_payload = struct.pack("!IB", chunk_idx, 0x02)  # NOT_FOUND
                        await self._send_packet(writer, PacketType.ACK, ack_payload)

                else:
                    break

            except asyncio.IncompleteReadError:
                break
            except Exception as e:
                print(f"[SERVER] Packet loop error: {e}")
                break
