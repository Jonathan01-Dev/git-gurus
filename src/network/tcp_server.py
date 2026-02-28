import asyncio
import struct
import time
from typing import Optional

from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError
from nacl.public import PublicKey

from src.crypto.session import generate_ephemeral_keypair, derive_shared_secret, derive_session_key, encrypt_message, decrypt_message
from src.crypto.trust_store import TrustStore
from src.network.constants import PacketType, HEADER_SIZE, HMAC_SIZE, HEADER_FORMAT
from src.network.packet import ArchipelPacket


class ArchipelTcpServer:
    def __init__(self, node_id: bytes, hmac_key: bytes, priv_key: SigningKey, trust_store: TrustStore, port: int = 7777):
        self.node_id = node_id
        self.hmac_key = hmac_key
        self.priv_key = priv_key
        self.trust_store = trust_store
        self.port = port
        self._server: Optional[asyncio.AbstractServer] = None

    async def start(self):
        self._server = await asyncio.start_server(self._handle_client, "0.0.0.0", self.port)
        print(f"[SERVER] Listening on 0.0.0.0:{self.port}")
        async with self._server:
            await self._server.serve_forever()

    async def _send_packet(self, writer: asyncio.StreamWriter, packet_type: PacketType, payload: bytes):
        pkt = ArchipelPacket(packet_type=packet_type, node_id=self.node_id, payload=payload)
        data = pkt.pack(self.hmac_key)
        writer.write(data)
        await writer.drain()

    async def _recv_packet(self, reader: asyncio.StreamReader) -> ArchipelPacket:
        # Read header only
        header = await reader.readexactly(HEADER_SIZE)
        magic, p_type, sender_node_id, payload_len = struct.unpack(HEADER_FORMAT, header)
        
        # Read payload + HMAC
        rest = await reader.readexactly(payload_len + HMAC_SIZE)
        raw_packet = header + rest
        
        return ArchipelPacket.unpack(raw_packet, self.hmac_key)

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer_addr = writer.get_extra_info('peername')
        try:
            # 1. Expect HELLO
            hello = await getattr(asyncio, 'wait_for', asyncio.wait_for)(self._recv_packet(reader), timeout=5.0)
            if hello.packet_type != PacketType.HELLO:
                return

            peer_node_id = hello.node_id
            e_peer_pub_bytes = hello.payload[:32]
            e_peer_pub = PublicKey(e_peer_pub_bytes)
            
            # 2. Send HELLO_REPLY
            e_priv, e_pub = generate_ephemeral_keypair()
            e_pub_bytes = bytes(e_pub)
            sig_b = self.priv_key.sign(e_pub_bytes).signature
            reply_payload = e_pub_bytes + sig_b
            await self._send_packet(writer, PacketType.HELLO_REPLY, reply_payload)

            # Derive keys
            shared_secret = derive_shared_secret(e_priv, e_peer_pub)
            session_key = derive_session_key(shared_secret)

            # 3. Expect AUTH
            auth = await getattr(asyncio, 'wait_for', asyncio.wait_for)(self._recv_packet(reader), timeout=5.0)
            if auth.packet_type != PacketType.AUTH:
                return

            if auth.node_id != peer_node_id:
                return

            sig_a = auth.payload
            verify_key = VerifyKey(peer_node_id)
            try:
                verify_key.verify(shared_secret, sig_a)
            except BadSignatureError:
                print(f"[SERVER] Handshake failed: Invalid AUTH signature from {peer_addr}")
                return

            # Check Trust Store TOFU
            if not self.trust_store.is_trusted(peer_node_id):
                self.trust_store.trust_node(peer_node_id)

            # 4. Send AUTH_OK
            await self._send_packet(writer, PacketType.AUTH_OK, b"")
            print(f"[SERVER] Session established with {peer_node_id.hex()[:12]}...")

            # 5. Enter message loop
            await self._message_loop(reader, writer, session_key, peer_node_id)

        except Exception as e:
            print(f"[SERVER] Error handling client {peer_addr}: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def _message_loop(self, reader, writer, session_key: bytes, peer_node_id: bytes):
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
                else:
                    # Ignore other packets or drop connection
                    break
            except asyncio.IncompleteReadError:
                break
            except Exception as e:
                print(f"[SERVER] Message loop error: {e}")
                break
