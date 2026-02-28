import asyncio
import struct
import time
from typing import Optional

from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError
from nacl.public import PublicKey

from src.crypto.session import generate_ephemeral_keypair, derive_shared_secret, derive_session_key, encrypt_message, decrypt_message
from src.network.constants import PacketType, HEADER_SIZE, HMAC_SIZE
from src.network.packet import ArchipelPacket


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
        
        # Read header + hmac
        # Actually we don't know the full length upfront, so we read only the header first
        # Because packet length is inside the header
        header = await self.reader.readexactly(HEADER_SIZE)
        
        # Unpack header to find out payload length
        import src.network.constants as constants
        magic, p_type, sender_node_id, payload_len = struct.unpack(constants.HEADER_FORMAT, header)
        
        # Read payload + HMAC
        rest = await self.reader.readexactly(payload_len + HMAC_SIZE)
        raw_packet = header + rest
        
        return ArchipelPacket.unpack(raw_packet, self.hmac_key)

    async def _perform_handshake(self) -> bool:
        # 1. HELLO
        e_priv, e_pub = generate_ephemeral_keypair()
        timestamp = int(time.time())
        # payload = e_A_pub (32 bytes) + timestamp (8 bytes)
        hello_payload = bytes(e_pub) + struct.pack("!Q", timestamp)
        await self._send_packet(PacketType.HELLO, hello_payload)

        # 2. Receive HELLO_REPLY
        reply = await self._recv_packet()
        if reply.packet_type != PacketType.HELLO_REPLY:
            print("[CLIENT] Expected HELLO_REPLY")
            return False
        
        peer_node_id = reply.node_id
        
        # payload = e_B_pub (32 bytes) + sig_B
        if len(reply.payload) < 32:
            return False
            
        e_peer_pub_bytes = reply.payload[:32]
        sig_b = reply.payload[32:]
        e_peer_pub = PublicKey(e_peer_pub_bytes)
        
        # verify sig_B. Note: The peer signs the ephemeral public key to prove identity.
        verify_key = VerifyKey(peer_node_id)
        try:
            verify_key.verify(e_peer_pub_bytes, sig_b)
        except BadSignatureError:
            print("[CLIENT] Invalid signature from peer")
            return False

        # Derive keys
        shared_secret = derive_shared_secret(e_priv, e_peer_pub)
        self.session_key = derive_session_key(shared_secret)

        # 3. AUTH (sig_A sur shared_secret)
        # To prove we hold the private key of our node_id, and that we computed the shared secret.
        sig_a = self.priv_key.sign(shared_secret).signature
        await self._send_packet(PacketType.AUTH, sig_a)

        # 4. Receive AUTH_OK
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
        # Payload format for MSG: nonce (12) + tag (16) + ciphertext
        payload = nonce + tag + ciphertext
        await self._send_packet(PacketType.MSG, payload)

    def close(self):
        if self.writer:
            self.writer.close()
