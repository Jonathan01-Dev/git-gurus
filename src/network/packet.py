import hashlib
import hmac
import struct
from dataclasses import dataclass

from src.network.constants import HEADER_FORMAT, HEADER_SIZE, HMAC_SIZE, MAGIC


@dataclass(slots=True)
class ArchipelPacket:
    packet_type: int
    node_id: bytes
    payload: bytes

    def pack(self, hmac_key: bytes) -> bytes:
        if len(self.node_id) != 32:
            raise ValueError("node_id must be 32 bytes")
        header = struct.pack(HEADER_FORMAT, MAGIC, self.packet_type, self.node_id, len(self.payload))
        packet_data = header + self.payload
        signature = hmac.new(hmac_key, packet_data, hashlib.sha256).digest()
        return packet_data + signature

    @staticmethod
    def unpack(raw: bytes, hmac_key: bytes) -> "ArchipelPacket":
        min_len = HEADER_SIZE + HMAC_SIZE
        if len(raw) < min_len:
            raise ValueError("packet too short")

        packet_data = raw[:-HMAC_SIZE]
        received_sig = raw[-HMAC_SIZE:]
        expected_sig = hmac.new(hmac_key, packet_data, hashlib.sha256).digest()
        if not hmac.compare_digest(received_sig, expected_sig):
            raise ValueError("invalid packet HMAC")

        magic, packet_type, node_id, payload_len = struct.unpack(HEADER_FORMAT, raw[:HEADER_SIZE])
        if magic != MAGIC:
            raise ValueError("invalid packet magic")

        payload = raw[HEADER_SIZE:HEADER_SIZE + payload_len]
        if len(payload) != payload_len:
            raise ValueError("invalid payload length")

        return ArchipelPacket(packet_type=packet_type, node_id=node_id, payload=payload)
