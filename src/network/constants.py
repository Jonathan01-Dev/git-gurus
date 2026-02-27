from enum import IntEnum


MAGIC = b"ARCH"
HEADER_FORMAT = "!4s B 32s I"
HEADER_SIZE = 41
HMAC_SIZE = 32


class PacketType(IntEnum):
    HELLO = 0x01
    PEER_LIST = 0x02
    MSG = 0x03
    CHUNK_REQ = 0x04
    CHUNK_DATA = 0x05
    MANIFEST = 0x06
    ACK = 0x07
