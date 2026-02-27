# Protocol Spec (Draft)

## Packet Header v1
- MAGIC: 4 bytes (ARCH)
- TYPE: 1 byte
- NODE_ID: 32 bytes (Ed25519 verify key)
- PAYLOAD_LEN: 4 bytes (uint32 big-endian)

Then:
- PAYLOAD: variable bytes
- HMAC_SHA256: 32 bytes over header+payload
