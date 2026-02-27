import hashlib
import hmac


def derive_session_key(shared_secret: bytes, context: bytes = b"archipel-v1", length: int = 32) -> bytes:
    # Minimal HKDF-like derivation for skeleton stage.
    prk = hmac.new(context, shared_secret, hashlib.sha256).digest()
    return hmac.new(prk, b"session-key", hashlib.sha256).digest()[:length]
