import hashlib
import hmac
import os

from Crypto.Cipher import AES
from nacl.bindings import crypto_scalarmult
from nacl.public import PrivateKey, PublicKey


def generate_ephemeral_keypair() -> tuple[PrivateKey, PublicKey]:
    priv = PrivateKey.generate()
    return priv, priv.public_key


def derive_shared_secret(priv: PrivateKey, pub: PublicKey) -> bytes:
    return crypto_scalarmult(bytes(priv), bytes(pub))


def hkdf_extract(salt: bytes, input_key_material: bytes) -> bytes:
    if not salt:
        salt = b'\0' * hashlib.sha256().digest_size
    return hmac.new(salt, input_key_material, hashlib.sha256).digest()


def hkdf_expand(pseudo_random_key: bytes, info: bytes, length: int) -> bytes:
    t = b""
    okm = b""
    i = 1
    while len(okm) < length:
        t = hmac.new(pseudo_random_key, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


def derive_session_key(shared_secret: bytes, context: bytes = b"archipel-v1", length: int = 32) -> bytes:
    prk = hkdf_extract(b"", shared_secret)
    return hkdf_expand(prk, context, length)


def encrypt_message(session_key: bytes, plaintext: bytes) -> tuple[bytes, bytes, bytes]:
    """Encrypts plaintext using AES-256-GCM. Returns (nonce, ciphertext, tag)."""
    nonce = os.urandom(12)  # 96-bit random nonce
    cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce, ciphertext, tag


def decrypt_message(session_key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    """Decrypts ciphertext using AES-256-GCM."""
    cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)
