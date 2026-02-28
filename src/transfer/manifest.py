"""Manifest module for Archipel file transfer protocol.

Handles creation, signing, and verification of file manifests.
A manifest describes a file split into 512 KB chunks and includes
SHA-256 hashes for integrity verification and an Ed25519 signature
for sender authentication.
"""

from dataclasses import asdict, dataclass, field
from pathlib import Path
import hashlib
import json

from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError

from src.transfer.chunking import chunk_file


# Default chunk size used for splitting files (512 KB).
CHUNK_SIZE = 512 * 1024


@dataclass(slots=True)
class ManifestChunk:
    """Represents metadata for a single chunk within a manifest.

    Attributes:
        index: Zero-based position of the chunk in the file.
        hash: SHA-256 hex digest of the chunk data.
        size: Size of the chunk in bytes.
    """

    index: int
    hash: str
    size: int


@dataclass(slots=True)
class Manifest:
    """Describes a file available for transfer on the Archipel network.

    The manifest is serialised as JSON, encrypted with AES-GCM, and
    sent to the receiver before any chunk data.  It carries an Ed25519
    signature so the receiver can verify the sender's identity.

    Attributes:
        file_id: SHA-256 hex digest of the whole file.
        filename: Original file name (e.g. ``report.pdf``).
        size: Total file size in bytes.
        chunk_size: Size of each chunk in bytes (default 512 KB).
        nb_chunks: Total number of chunks.
        chunks: Ordered list of :class:`ManifestChunk` entries.
        sender_id: Hex-encoded Ed25519 public key of the sender.
        signature: Hex-encoded Ed25519 signature over the manifest hash.
    """

    file_id: str
    filename: str
    size: int
    chunk_size: int
    nb_chunks: int
    chunks: list[ManifestChunk]
    sender_id: str
    signature: str = ""

    def to_json(self) -> str:
        """Serialise the manifest to a JSON string."""
        return json.dumps(asdict(self), indent=2)

    @classmethod
    def from_json(cls, data: str) -> "Manifest":
        """Deserialise a manifest from a JSON string.

        Args:
            data: Raw JSON string produced by :meth:`to_json`.

        Returns:
            A fully-populated :class:`Manifest` instance.
        """
        d = json.loads(data)
        chunks = [ManifestChunk(**c) for c in d.pop("chunks")]
        return cls(chunks=chunks, **d)

    def compute_hash(self) -> bytes:
        """Compute a SHA-256 hash over the manifest content.

        The ``signature`` field is excluded before hashing so that
        the hash is deterministic prior to signing.

        Returns:
            Raw 32-byte SHA-256 digest.
        """
        d = asdict(self)
        d.pop("signature", None)
        raw = json.dumps(d, sort_keys=True).encode("utf-8")
        return hashlib.sha256(raw).digest()

    def sign(self, signing_key: SigningKey) -> None:
        """Sign the manifest with the sender's Ed25519 private key.

        Populates the ``signature`` field in-place.

        Args:
            signing_key: Ed25519 private key used for signing.
        """
        manifest_hash = self.compute_hash()
        self.signature = signing_key.sign(manifest_hash).signature.hex()

    def verify_signature(self, sender_pub: bytes) -> bool:
        """Verify the manifest signature against the sender's public key.

        Args:
            sender_pub: Raw 32-byte Ed25519 public key of the sender.

        Returns:
            ``True`` if the signature is valid, ``False`` otherwise.
        """
        try:
            verify_key = VerifyKey(sender_pub)
            sig = bytes.fromhex(self.signature)
            verify_key.verify(self.compute_hash(), sig)
            return True
        except (BadSignatureError, Exception):
            return False


def file_sha256(path: Path) -> str:
    """Compute the SHA-256 hex digest of an entire file.

    Reads the file in 1 MB blocks to keep memory usage constant
    regardless of file size.

    Args:
        path: Path to the file.

    Returns:
        Lowercase hex-encoded SHA-256 digest string.
    """
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def build_manifest(
    filepath: Path,
    sender_id: bytes,
    signing_key: SigningKey,
) -> Manifest:
    """Build, sign, and return a complete manifest for *filepath*.

    The file is chunked (512 KB per chunk) and each chunk's SHA-256
    hash is recorded.  The manifest is then signed with *signing_key*.

    Args:
        filepath: Path to the source file.
        sender_id: Raw 32-byte Ed25519 public key (node identity).
        signing_key: Ed25519 private key for manifest signing.

    Returns:
        A signed :class:`Manifest` ready for transmission.
    """
    file_hash = file_sha256(filepath)
    chunks_info = chunk_file(filepath, CHUNK_SIZE)

    manifest = Manifest(
        file_id=file_hash,
        filename=filepath.name,
        size=filepath.stat().st_size,
        chunk_size=CHUNK_SIZE,
        nb_chunks=len(chunks_info),
        chunks=[
            ManifestChunk(
                index=c["index"], hash=c["hash"], size=c["size"]
            )
            for c in chunks_info
        ],
        sender_id=sender_id.hex(),
    )
    manifest.sign(signing_key)
    return manifest
