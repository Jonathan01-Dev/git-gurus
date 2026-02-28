from dataclasses import asdict, dataclass, field
from pathlib import Path
import hashlib
import json

from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError

from src.transfer.chunking import chunk_file


CHUNK_SIZE = 512 * 1024  # 512 KB


@dataclass(slots=True)
class ManifestChunk:
    index: int
    hash: str
    size: int


@dataclass(slots=True)
class Manifest:
    file_id: str
    filename: str
    size: int
    chunk_size: int
    nb_chunks: int
    chunks: list[ManifestChunk]
    sender_id: str
    signature: str = ""

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)

    @classmethod
    def from_json(cls, data: str) -> "Manifest":
        d = json.loads(data)
        chunks = [ManifestChunk(**c) for c in d.pop("chunks")]
        return cls(chunks=chunks, **d)

    def compute_hash(self) -> bytes:
        """Hash of manifest content (excluding signature) for signing."""
        d = asdict(self)
        d.pop("signature", None)
        raw = json.dumps(d, sort_keys=True).encode("utf-8")
        return hashlib.sha256(raw).digest()

    def sign(self, signing_key: SigningKey) -> None:
        manifest_hash = self.compute_hash()
        self.signature = signing_key.sign(manifest_hash).signature.hex()

    def verify_signature(self, sender_pub: bytes) -> bool:
        try:
            verify_key = VerifyKey(sender_pub)
            sig = bytes.fromhex(self.signature)
            verify_key.verify(self.compute_hash(), sig)
            return True
        except (BadSignatureError, Exception):
            return False


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def build_manifest(filepath: Path, sender_id: bytes, signing_key: SigningKey) -> Manifest:
    """Build a complete manifest for a file."""
    file_hash = file_sha256(filepath)
    chunks_info = chunk_file(filepath, CHUNK_SIZE)

    manifest = Manifest(
        file_id=file_hash,
        filename=filepath.name,
        size=filepath.stat().st_size,
        chunk_size=CHUNK_SIZE,
        nb_chunks=len(chunks_info),
        chunks=[ManifestChunk(index=c["index"], hash=c["hash"], size=c["size"]) for c in chunks_info],
        sender_id=sender_id.hex(),
    )
    manifest.sign(signing_key)
    return manifest
