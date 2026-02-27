from dataclasses import asdict, dataclass
from pathlib import Path
import hashlib
import json


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

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()
