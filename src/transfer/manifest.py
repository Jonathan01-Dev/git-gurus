from dataclasses import asdict, dataclass
from pathlib import Path
import hashlib
import json
from typing import Iterator


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


def iter_chunks(path: Path, chunk_size: int = 512 * 1024) -> Iterator[bytes]:
    """Yield raw chunk bytes from a file."""
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            yield chunk


def chunk_file(path: Path, chunk_size: int = 512 * 1024) -> list[dict]:
    """Chunk a file and return metadata for each chunk (index, hash, size)."""
    result = []
    for idx, data in enumerate(iter_chunks(path, chunk_size)):
        h = hashlib.sha256(data).hexdigest()
        result.append({"index": idx, "hash": h, "size": len(data)})
    return result


def read_chunk(path: Path, index: int, chunk_size: int = 512 * 1024) -> bytes:
    """Read a specific chunk from a file by index."""
    with path.open("rb") as f:
        f.seek(index * chunk_size)
        return f.read(chunk_size)
