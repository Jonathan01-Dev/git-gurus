import hashlib
from pathlib import Path
from typing import Iterator


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
