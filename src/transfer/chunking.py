from pathlib import Path
from typing import Iterator


def iter_chunks(path: Path, chunk_size: int = 512 * 1024) -> Iterator[bytes]:
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            yield chunk
