"""Chunking utilities for the Archipel file transfer protocol.

Provides functions to split a file into fixed-size chunks (512 KB by
default), iterate over them lazily, compute per-chunk SHA-256 hashes,
and perform random-access reads on individual chunks.
"""

import hashlib
from pathlib import Path
from typing import Iterator


def iter_chunks(path: Path, chunk_size: int = 512 * 1024) -> Iterator[bytes]:
    """Yield successive raw byte chunks from a file.

    Args:
        path: Path to the source file.
        chunk_size: Maximum number of bytes per chunk (default 512 KB).

    Yields:
        Raw bytes for each chunk.  The last chunk may be shorter than
        *chunk_size* if the file size is not an exact multiple.
    """
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            yield chunk


def chunk_file(path: Path, chunk_size: int = 512 * 1024) -> list[dict]:
    """Chunk a file and return metadata for every chunk.

    Each entry in the returned list is a dictionary with keys:
    - ``index``: zero-based chunk position.
    - ``hash``: SHA-256 hex digest of the chunk data.
    - ``size``: chunk length in bytes.

    Args:
        path: Path to the source file.
        chunk_size: Maximum number of bytes per chunk (default 512 KB).

    Returns:
        Ordered list of chunk metadata dictionaries.
    """
    result = []
    for idx, data in enumerate(iter_chunks(path, chunk_size)):
        h = hashlib.sha256(data).hexdigest()
        result.append({"index": idx, "hash": h, "size": len(data)})
    return result


def read_chunk(path: Path, index: int, chunk_size: int = 512 * 1024) -> bytes:
    """Read a single chunk from a file by its index.

    Seeks directly to *index * chunk_size* before reading, so only
    the requested chunk data is loaded into memory.

    Args:
        path: Path to the source file.
        index: Zero-based chunk index.
        chunk_size: Size of each chunk in bytes (default 512 KB).

    Returns:
        Raw bytes of the requested chunk.
    """
    with path.open("rb") as f:
        f.seek(index * chunk_size)
        return f.read(chunk_size)
