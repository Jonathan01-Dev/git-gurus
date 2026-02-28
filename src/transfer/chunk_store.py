"""Local chunk storage for the Archipel file transfer protocol.

Manages on-disk storage of received file chunks, organised by file ID.
Each file's chunks are stored in a dedicated directory under
``.archipel/chunks/<file_id>/``.  A JSON index tracks which chunks
are available locally, enabling efficient resume and reassembly.
"""

import hashlib
import json
from pathlib import Path


class ChunkStore:
    """Persistent, file-system-based store for received chunks.

    Directory layout::

        .archipel/
            index.json              # maps file_id -> list of available chunk indices
            chunks/
                <file_id>/
                    manifest.json   # (optional) cached manifest for the file
                    chunk_0.bin
                    chunk_1.bin
                    ...

    Attributes:
        chunks_dir: Root directory where chunk files are written.
        index_path: Path to the JSON index file.
    """

    def __init__(self, base_dir: Path = Path(".archipel")):
        """Initialise the store paths.

        Args:
            base_dir: Base directory for all Archipel local data.
        """
        self.chunks_dir = base_dir / "chunks"
        self.index_path = base_dir / "index.json"
        self._index: dict = {}

    # ----- Index persistence ------------------------------------------------

    def load_index(self):
        """Load the chunk availability index from disk."""
        if self.index_path.exists():
            try:
                self._index = json.loads(
                    self.index_path.read_text(encoding="utf-8")
                )
            except (json.JSONDecodeError, OSError):
                self._index = {}
        else:
            self._index = {}

    def save_index(self):
        """Persist the current chunk availability index to disk."""
        self.index_path.parent.mkdir(parents=True, exist_ok=True)
        self.index_path.write_text(
            json.dumps(self._index, indent=2), encoding="utf-8"
        )

    # ----- Chunk I/O --------------------------------------------------------

    def store_chunk(
        self, file_id: str, chunk_idx: int, data: bytes, expected_hash: str
    ) -> bool:
        """Write a chunk to disk after verifying its SHA-256 hash.

        Args:
            file_id: Hex-encoded SHA-256 of the whole file.
            chunk_idx: Zero-based chunk index.
            data: Raw chunk bytes.
            expected_hash: Expected SHA-256 hex digest for *data*.

        Returns:
            ``True`` if the hash matched and the chunk was stored,
            ``False`` on hash mismatch (chunk is **not** written).
        """
        actual_hash = hashlib.sha256(data).hexdigest()
        if actual_hash != expected_hash:
            print(f"[STORE] HASH_MISMATCH chunk {chunk_idx} of {file_id[:12]}...")
            return False

        # Write chunk bytes to disk.
        chunk_dir = self.chunks_dir / file_id
        chunk_dir.mkdir(parents=True, exist_ok=True)
        chunk_path = chunk_dir / f"chunk_{chunk_idx}.bin"
        chunk_path.write_bytes(data)

        # Update the in-memory and on-disk index.
        if file_id not in self._index:
            self._index[file_id] = {"chunks": []}
        if chunk_idx not in self._index[file_id]["chunks"]:
            self._index[file_id]["chunks"].append(chunk_idx)
            self._index[file_id]["chunks"].sort()
        self.save_index()
        return True

    def get_chunk(self, file_id: str, chunk_idx: int) -> bytes | None:
        """Retrieve a stored chunk's bytes, or ``None`` if absent.

        Args:
            file_id: Hex-encoded file SHA-256.
            chunk_idx: Zero-based chunk index.

        Returns:
            Raw chunk bytes or ``None``.
        """
        chunk_path = self.chunks_dir / file_id / f"chunk_{chunk_idx}.bin"
        if chunk_path.exists():
            return chunk_path.read_bytes()
        return None

    def has_chunk(self, file_id: str, chunk_idx: int) -> bool:
        """Check whether a specific chunk exists on disk.

        Args:
            file_id: Hex-encoded file SHA-256.
            chunk_idx: Zero-based chunk index.

        Returns:
            ``True`` if the chunk file exists.
        """
        return (self.chunks_dir / file_id / f"chunk_{chunk_idx}.bin").exists()

    def get_available_chunks(self, file_id: str) -> list[int]:
        """Return the sorted list of locally-available chunk indices.

        Args:
            file_id: Hex-encoded file SHA-256.

        Returns:
            List of zero-based chunk indices present in the store.
        """
        if file_id in self._index:
            return self._index[file_id].get("chunks", [])
        return []

    # ----- Manifest helpers -------------------------------------------------

    def store_manifest_json(self, file_id: str, manifest_json: str):
        """Cache a manifest JSON string alongside the chunk directory.

        Args:
            file_id: Hex-encoded file SHA-256.
            manifest_json: Serialised manifest string.
        """
        manifest_dir = self.chunks_dir / file_id
        manifest_dir.mkdir(parents=True, exist_ok=True)
        (manifest_dir / "manifest.json").write_text(
            manifest_json, encoding="utf-8"
        )

    def get_manifest_json(self, file_id: str) -> str | None:
        """Retrieve the cached manifest JSON for a file, if available.

        Args:
            file_id: Hex-encoded file SHA-256.

        Returns:
            Manifest JSON string or ``None``.
        """
        p = self.chunks_dir / file_id / "manifest.json"
        if p.exists():
            return p.read_text(encoding="utf-8")
        return None

    # ----- Query & reassembly -----------------------------------------------

    def list_files(self) -> list[str]:
        """Return all file IDs that have at least one chunk stored.

        Returns:
            List of hex-encoded file SHA-256 strings.
        """
        if not self.chunks_dir.exists():
            return []
        return [d.name for d in self.chunks_dir.iterdir() if d.is_dir()]

    def reassemble(self, file_id: str, nb_chunks: int, output_path: Path) -> bool:
        """Concatenate all chunks in order and write the final file.

        Args:
            file_id: Hex-encoded file SHA-256.
            nb_chunks: Expected total number of chunks.
            output_path: Destination path for the reassembled file.

        Returns:
            ``True`` if all chunks were found and the file was written,
            ``False`` if any chunk is missing.
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("wb") as out:
            for i in range(nb_chunks):
                data = self.get_chunk(file_id, i)
                if data is None:
                    print(f"[STORE] Missing chunk {i} for {file_id[:12]}...")
                    return False
                out.write(data)
        return True
