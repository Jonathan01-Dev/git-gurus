import hashlib
import json
from pathlib import Path


class ChunkStore:
    """Local storage for file chunks, organized by file_id."""

    def __init__(self, base_dir: Path = Path(".archipel")):
        self.chunks_dir = base_dir / "chunks"
        self.index_path = base_dir / "index.json"
        self._index: dict = {}

    def load_index(self):
        if self.index_path.exists():
            try:
                self._index = json.loads(self.index_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                self._index = {}
        else:
            self._index = {}

    def save_index(self):
        self.index_path.parent.mkdir(parents=True, exist_ok=True)
        self.index_path.write_text(json.dumps(self._index, indent=2), encoding="utf-8")

    def store_chunk(self, file_id: str, chunk_idx: int, data: bytes, expected_hash: str) -> bool:
        """Store a chunk and verify its SHA-256 hash. Returns True if hash matches."""
        actual_hash = hashlib.sha256(data).hexdigest()
        if actual_hash != expected_hash:
            print(f"[STORE] HASH_MISMATCH chunk {chunk_idx} of {file_id[:12]}...")
            return False

        chunk_dir = self.chunks_dir / file_id
        chunk_dir.mkdir(parents=True, exist_ok=True)
        chunk_path = chunk_dir / f"chunk_{chunk_idx}.bin"
        chunk_path.write_bytes(data)

        # Update index
        if file_id not in self._index:
            self._index[file_id] = {"chunks": []}
        if chunk_idx not in self._index[file_id]["chunks"]:
            self._index[file_id]["chunks"].append(chunk_idx)
            self._index[file_id]["chunks"].sort()
        self.save_index()
        return True

    def get_chunk(self, file_id: str, chunk_idx: int) -> bytes | None:
        chunk_path = self.chunks_dir / file_id / f"chunk_{chunk_idx}.bin"
        if chunk_path.exists():
            return chunk_path.read_bytes()
        return None

    def has_chunk(self, file_id: str, chunk_idx: int) -> bool:
        return (self.chunks_dir / file_id / f"chunk_{chunk_idx}.bin").exists()

    def get_available_chunks(self, file_id: str) -> list[int]:
        if file_id in self._index:
            return self._index[file_id].get("chunks", [])
        return []

    def store_manifest_json(self, file_id: str, manifest_json: str):
        manifest_dir = self.chunks_dir / file_id
        manifest_dir.mkdir(parents=True, exist_ok=True)
        (manifest_dir / "manifest.json").write_text(manifest_json, encoding="utf-8")

    def get_manifest_json(self, file_id: str) -> str | None:
        p = self.chunks_dir / file_id / "manifest.json"
        if p.exists():
            return p.read_text(encoding="utf-8")
        return None

    def list_files(self) -> list[str]:
        """List all file_ids that have at least one chunk stored."""
        if not self.chunks_dir.exists():
            return []
        return [d.name for d in self.chunks_dir.iterdir() if d.is_dir()]

    def reassemble(self, file_id: str, nb_chunks: int, output_path: Path) -> bool:
        """Reassemble all chunks into the final file."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("wb") as out:
            for i in range(nb_chunks):
                data = self.get_chunk(file_id, i)
                if data is None:
                    print(f"[STORE] Missing chunk {i} for {file_id[:12]}...")
                    return False
                out.write(data)
        return True
