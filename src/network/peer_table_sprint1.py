from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any


class PeerTable:
    """Sprint 1 peer table keyed by node_id."""

    def __init__(self, db_path: Path | None = None) -> None:
        self._db_path = db_path
        self._peers: dict[str, dict[str, Any]] = {}

    def upsert(self, node_id: str, data: dict[str, Any]) -> None:
        now = datetime.now(timezone.utc).isoformat()
        merged = dict(self._peers.get(node_id, {}))
        merged.update(data)
        merged["node_id"] = node_id
        merged["last_seen"] = now
        self._peers[node_id] = merged

    def get_all(self) -> dict[str, dict[str, Any]]:
        return {node_id: dict(peer) for node_id, peer in self._peers.items()}

    def remove(self, node_id: str) -> bool:
        return self._peers.pop(node_id, None) is not None

    def save_to_disk(self, path: Path | None = None) -> None:
        target = path or self._db_path
        if target is None:
            raise ValueError("A path is required to save peer table")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self._peers, indent=2), encoding="utf-8")

    def load_from_disk(self, path: Path | None = None) -> None:
        target = path or self._db_path
        if target is None or not target.exists():
            return
        raw = json.loads(target.read_text(encoding="utf-8"))
        self._peers = {str(node_id): dict(data) for node_id, data in raw.items()}
