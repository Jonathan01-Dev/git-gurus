import json
from pathlib import Path


class TrustStore:
    """Trust On First Use (TOFU) manager for Archipel nodes."""

    def __init__(self, store_path: Path):
        self.store_path = store_path
        self._trusted: dict[str, bool] = {}

    def load(self) -> None:
        if not self.store_path.exists():
            self._trusted = {}
            return
        
        try:
            with open(self.store_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    self._trusted = {k: bool(v) for k, v in data.items()}
        except (json.JSONDecodeError, OSError) as e:
            print(f"[TRUST] Error loading trust store: {e}")
            self._trusted = {}

    def save(self) -> None:
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(self.store_path, "w", encoding="utf-8") as f:
                json.dump(self._trusted, f, indent=2)
        except OSError as e:
            print(f"[TRUST] Error saving trust store: {e}")

    def is_trusted(self, node_id: bytes) -> bool:
        """Returns True if the node is already known AND trusted."""
        node_hex = node_id.hex()
        return self._trusted.get(node_hex, False)

    def trust_node(self, node_id: bytes) -> None:
        """Marks a node as trusted (TOFU)."""
        node_hex = node_id.hex()
        if not self._trusted.get(node_hex, False):
            self._trusted[node_hex] = True
            self.save()
            print(f"[TRUST] Node {node_hex[:12]}... is now trusted (TOFU).")

    def revoke_node(self, node_id: bytes) -> None:
        """Explicitly untrusts a node."""
        node_hex = node_id.hex()
        if node_hex in self._trusted:
            self._trusted[node_hex] = False
            self.save()
            print(f"[TRUST] Node {node_hex[:12]}... revoked.")
