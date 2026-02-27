from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
import json


@dataclass(slots=True)
class PeerInfo:
    node_id_hex: str
    ip: str
    tcp_port: int
    last_seen_iso: str
    reputation: float = 1.0


class PeerTable:
    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._peers: dict[str, PeerInfo] = {}

    def upsert(self, node_id_hex: str, ip: str, tcp_port: int) -> None:
        now = datetime.now(timezone.utc).isoformat()
        peer = self._peers.get(node_id_hex)
        if peer is None:
            self._peers[node_id_hex] = PeerInfo(node_id_hex=node_id_hex, ip=ip, tcp_port=tcp_port, last_seen_iso=now)
            return
        peer.ip = ip
        peer.tcp_port = tcp_port
        peer.last_seen_iso = now

    def list_peers(self) -> list[PeerInfo]:
        return list(self._peers.values())

    def save(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        payload = [asdict(p) for p in self._peers.values()]
        self._db_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def load(self) -> None:
        if not self._db_path.exists():
            return
        raw = json.loads(self._db_path.read_text(encoding="utf-8"))
        self._peers = {item["node_id_hex"]: PeerInfo(**item) for item in raw}
