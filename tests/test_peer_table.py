from pathlib import Path

from src.network.peer_table_sprint1 import PeerTable


def test_upsert_get_all_remove() -> None:
    table = PeerTable()
    table.upsert("node-a", {"ip": "10.0.0.1", "tcp_port": 7777})

    peers = table.get_all()
    assert "node-a" in peers
    assert peers["node-a"]["ip"] == "10.0.0.1"
    assert peers["node-a"]["tcp_port"] == 7777
    assert "last_seen" in peers["node-a"]

    assert table.remove("node-a") is True
    assert table.remove("node-a") is False


def test_save_to_disk_and_load(tmp_path: Path) -> None:
    db_path = tmp_path / "peers.json"
    writer = PeerTable(db_path)
    writer.upsert("node-b", {"ip": "192.168.1.20", "tcp_port": 9000, "reputation": 0.9})
    writer.save_to_disk()

    reader = PeerTable(db_path)
    reader.load_from_disk()
    peers = reader.get_all()

    assert peers["node-b"]["ip"] == "192.168.1.20"
    assert peers["node-b"]["tcp_port"] == 9000
    assert peers["node-b"]["reputation"] == 0.9
