from __future__ import annotations

import argparse
import asyncio
import struct
from pathlib import Path
from typing import Any

from src.network.constants import PacketType
from src.network.packet import ArchipelPacket
from src.network.peer_table_sprint1 import PeerTable

DEFAULT_TCP_PORT = 7777
MAX_PARALLEL_CONNECTIONS = 10
DEFAULT_HMAC_KEY = b"archipel-sprint0-dev-key-change-me"


def encode_peer_list_payload(peers: dict[str, dict[str, Any]]) -> bytes:
    """Encode peers in binary format.

    Format:
    - peer_count: uint16
    - repeated peer_count times:
      - node_id: 32 bytes
      - ip_len: uint8
      - ip_utf8: ip_len bytes
      - tcp_port: uint16
    """
    if len(peers) > 65535:
        raise ValueError("too many peers for uint16 count")

    chunks: list[bytes] = [struct.pack("!H", len(peers))]
    for node_id_hex, peer in peers.items():
        node_id = bytes.fromhex(node_id_hex)
        if len(node_id) != 32:
            raise ValueError(f"invalid node_id_hex length for peer {node_id_hex!r}")

        ip_raw = str(peer.get("ip", "")).encode("utf-8")
        if len(ip_raw) > 255:
            raise ValueError(f"ip too long for peer {ip_raw!r}")

        tcp_port = int(peer.get("tcp_port", 0))
        if not (0 <= tcp_port <= 65535):
            raise ValueError(f"invalid tcp_port for peer {node_id_hex!r}: {tcp_port}")

        chunks.append(struct.pack("!32sB", node_id, len(ip_raw)))
        chunks.append(ip_raw)
        chunks.append(struct.pack("!H", tcp_port))

    return b"".join(chunks)


class Sprint1PeerListServer:
    def __init__(
        self,
        tcp_port: int,
        max_connections: int,
        node_id: bytes,
        peer_table_path: Path,
        hmac_key: bytes,
    ) -> None:
        self.tcp_port = tcp_port
        self.max_connections = max_connections
        self.node_id = node_id
        self.peer_table_path = peer_table_path
        self.hmac_key = hmac_key
        self._connections = 0
        self._server: asyncio.AbstractServer | None = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_connection,
            host="0.0.0.0",
            port=self.tcp_port,
        )
        print(
            f"[S1-2.3] PEER_LIST server on 0.0.0.0:{self.tcp_port} "
            f"(max parallel connections: {self.max_connections})"
        )
        print("[S1-2.3] Press Ctrl+C to stop.")
        async with self._server:
            await self._server.serve_forever()

    async def _handle_connection(self, _: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if self._connections >= self.max_connections:
            writer.write(b"BUSY\n")
            await writer.drain()
            writer.close()
            await self._safe_wait_closed(writer)
            return

        self._connections += 1
        peer_addr = writer.get_extra_info("peername")
        print(f"[S1-2.3] accepted {peer_addr}, active={self._connections}")
        try:
            table = PeerTable(self.peer_table_path)
            table.load_from_disk()
            peers = table.get_all()

            payload = encode_peer_list_payload(peers)
            packet = ArchipelPacket(
                packet_type=int(PacketType.PEER_LIST),
                node_id=self.node_id,
                payload=payload,
            ).pack(self.hmac_key)

            writer.write(packet)
            await writer.drain()
            print(f"[S1-2.3] sent PEER_LIST ({len(peers)} peers, {len(packet)} bytes) to {peer_addr}")
        except (OSError, ValueError) as exc:
            print(f"[S1-2.3] error with {peer_addr}: {exc}")
        finally:
            writer.close()
            await self._safe_wait_closed(writer)
            self._connections -= 1
            print(f"[S1-2.3] closed {peer_addr}, active={self._connections}")

    async def _safe_wait_closed(self, writer: asyncio.StreamWriter) -> None:
        try:
            await writer.wait_closed()
        except OSError:
            pass


def build_cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Sprint 1 task 2.3: send PEER_LIST on TCP connect")
    parser.add_argument("--tcp-port", type=int, default=DEFAULT_TCP_PORT)
    parser.add_argument("--max-connections", type=int, default=MAX_PARALLEL_CONNECTIONS)
    parser.add_argument("--node-id-file", default="keys/node-1_node_id.bin")
    parser.add_argument("--peer-table", default=".archipel/peers.json")
    parser.add_argument("--hmac-key", default=DEFAULT_HMAC_KEY.decode("utf-8"))
    return parser


def main() -> None:
    args = build_cli().parse_args()

    node_id = Path(args.node_id_file).read_bytes()
    if len(node_id) != 32:
        raise ValueError("node_id must be exactly 32 bytes")
    if args.max_connections < 1:
        raise ValueError("max-connections must be >= 1")

    server = Sprint1PeerListServer(
        tcp_port=args.tcp_port,
        max_connections=args.max_connections,
        node_id=node_id,
        peer_table_path=Path(args.peer_table),
        hmac_key=args.hmac_key.encode("utf-8"),
    )
    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        print("\n[S1-2.3] PEER_LIST server stopped.")


if __name__ == "__main__":
    main()
