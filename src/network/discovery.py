from __future__ import annotations

import argparse
import asyncio
import socket
import struct
from datetime import datetime, timezone
from pathlib import Path

from src.network.constants import PacketType
from src.network.packet import ArchipelPacket
from src.network.peer_table_sprint1 import PeerTable

MCAST_GRP = "239.255.42.99"
MCAST_PORT = 6000
DEFAULT_TCP_PORT = 7777
DEFAULT_HELLO_INTERVAL_SECONDS = 30
DEFAULT_PEER_TIMEOUT_SECONDS = 90
DEFAULT_CLEAN_INTERVAL_SECONDS = 10
DEFAULT_HMAC_KEY = b"archipel-sprint0-dev-key-change-me"
DEFAULT_MCAST_IFACE = "0.0.0.0"


class ArchipelDiscovery:
    def __init__(
        self,
        node_id: bytes,
        tcp_port: int = DEFAULT_TCP_PORT,
        peer_table_path: Path = Path(".archipel/peers.json"),
        hmac_key: bytes = DEFAULT_HMAC_KEY,
        hello_interval_seconds: int = DEFAULT_HELLO_INTERVAL_SECONDS,
        peer_timeout_seconds: int = DEFAULT_PEER_TIMEOUT_SECONDS,
        clean_interval_seconds: int = DEFAULT_CLEAN_INTERVAL_SECONDS,
        mcast_iface: str = DEFAULT_MCAST_IFACE,
    ) -> None:
        if len(node_id) != 32:
            raise ValueError("node_id must be exactly 32 bytes")
        if not (0 <= tcp_port <= 65535):
            raise ValueError("tcp_port must be in range 0..65535")
        try:
            socket.inet_aton(mcast_iface)
        except OSError as exc:
            raise ValueError("mcast_iface must be a valid IPv4 address") from exc

        self.node_id = node_id
        self.tcp_port = tcp_port
        self.hmac_key = hmac_key
        self.hello_interval_seconds = hello_interval_seconds
        self.peer_timeout_seconds = peer_timeout_seconds
        self.clean_interval_seconds = clean_interval_seconds
        self.mcast_iface = mcast_iface
        self.peer_table = PeerTable(peer_table_path)
        self.peer_table.load_from_disk()
        if not peer_table_path.exists():
            self.peer_table.save_to_disk(peer_table_path)

    def _build_hello_packet(self) -> bytes:
        payload = struct.pack("!H", self.tcp_port)
        return ArchipelPacket(
            packet_type=int(PacketType.HELLO),
            node_id=self.node_id,
            payload=payload,
        ).pack(self.hmac_key)

    async def run_beacon(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        if self.mcast_iface != "0.0.0.0":
            try:
                sock.setsockopt(
                    socket.IPPROTO_IP,
                    socket.IP_MULTICAST_IF,
                    socket.inet_aton(self.mcast_iface),
                )
            except OSError as exc:
                print(
                    f"[DISCOVERY] WARN cannot set multicast iface={self.mcast_iface}: {exc}. "
                    "Falling back to automatic interface selection."
                )
        packet = self._build_hello_packet()

        print(
            f"[DISCOVERY] Beacon active on {MCAST_GRP}:{MCAST_PORT} "
            f"(node={self.node_id.hex()[:12]}..., tcp={self.tcp_port}, iface={self.mcast_iface})"
        )
        try:
            while True:
                sock.sendto(packet, (MCAST_GRP, MCAST_PORT))
                print("[DISCOVERY] HELLO sent")
                await asyncio.sleep(self.hello_interval_seconds)
        finally:
            sock.close()

    async def run_listener(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", MCAST_PORT))

        group = socket.inet_aton(MCAST_GRP)
        iface = socket.inet_aton(self.mcast_iface)
        try:
            mreq = struct.pack("=4s4s", group, iface)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        except OSError:
            mreq = struct.pack("=4sl", group, socket.INADDR_ANY)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        sock.setblocking(False)
        loop = asyncio.get_running_loop()
        print(f"[DISCOVERY] Listener waiting on 0.0.0.0:{MCAST_PORT} (iface={self.mcast_iface})")

        try:
            while True:
                data, addr = await loop.sock_recvfrom(sock, 4096)
                self._process_incoming(data, addr)
        finally:
            sock.close()

    def _process_incoming(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            packet = ArchipelPacket.unpack(data, self.hmac_key)
        except ValueError:
            return

        if packet.packet_type != int(PacketType.HELLO):
            return
        if packet.node_id == self.node_id:
            return
        if len(packet.payload) != 2:
            return

        peer_ip = addr[0]
        peer_node_id = packet.node_id.hex()
        peer_tcp_port = struct.unpack("!H", packet.payload)[0]

        peers_before = self.peer_table.get_all()
        is_new = peer_node_id not in peers_before
        self.peer_table.upsert(
            peer_node_id,
            {
                "ip": peer_ip,
                "tcp_port": peer_tcp_port,
            },
        )
        self.peer_table.save_to_disk()

        if is_new:
            print(f"[DISCOVERY] NEW PEER {peer_node_id[:12]}... {peer_ip}:{peer_tcp_port}")
        else:
            print(f"[DISCOVERY] REFRESH PEER {peer_node_id[:12]}... {peer_ip}:{peer_tcp_port}")

    async def run_cleaner(self) -> None:
        while True:
            now = datetime.now(timezone.utc)
            peers = self.peer_table.get_all()
            removed = 0
            for node_id, info in peers.items():
                last_seen_raw = str(info.get("last_seen", ""))
                try:
                    last_seen = datetime.fromisoformat(last_seen_raw)
                except ValueError:
                    self.peer_table.remove(node_id)
                    removed += 1
                    continue

                if last_seen.tzinfo is None:
                    last_seen = last_seen.replace(tzinfo=timezone.utc)

                age_seconds = (now - last_seen).total_seconds()
                if age_seconds > self.peer_timeout_seconds:
                    self.peer_table.remove(node_id)
                    removed += 1

            if removed:
                self.peer_table.save_to_disk()
                print(f"[DISCOVERY] Removed {removed} offline peer(s)")

            self._print_peer_table()
            await asyncio.sleep(self.clean_interval_seconds)

    def _print_peer_table(self) -> None:
        peers = self.peer_table.get_all()
        print(f"[DISCOVERY] Peer table size={len(peers)}")
        for node_id, info in peers.items():
            ip = info.get("ip", "?")
            tcp_port = info.get("tcp_port", "?")
            last_seen = info.get("last_seen", "?")
            print(f"  - {node_id[:12]}... {ip}:{tcp_port} last_seen={last_seen}")


def build_cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Sprint 1 discovery service (tasks 1.1, 1.2, 1.3)")
    parser.add_argument("--node-id-file", default="keys/node-1_node_id.bin")
    parser.add_argument("--tcp-port", type=int, default=DEFAULT_TCP_PORT)
    parser.add_argument("--peer-table", default=".archipel/peers.json")
    parser.add_argument("--hmac-key", default=DEFAULT_HMAC_KEY.decode("utf-8"))
    parser.add_argument("--hello-interval", type=int, default=DEFAULT_HELLO_INTERVAL_SECONDS)
    parser.add_argument("--peer-timeout", type=int, default=DEFAULT_PEER_TIMEOUT_SECONDS)
    parser.add_argument("--clean-interval", type=int, default=DEFAULT_CLEAN_INTERVAL_SECONDS)
    parser.add_argument("--mcast-iface", default=DEFAULT_MCAST_IFACE)
    return parser


async def start_discovery(args: argparse.Namespace) -> None:
    node_id = Path(args.node_id_file).read_bytes()
    discovery = ArchipelDiscovery(
        node_id=node_id,
        tcp_port=args.tcp_port,
        peer_table_path=Path(args.peer_table),
        hmac_key=args.hmac_key.encode("utf-8"),
        hello_interval_seconds=args.hello_interval,
        peer_timeout_seconds=args.peer_timeout,
        clean_interval_seconds=args.clean_interval,
        mcast_iface=args.mcast_iface,
    )
    await asyncio.gather(
        discovery.run_beacon(),
        discovery.run_listener(),
        discovery.run_cleaner(),
    )


def main() -> None:
    args = build_cli().parse_args()
    try:
        asyncio.run(start_discovery(args))
    except KeyboardInterrupt:
        print("\n[DISCOVERY] Stopped.")


if __name__ == "__main__":
    main()
