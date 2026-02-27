import argparse
from pathlib import Path

from src.crypto.keys import generate_keypair, verify_keypair
from src.network.peer_table import PeerTable


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="archipel", description="Archipel P2P prototype CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    start = sub.add_parser("start", help="Start local node")
    start.add_argument("--port", type=int, default=7777)

    sub.add_parser("peers", help="List known peers")

    msg = sub.add_parser("msg", help="Send encrypted message (placeholder)")
    msg.add_argument("node_id")
    msg.add_argument("message")

    send = sub.add_parser("send", help="Send file (placeholder)")
    send.add_argument("node_id")
    send.add_argument("filepath")

    sub.add_parser("receive", help="List available files (placeholder)")

    dl = sub.add_parser("download", help="Download file (placeholder)")
    dl.add_argument("file_id")

    sub.add_parser("status", help="Show node status")

    trust = sub.add_parser("trust", help="Trust a node (placeholder)")
    trust.add_argument("node_id")

    sub.add_parser("keygen", help="Generate Ed25519 node keys")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "start":
        print(f"Node start requested on TCP port {args.port} (skeleton mode)")
        return

    if args.command == "peers":
        table = PeerTable(Path('.archipel/peers.json'))
        table.load()
        peers = table.list_peers()
        if not peers:
            print("No peers discovered yet")
            return
        for p in peers:
            print(f"{p.node_id_hex} {p.ip}:{p.tcp_port} last_seen={p.last_seen_iso}")
        return

    if args.command == "msg":
        print(f"MSG placeholder -> {args.node_id}: {args.message}")
        return

    if args.command == "send":
        print(f"SEND placeholder -> {args.node_id}: {args.filepath}")
        return

    if args.command == "receive":
        print("RECEIVE placeholder")
        return

    if args.command == "download":
        print(f"DOWNLOAD placeholder -> {args.file_id}")
        return

    if args.command == "status":
        print("STATUS placeholder: node up=false peers=0 sessions=0")
        return

    if args.command == "trust":
        print(f"TRUST placeholder -> {args.node_id}")
        return

    if args.command == "keygen":
        priv, pub = generate_keypair()
        verify_keypair(priv, pub)
        print(f"Private key: {priv.resolve()}")
        print(f"Public key:  {pub.resolve()}")
        print("Verification: OK")
        return

    parser.error("unknown command")


if __name__ == "__main__":
    main()
