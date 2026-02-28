import argparse
import asyncio
from pathlib import Path

from nacl.signing import SigningKey

from src.crypto.keys import generate_keypair, verify_keypair
from src.crypto.trust_store import TrustStore
from src.network.peer_table_sprint1 import PeerTable
from src.network.tcp_client import ArchipelTcpClient
from src.network.tcp_server import ArchipelTcpServer


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
        priv_path = Path("keys/ed25519_private.key")
        pub_path = Path("keys/ed25519_public.key")
        if not priv_path.exists() or not pub_path.exists():
            print("Generate keys first: python -m src.cli.main keygen")
            return
        
        priv_key = SigningKey(priv_path.read_bytes())
        node_id = pub_path.read_bytes()
        hmac_key = b"archipel-sprint0-dev-key-change-me"
        
        trust_store = TrustStore(Path(".archipel/trust_store.json"))
        trust_store.load()
        
        server = ArchipelTcpServer(node_id, hmac_key, priv_key, trust_store, args.port)
        try:
            asyncio.run(server.start())
        except KeyboardInterrupt:
            print("\n[SERVER] Shutting down.")
        return

    if args.command == "peers":
        table = PeerTable(Path('.archipel/peers.json'))
        table.load_from_disk()
        peers = table.get_all()
        if not peers:
            print("No peers discovered yet")
            return
        for node_id_hex, p in peers.items():
            ip = p.get("ip", "?")
            tcp_port = p.get("tcp_port", "?")
            last_seen = p.get("last_seen", "?")
            print(f"{node_id_hex} {ip}:{tcp_port} last_seen={last_seen}")
        return

    if args.command == "msg":
        priv_path = Path("keys/ed25519_private.key")
        pub_path = Path("keys/ed25519_public.key")
        if not priv_path.exists() or not pub_path.exists():
            print("Generate keys first: python -m src.cli.main keygen")
            return
            
        priv_key = SigningKey(priv_path.read_bytes())
        node_id = pub_path.read_bytes()
        hmac_key = b"archipel-sprint0-dev-key-change-me"
        
        table = PeerTable(Path('.archipel/peers.json'))
        table.load_from_disk()
        peers = table.get_all()
        
        peer_info = peers.get(args.node_id)
        if not peer_info:
            print("Unknown peer. Run 'peers' command to discover.")
            return
            
        ip = peer_info.get("ip")
        port = peer_info.get("tcp_port")
        
        async def _send():
            client = ArchipelTcpClient(node_id, hmac_key, priv_key)
            print(f"Connecting to {ip}:{port}...")
            if await client.connect(ip, port):
                await client.send_msg(args.message)
                client.close()
                print("Message sent.")
            else:
                print("Failed to send message.")
                
        asyncio.run(_send())
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
        trust_store = TrustStore(Path(".archipel/trust_store.json"))
        trust_store.load()
        try:
            target_id = bytes.fromhex(args.node_id)
            trust_store.trust_node(target_id)
        except ValueError:
            print("Invalid node_id hex format.")
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
