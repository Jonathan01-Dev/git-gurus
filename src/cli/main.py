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

    start = sub.add_parser("start", help="Start node server")
    start.add_argument("--port", type=int, default=7777)
    start.add_argument("--api-key", help="Google Gemini API key")
    start.add_argument("--no-ai", action="store_true", help="Disable AI features")

    inter = sub.add_parser("interactive", help="Start interactive dashboard (Web UI)")
    inter.add_argument("--port", type=int, default=7777, help="TCP port for node server")
    inter.add_argument("--ui-port", type=int, default=8000, help="HTTP port for Web UI")
    inter.add_argument("--api-key", help="Google Gemini API key")
    inter.add_argument("--no-ai", action="store_true", help="Disable AI features")

    sub.add_parser("peers", help="List known peers")

    msg = sub.add_parser("msg", help="Send encrypted message")
    msg.add_argument("node_id")
    msg.add_argument("message")
    msg.add_argument("--ip", help="Bypass discovery config by setting IP directly")
    msg.add_argument("--port", type=int, default=7777, help="Bypass discovery config by setting Port directly")

    send = sub.add_parser("send", help="Send file to a peer (chunked + encrypted)")
    send.add_argument("filepath")
    send.add_argument("--ip", required=True, help="Target peer IP")
    send.add_argument("--port", type=int, default=7777, help="Target peer TCP port")

    sub.add_parser("receive", help="List available files (placeholder)")

    dl = sub.add_parser("download", help="Download file (placeholder)")
    dl.add_argument("file_id")

    sub.add_parser("status", help="Show node status")

    trust = sub.add_parser("trust", help="Trust a node (placeholder)")
    trust.add_argument("node_id")

    sub.add_parser("keygen", help="Generate Ed25519 node keys")

    net = sub.add_parser("network", help="Manage zero-infrastructure Wi-Fi Direct network")
    net.add_argument("action", choices=["create-island", "status"], help="Network action")

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
        
        trust_store = TrustStore(Path("keys/trust.json"))
        trust_store.load()
        
        server = ArchipelTcpServer(
            pub_path.read_bytes(), 
            b"archipel-sprint0-dev-key-change-me", 
            SigningKey(priv_path.read_bytes()), 
            trust_store, 
            args.port,
            api_key=args.api_key,
            no_ai=args.no_ai
        )
        try:
            asyncio.run(server.start())
        except KeyboardInterrupt:
            print("\n[SERVER] Shutting down.")
        return

    if args.command == "interactive":
        from src.ui.dashboard import start_dashboard
        priv_path = Path("keys/ed25519_private.key")
        pub_path = Path("keys/ed25519_public.key")
        if not priv_path.exists() or not pub_path.exists():
            print("Generate keys first: python -m src.cli.main keygen")
            return

        start_dashboard(args)
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
        
        if args.ip:
            ip = args.ip
            port = args.port
        else:
            if not peer_info:
                print("Unknown peer. Run 'peers' command to discover, or use --ip <address>.")
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
        priv_path = Path("keys/ed25519_private.key")
        pub_path = Path("keys/ed25519_public.key")
        if not priv_path.exists() or not pub_path.exists():
            print("Generate keys first: python -m src.cli.main keygen")
            return

        priv_key = SigningKey(priv_path.read_bytes())
        node_id = pub_path.read_bytes()
        hmac_key = b"archipel-sprint0-dev-key-change-me"
        filepath = Path(args.filepath)

        async def _send_file():
            client = ArchipelTcpClient(node_id, hmac_key, priv_key)
            print(f"Connecting to {args.ip}:{args.port}...")
            if await client.connect(args.ip, args.port):
                await client.send_file(filepath)
                client.close()
            else:
                print("Failed to connect.")

        asyncio.run(_send_file())
        return

    if args.command == "receive":
        from src.transfer.chunk_store import ChunkStore
        from src.transfer.manifest import Manifest
        store = ChunkStore(Path(".archipel"))
        store.load_index()
        files = store.list_files()
        if not files:
            print("No files received yet.")
            return
        for fid in files:
            mj = store.get_manifest_json(fid)
            if mj:
                m = Manifest.from_json(mj)
                available = len(store.get_available_chunks(fid))
                print(f"  {fid[:16]}... {m.filename} ({m.size} bytes) [{available}/{m.nb_chunks} chunks]")
            else:
                print(f"  {fid[:16]}... (no manifest)")
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

    if args.command == "network":
        from src.network.wifi_direct import WiFiDirectIsland
        island = WiFiDirectIsland()
        
        if args.action == "create-island":
            island.create_island()
        elif args.action == "status":
            island.check_status()
        return

    parser.error("unknown command")


if __name__ == "__main__":
    main()
