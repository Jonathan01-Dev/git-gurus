from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
import json
import os
import struct
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

MAGIC = b"ARCH"
HEADER_FORMAT = "!4s B 32s I"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
HMAC_SIZE = 32
DEFAULT_HMAC_KEY = b"archipel-sprint0-dev-key-change-me"


@dataclass(slots=True)
class DeliverableStatus:
    item: str
    status: str
    details: str


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _node_id_32(node_id: bytes) -> bytes:
    if len(node_id) != 32:
        raise ValueError("node_id must be exactly 32 bytes")
    return node_id


def build_packet(packet_type: int, node_id: bytes, payload: bytes, hmac_key: bytes) -> bytes:
    node_id_32 = _node_id_32(node_id)
    header = struct.pack(HEADER_FORMAT, MAGIC, packet_type, node_id_32, len(payload))
    body = header + payload
    signature = hmac.new(hmac_key, body, hashlib.sha256).digest()
    return body + signature


def parse_packet(raw: bytes, hmac_key: bytes) -> dict:
    if len(raw) < HEADER_SIZE + HMAC_SIZE:
        raise ValueError("packet too short")

    body = raw[:-HMAC_SIZE]
    received_sig = raw[-HMAC_SIZE:]
    expected_sig = hmac.new(hmac_key, body, hashlib.sha256).digest()
    if not hmac.compare_digest(received_sig, expected_sig):
        raise ValueError("invalid HMAC-SHA256")

    magic, packet_type, node_id, payload_len = struct.unpack(HEADER_FORMAT, body[:HEADER_SIZE])
    if magic != MAGIC:
        raise ValueError("invalid magic")

    payload = body[HEADER_SIZE:]
    if len(payload) != payload_len:
        raise ValueError("invalid payload length")

    return {
        "packet_type": packet_type,
        "node_id_hex": node_id.hex(),
        "payload_len": payload_len,
        "payload_utf8": payload.decode("utf-8", errors="replace"),
    }


def generate_rsa_keypair(node_name: str, out_dir: Path, password: bytes) -> tuple[Path, Path]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    priv_path = out_dir / f"{node_name}_rsa_private.pem"
    pub_path = out_dir / f"{node_name}_rsa_public.pem"

    priv_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password),
        )
    )
    pub_path.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return priv_path, pub_path


def generate_ed25519_keypair(node_name: str, out_dir: Path, password: bytes) -> tuple[Path, Path, Path]:
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_path = out_dir / f"{node_name}_ed25519_private.pem"
    pub_path = out_dir / f"{node_name}_ed25519_public.pem"
    node_id_path = out_dir / f"{node_name}_node_id.bin"

    priv_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password),
        )
    )
    pub_path.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    node_id_raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    node_id_path.write_bytes(node_id_raw)
    return priv_path, pub_path, node_id_path


def verify_ed25519_pair(private_pem: Path, public_pem: Path, password: bytes) -> None:
    private_key = serialization.load_pem_private_key(private_pem.read_bytes(), password=password)
    public_key = serialization.load_pem_public_key(public_pem.read_bytes())
    message = b"archipel-sprint0-key-check"
    signature = private_key.sign(message)
    public_key.verify(signature, message)


def _read_password(args: argparse.Namespace) -> bytes:
    if args.password:
        return args.password.encode("utf-8")

    if args.password_env:
        raw = os.getenv(args.password_env)
        if not raw:
            raise ValueError(f"environment variable '{args.password_env}' is empty or missing")
        return raw.encode("utf-8")

    first = getpass.getpass("Password to encrypt private keys: ")
    second = getpass.getpass("Confirm password: ")
    if first != second:
        raise ValueError("password confirmation does not match")
    if len(first) < 8:
        raise ValueError("password must be at least 8 characters")
    return first.encode("utf-8")


def cmd_keygen(args: argparse.Namespace) -> None:
    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    password = _read_password(args)

    rsa_priv, rsa_pub = generate_rsa_keypair(args.node, out_dir, password=password)
    ed_priv, ed_pub, node_id_path = generate_ed25519_keypair(args.node, out_dir, password=password)
    verify_ed25519_pair(ed_priv, ed_pub, password=password)

    print("Sprint 0 key generation completed")
    print(f"- RSA private:      {rsa_priv}")
    print(f"- RSA public:       {rsa_pub}")
    print(f"- Ed25519 private:  {ed_priv}")
    print(f"- Ed25519 public:   {ed_pub}")
    print(f"- NODE_ID (32 raw): {node_id_path}")
    print("Ed25519 verification: OK")
    print("Private keys are password-encrypted (PKCS8 + BestAvailableEncryption)")


def cmd_packet_demo(args: argparse.Namespace) -> None:
    node_id_path = Path(args.node_id_file)
    node_id = node_id_path.read_bytes()
    payload = json.dumps(
        {
            "type": "HELLO",
            "node_name": args.node,
            "tcp_port": args.tcp_port,
            "timestamp": _now_iso(),
        },
        separators=(",", ":"),
    ).encode("utf-8")
    key = args.hmac_key.encode("utf-8")

    packet = build_packet(packet_type=0x01, node_id=node_id, payload=payload, hmac_key=key)
    parsed = parse_packet(packet, hmac_key=key)

    out_path = Path(args.out_packet)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(packet)

    print(f"Packet written: {out_path.resolve()}")
    print(f"Packet size: {len(packet)} bytes")
    print(f"Parsed packet: {json.dumps(parsed, indent=2)}")


def _exists(path: Path) -> bool:
    return path.exists()


def cmd_report(args: argparse.Namespace) -> None:
    project_root = Path(".").resolve()
    keys_dir = project_root / args.keys_dir
    node = args.node

    checklist = [
        DeliverableStatus(
            item="README with stack choice + architecture + packet format",
            status="OK" if _exists(project_root / "README.md") else "MISSING",
            details="README.md found" if _exists(project_root / "README.md") else "README.md missing",
        ),
        DeliverableStatus(
            item="Protocol spec document",
            status="OK" if _exists(project_root / "docs" / "protocol-spec.md") else "MISSING",
            details="docs/protocol-spec.md found"
            if _exists(project_root / "docs" / "protocol-spec.md")
            else "docs/protocol-spec.md missing",
        ),
        DeliverableStatus(
            item="Architecture document",
            status="OK" if _exists(project_root / "docs" / "architecture.md") else "MISSING",
            details="docs/architecture.md found"
            if _exists(project_root / "docs" / "architecture.md")
            else "docs/architecture.md missing",
        ),
        DeliverableStatus(
            item="RSA keypair generated",
            status="OK"
            if _exists(keys_dir / f"{node}_rsa_private.pem") and _exists(keys_dir / f"{node}_rsa_public.pem")
            else "MISSING",
            details=f"Expected in {keys_dir}",
        ),
        DeliverableStatus(
            item="Ed25519 keypair generated",
            status="OK"
            if _exists(keys_dir / f"{node}_ed25519_private.pem")
            and _exists(keys_dir / f"{node}_ed25519_public.pem")
            else "MISSING",
            details=f"Expected in {keys_dir}",
        ),
        DeliverableStatus(
            item="NODE_ID (32 bytes) extracted from Ed25519 public key",
            status="OK" if _exists(keys_dir / f"{node}_node_id.bin") else "MISSING",
            details=f"Expected in {keys_dir}",
        ),
    ]

    report = {
        "generated_at": _now_iso(),
        "node": node,
        "project_root": str(project_root),
        "sprint0_checklist": [asdict(item) for item in checklist],
    }

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Sprint 0 report written: {out.resolve()}")
    for row in checklist:
        print(f"- [{row.status}] {row.item} -> {row.details}")


def build_cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Archipel Sprint 0 utility: key generation, packet demo, deliverable report"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_keygen = sub.add_parser("keygen", help="Generate RSA + Ed25519 keypairs for one node")
    p_keygen.add_argument("--node", default="node-1")
    p_keygen.add_argument("--out", default="keys")
    p_keygen.add_argument("--password", default=None, help="Password for private key encryption")
    p_keygen.add_argument(
        "--password-env",
        default=None,
        help="Read password from environment variable name (preferred over prompt)",
    )
    p_keygen.set_defaults(func=cmd_keygen)

    p_demo = sub.add_parser("packet-demo", help="Build and parse one ARCH packet with HMAC-SHA256")
    p_demo.add_argument("--node", default="node-1")
    p_demo.add_argument("--tcp-port", type=int, default=7777)
    p_demo.add_argument("--node-id-file", default="keys/node-1_node_id.bin")
    p_demo.add_argument("--hmac-key", default=DEFAULT_HMAC_KEY.decode("utf-8"))
    p_demo.add_argument("--out-packet", default=".archipel/sprint0_hello.packet")
    p_demo.set_defaults(func=cmd_packet_demo)

    p_report = sub.add_parser("report", help="Generate a Sprint 0 deliverable status report")
    p_report.add_argument("--node", default="node-1")
    p_report.add_argument("--keys-dir", default="keys")
    p_report.add_argument("--out", default=".archipel/sprint0_report.json")
    p_report.set_defaults(func=cmd_report)

    return parser


def main() -> None:
    parser = build_cli()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
