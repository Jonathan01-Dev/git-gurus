from pathlib import Path

from nacl.signing import SigningKey, VerifyKey


DEFAULT_KEYS_DIR = Path("keys")
PRIVATE_KEY_FILE = DEFAULT_KEYS_DIR / "ed25519_private.key"
PUBLIC_KEY_FILE = DEFAULT_KEYS_DIR / "ed25519_public.key"


def generate_keypair(output_dir: Path = DEFAULT_KEYS_DIR) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)

    signing_key = SigningKey.generate()
    verify_key = signing_key.verify_key

    private_path = output_dir / PRIVATE_KEY_FILE.name
    public_path = output_dir / PUBLIC_KEY_FILE.name

    private_path.write_bytes(bytes(signing_key))
    public_path.write_bytes(bytes(verify_key))

    return private_path, public_path


def verify_keypair(private_path: Path, public_path: Path) -> None:
    signing_key = SigningKey(private_path.read_bytes())
    verify_key = VerifyKey(public_path.read_bytes())

    test_message = b"archipel-key-check"
    signature = signing_key.sign(test_message).signature
    verify_key.verify(test_message, signature)
