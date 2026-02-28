import asyncio
import hashlib
import os
import time
from pathlib import Path

from nacl.signing import SigningKey

from src.crypto.keys import generate_keypair
from src.crypto.trust_store import TrustStore
from src.network.tcp_server import ArchipelTcpServer
from src.network.tcp_client import ArchipelTcpClient
from src.transfer.manifest import file_sha256


TEST_FILE_SIZE = 50 * 1024 * 1024  # 50 MB


async def main():
    # Setup keys for A (sender) and B (receiver)
    priv_a, pub_a = generate_keypair(Path("keys_a"))
    priv_b, pub_b = generate_keypair(Path("keys_b"))

    key_a = SigningKey(priv_a.read_bytes())
    node_a_id = pub_a.read_bytes()

    key_b = SigningKey(priv_b.read_bytes())
    node_b_id = pub_b.read_bytes()

    hmac_key = b"archipel-test-hmac-123"

    # Create 50MB test file
    test_file = Path("test_50mb.bin")
    if not test_file.exists():
        print(f"Generating {TEST_FILE_SIZE // (1024*1024)} MB test file...")
        with test_file.open("wb") as f:
            f.write(os.urandom(TEST_FILE_SIZE))
    
    original_hash = file_sha256(test_file)
    print(f"Original file SHA-256: {original_hash[:16]}...")
    print(f"File size: {test_file.stat().st_size} bytes")

    # Start Server B (receiver)
    trust_store_b = TrustStore(Path("keys_b/trust.json"))
    trust_store_b.load()
    port = 7790

    server_b = ArchipelTcpServer(node_b_id, hmac_key, key_b, trust_store_b, port)
    server_task = asyncio.create_task(server_b.start())
    await asyncio.sleep(0.5)

    # Client A connects and sends the file
    client_a = ArchipelTcpClient(node_a_id, hmac_key, key_a)
    print(f"\nConnecting to server...")
    if await client_a.connect("127.0.0.1", port):
        start = time.time()
        await client_a.send_file(test_file)
        elapsed = time.time() - start
        print(f"\nTotal time: {elapsed:.1f}s")
    else:
        print("Handshake failed!")

    await asyncio.sleep(2.0)
    client_a.close()

    # Verify the received file
    received_file = Path("downloads") / test_file.name
    if received_file.exists():
        received_hash = file_sha256(received_file)
        print(f"\nOriginal SHA-256:  {original_hash}")
        print(f"Received SHA-256:  {received_hash}")
        if original_hash == received_hash:
            print("RESULT: SHA-256 MATCH - Transfer successful!")
        else:
            print("RESULT: SHA-256 MISMATCH - Transfer failed!")
    else:
        print(f"\nReceived file not found at {received_file}")

    server_task.cancel()
    print("\nTest finished.")


if __name__ == "__main__":
    asyncio.run(main())
