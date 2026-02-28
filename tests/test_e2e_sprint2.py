import asyncio
from pathlib import Path

from nacl.signing import SigningKey

from src.crypto.trust_store import TrustStore
from src.network.tcp_server import ArchipelTcpServer
from src.network.tcp_client import ArchipelTcpClient
from src.crypto.keys import generate_keypair

async def main():
    # 1. Setup A and B
    priv_a, pub_a = generate_keypair(Path("keys_a"))
    priv_b, pub_b = generate_keypair(Path("keys_b"))
    
    key_a = SigningKey(priv_a.read_bytes())
    node_a_id = pub_a.read_bytes()
    
    key_b = SigningKey(priv_b.read_bytes())
    node_b_id = pub_b.read_bytes()
    
    hmac_key = b"archipel-test-hmac-123"
    
    trust_store_b = TrustStore(Path("keys_b/trust.json"))
    trust_store_b._trusted[node_a_id.hex()] = True # Pre-trust A for the test just in case, though TOFU would do it
    
    # 2. Start Server B
    port = 7780
    server_b = ArchipelTcpServer(node_b_id, hmac_key, key_b, trust_store_b, port)
    
    # Run server in background
    task = asyncio.create_task(server_b.start())
    await asyncio.sleep(0.5) # Wait for server to bind
    
    # 3. Start Client A
    client_a = ArchipelTcpClient(node_a_id, hmac_key, key_a)
    print("Client connecting...")
    success = await client_a.connect("127.0.0.1", port)
    
    if success:
        print("Sending message...")
        await client_a.send_msg("Hello Bob, this is a highly secret message!")
    else:
        print("Handshake failed.")
        
    await asyncio.sleep(1.0) # Wait for message to be processed
    client_a.close()
    task.cancel()
    print("Test finished.")

if __name__ == "__main__":
    asyncio.run(main())
