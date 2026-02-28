"""FastAPI dashboard for Archipel."""

import asyncio
from pathlib import Path
from typing import Optional

import uvicorn
from fastapi import FastAPI, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from nacl.signing import SigningKey

from src.crypto.trust_store import TrustStore
from src.network.tcp_client import ArchipelTcpClient
from src.network.tcp_server import ArchipelTcpServer
from src.transfer.manifest import Manifest

app = FastAPI()
BASE_DIR = Path(__file__).parent
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

LOCAL_HMAC_KEY = b"archipel-sprint0-dev-key-change-me"
KEYS_DIR = Path("keys")

node_server: Optional[ArchipelTcpServer] = None
node_args = None


def _local_keys() -> tuple[bytes, SigningKey]:
    priv_path = KEYS_DIR / "ed25519_private.key"
    pub_path = KEYS_DIR / "ed25519_public.key"
    if not priv_path.exists() or not pub_path.exists():
        raise FileNotFoundError("Missing keys. Run: python -m src.cli.main keygen")
    return pub_path.read_bytes(), SigningKey(priv_path.read_bytes())


def _resolve_target(node_id: Optional[str], ip: Optional[str], port: int) -> tuple[str, int, str]:
    if not node_server:
        raise RuntimeError("Server not ready")

    if node_id:
        peers = node_server.discovery.peer_table.get_all()
        peer = peers.get(node_id)
        if not peer:
            raise ValueError("Peer not found in discovery table")
        return str(peer["ip"]), int(peer["tcp_port"]), node_id

    if not ip:
        raise ValueError("Provide node_id or ip")
    return ip, int(port), ip


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/api/status")
async def get_status():
    if not node_server:
        return {"status": "offline"}

    return {
        "status": "online",
        "node_id": node_server.node_id.hex(),
        "port": node_server.port,
        "peers_count": len(node_server.discovery.peer_table.get_all()),
        "files_count": len(node_server.chunk_store.list_files()),
        "ai_enabled": (not node_server.no_ai) and bool(node_server.ai.api_key),
    }


@app.get("/api/peers")
async def get_peers():
    if not node_server:
        return []
    return list(node_server.discovery.peer_table.get_all().values())


@app.post("/api/peers/add")
async def add_manual_peer(ip: str, port: int = 7777):
    if not node_server:
        return JSONResponse(status_code=503, content={"status": "error", "message": "Server not ready"})
    temp_id = f"manual-{ip}:{port}"
    node_server.discovery.peer_table.upsert(temp_id, {"ip": ip, "tcp_port": int(port)})
    node_server.discovery.peer_table.save_to_disk()
    return {"status": "ok", "peer_id": temp_id}


@app.post("/api/chat/send")
async def send_p2p_message(
    text: str,
    node_id: Optional[str] = None,
    ip: Optional[str] = None,
    port: int = 7777,
):
    if not node_server:
        return JSONResponse(status_code=503, content={"status": "error", "message": "Server not ready"})
    if not text.strip():
        return JSONResponse(status_code=400, content={"status": "error", "message": "Empty message"})

    try:
        target_ip, target_port, sender_ref = _resolve_target(node_id=node_id, ip=ip, port=port)
        local_node_id, priv_key = _local_keys()
        client = ArchipelTcpClient(local_node_id, node_server.hmac_key, priv_key)
        if not await client.connect(target_ip, target_port):
            return {"status": "error", "message": f"Failed to connect to {target_ip}:{target_port}"}
        await client.send_msg(text)
        client.close()
        node_server.history.add_message(sender_ref, text, role="user")
        return {"status": "ok"}
    except Exception as exc:
        return {"status": "error", "message": str(exc)}


@app.post("/api/files/send")
async def send_p2p_file(
    filepath: str,
    node_id: Optional[str] = None,
    ip: Optional[str] = None,
    port: int = 7777,
):
    if not node_server:
        return JSONResponse(status_code=503, content={"status": "error", "message": "Server not ready"})

    try:
        target_ip, target_port, _ = _resolve_target(node_id=node_id, ip=ip, port=port)
        local_path = Path(filepath).expanduser()
        if not local_path.exists() or not local_path.is_file():
            return {"status": "error", "message": f"File not found: {local_path}"}

        local_node_id, priv_key = _local_keys()
        client = ArchipelTcpClient(local_node_id, node_server.hmac_key, priv_key)
        if not await client.connect(target_ip, target_port):
            return {"status": "error", "message": f"Failed to connect to {target_ip}:{target_port}"}
        await client.send_file(local_path)
        client.close()
        return {"status": "ok", "filename": local_path.name}
    except Exception as exc:
        return {"status": "error", "message": str(exc)}


@app.get("/api/files/received")
async def list_received_files():
    if not node_server:
        return []

    out = []
    for file_id in node_server.chunk_store.list_files():
        manifest_json = node_server.chunk_store.get_manifest_json(file_id)
        if not manifest_json:
            out.append({"file_id": file_id, "filename": "(unknown)", "chunks": 0, "total_chunks": 0})
            continue
        manifest = Manifest.from_json(manifest_json)
        chunks = len(node_server.chunk_store.get_available_chunks(file_id))
        out.append(
            {
                "file_id": file_id,
                "filename": manifest.filename,
                "chunks": chunks,
                "total_chunks": manifest.nb_chunks,
                "size": manifest.size,
            }
        )
    return out


@app.get("/api/ai")
async def query_ai(text: str = Query(...)):
    if not node_server:
        return JSONResponse(status_code=503, content={"status": "error", "message": "Server not ready"})
    if node_server.no_ai:
        return JSONResponse(status_code=400, content={"status": "error", "message": "AI disabled"})
    if not node_server.ai.api_key:
        return JSONResponse(status_code=400, content={"status": "error", "message": "Missing API key"})

    clean_query = text.replace("/ask", "").replace("@archipel-ai", "").strip()
    if not clean_query:
        return JSONResponse(status_code=400, content={"status": "error", "message": "Empty question"})

    context = node_server.history.get_context_for_ai()
    if not context:
        context.append(
            {
                "role": "user",
                "parts": [
                    {
                        "text": (
                            "You are Gemini integrated in Archipel, a decentralized local-first network. "
                            "Answer briefly and focus on practical help."
                        )
                    }
                ],
            }
        )
        context.append({"role": "model", "parts": [{"text": "Understood. Ready to help with Archipel."}]})

    response_text = await node_server.ai.query(clean_query, context)
    if response_text.startswith("[AI] Error"):
        return JSONResponse(status_code=500, content={"status": "error", "message": response_text})

    node_server.history.add_message("local", clean_query, role="user")
    node_server.history.add_message(node_server.node_id.hex(), response_text, role="model")
    return {"status": "ok", "response": response_text}


def start_dashboard(args):
    global node_args, node_server
    node_args = args

    import threading

    def run_archipel():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        priv_path = KEYS_DIR / "ed25519_private.key"
        pub_path = KEYS_DIR / "ed25519_public.key"
        trust_store = TrustStore(KEYS_DIR / "trust.json")
        trust_store.load()

        global node_server
        node_server = ArchipelTcpServer(
            pub_path.read_bytes(),
            LOCAL_HMAC_KEY,
            SigningKey(priv_path.read_bytes()),
            trust_store,
            args.port,
            api_key=args.api_key,
            no_ai=args.no_ai,
        )
        loop.run_until_complete(node_server.start())

    worker = threading.Thread(target=run_archipel, daemon=True)
    worker.start()

    print(f"\n[DASHBOARD] Starting Web UI on http://127.0.0.1:{args.ui_port}")
    uvicorn.run(app, host="127.0.0.1", port=args.ui_port)
