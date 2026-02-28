"""FastAPI Dashboard for Archipel.

Provides a Web UI to monitor and control the node.
"""

import asyncio
from pathlib import Path
from typing import Optional
import uvicorn
from fastapi import FastAPI, Request, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from src.network.tcp_server import ArchipelTcpServer
from src.crypto.trust_store import TrustStore
from src.network.tcp_client import ArchipelTcpClient
from nacl.signing import SigningKey

app = FastAPI()
BASE_DIR = Path(__file__).parent
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# Global states
node_server: Optional[ArchipelTcpServer] = None
node_args = None


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
        "peers_count": 0,  # TODO: get from discovery
        "files_count": len(node_server.chunk_store.list_files()),
        "ai_enabled": not node_server.no_ai
    }


@app.get("/api/ai")
async def query_ai(text: str = Query(...)):
    print(f"[DASHBOARD] AI Query received: {text}")
    try:
        if not node_server:
            print("[DASHBOARD] Server not pronto")
            return JSONResponse(
                status_code=503,
                content={"status": "error", "message": "Archipel server not yet initialized"}
            )
            
        if node_server.no_ai:
            return {"status": "error", "message": "AI features are disabled (--no-ai)"}
        
        if not node_server.ai.api_key:
            return {"status": "error", "message": "Missing Gemini API Key. Use --api-key"}
        
        # Clean the query
        clean_query = text.replace("/ask", "").replace("@archipel-ai", "").strip()
        print(f"[DASHBOARD] Clean query: {clean_query}")
        
        # Use the history from the server
        context = node_server.history.get_context_for_ai()
        
        # Query Gemini
        response_text = await node_server.ai.query(clean_query, context)
        print(f"[DASHBOARD] AI Response obtained")
        
        # Record in history
        node_server.history.add_message("local", clean_query, role="user")
        node_server.history.add_message(node_server.node_id.hex(), response_text, role="model")
        
        return {"status": "ok", "response": response_text}
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"[DASHBOARD] AI Error: {e}")
        return JSONResponse(
            status_code=500,
            content={"status": "error", "message": str(e)}
        )


def start_dashboard(args):
    global node_args, node_server
    node_args = args
    
    # Start Archipel Server in a background thread or process is tricky with asyncio
    # Simple approach: launch uvicorn synchronously, and Archipel in a thread
    
    import threading
    
    def run_archipel():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        priv_path = Path("keys/ed25519_private.key")
        pub_path = Path("keys/ed25519_public.key")
        trust_store = TrustStore(Path("keys/trust.json"))
        trust_store.load()
        
        global node_server
        node_server = ArchipelTcpServer(
            pub_path.read_bytes(),
            b"archipel-sprint0-dev-key-change-me",
            SigningKey(priv_path.read_bytes()),
            trust_store,
            args.port,
            api_key=args.api_key,
            no_ai=args.no_ai
        )
        loop.run_until_complete(node_server.start())

    t = threading.Thread(target=run_archipel, daemon=True)
    t.start()
    
    print(f"\n[DASHBOARD] Starting Web UI on http://127.0.0.1:{args.ui_port}")
    uvicorn.run(app, host="127.0.0.1", port=args.ui_port)
