import asyncio
import json
import os
import uuid
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from auditor_ai.client import GeminiClient
from auditor_ai.config import ANALYSIS_TEMPLATE_PROMPT, DEFAULT_MODEL
from auditor_ai.scanner import ejecutar_escaneo_sast
from auditor_ai.utils import escanear_directorio, leer_archivo

app = FastAPI(title="Auditor-AI Web")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

PROYECTO_DIR = Path(__file__).resolve().parent
STATIC_DIR = PROYECTO_DIR / "static"

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

chat_sessions: dict[str, dict] = {}
_api_key: str = ""

def get_client():
    key = _api_key or os.getenv("GEMINI_API_KEY") or ""
    if not key:
        raise HTTPException(status_code=500, detail="API Key de Gemini no configurada.")
    try:
        return GeminiClient(api_key=key)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al conectar con Gemini: {str(e)}")

def _client_or_none():
    key = _api_key or os.getenv("GEMINI_API_KEY") or ""
    if not key:
        return None
    try:
        return GeminiClient(api_key=key)
    except Exception:
        return None

async def sse_stream_gemini(prompt: str, model: str, client: GeminiClient):
    try:
        stream = await asyncio.get_event_loop().run_in_executor(
            None, lambda: client.analizar_codigo_stream(prompt, model=model)
        )
        for chunk in stream:
            text = chunk.text if hasattr(chunk, "text") else str(chunk)
            if text:
                yield f"data: {json.dumps({'type': 'chunk', 'content': text})}\n\n"
        yield f"data: {json.dumps({'type': 'done'})}\n\n"
    except Exception as e:
        yield f"data: {json.dumps({'type': 'error', 'content': str(e)})}\n\n"

async def sse_stream_chat(chat_session, message: str):
    try:
        stream = await asyncio.get_event_loop().run_in_executor(
            None, lambda: chat_session.send_message_stream(message)
        )
        for chunk in stream:
            text = chunk.text if hasattr(chunk, "text") else str(chunk)
            if text:
                yield f"data: {json.dumps({'type': 'chunk', 'content': text})}\n\n"
        yield f"data: {json.dumps({'type': 'done'})}\n\n"
    except Exception as e:
        yield f"data: {json.dumps({'type': 'error', 'content': str(e)})}\n\n"

# ── Frontend ─────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def root():
    return HTMLResponse(content=(STATIC_DIR / "index.html").read_text(encoding="utf-8"))

@app.get("/api/status")
async def status():
    return {"status": "ok", "api_key_configured": bool(_api_key or os.getenv("GEMINI_API_KEY"))}

@app.post("/api/configure-key")
async def configure_key(request: Request):
    global _api_key
    body = await request.json()
    key = body.get("api_key", "").strip()
    if not key:
        raise HTTPException(status_code=400, detail="API Key vacía.")
    _api_key = key
    return {"status": "ok", "message": "API Key configurada correctamente."}

# ── Analyze: File Upload ──────────────────────────────────────────────────

@app.post("/api/analyze/file")
async def analyze_file(file: UploadFile = File(...), model: str = Form(DEFAULT_MODEL)):
    client = get_client()
    content = await file.read()
    try:
        code = content.decode("utf-8", errors="ignore")
    except Exception:
        raise HTTPException(status_code=400, detail="No se pudo leer el archivo como texto.")
    prompt = ANALYSIS_TEMPLATE_PROMPT.format(code_content=code)
    return StreamingResponse(sse_stream_gemini(prompt, model, client), media_type="text/event-stream")

# ── Analyze: Local Path ───────────────────────────────────────────────────

@app.post("/api/analyze/path")
async def analyze_path(request: Request):
    body = await request.json()
    ruta = body.get("path", "").strip()
    model = body.get("model", DEFAULT_MODEL)
    if not os.path.exists(ruta):
        raise HTTPException(status_code=400, detail=f"La ruta '{ruta}' no existe.")
    client = get_client()
    if os.path.isdir(ruta):
        codigo = escanear_directorio(ruta)
    else:
        codigo = leer_archivo(ruta)
    if not codigo or codigo.strip() == "":
        raise HTTPException(status_code=400, detail="No se pudo extraer código de la ruta especificada.")
    prompt = ANALYSIS_TEMPLATE_PROMPT.format(code_content=codigo)
    return StreamingResponse(sse_stream_gemini(prompt, model, client), media_type="text/event-stream")

# ── Analyze: URL ──────────────────────────────────────────────────────────

@app.post("/api/analyze/url")
async def analyze_url(request: Request):
    body = await request.json()
    url = body.get("url", "").strip()
    model = body.get("model", DEFAULT_MODEL)
    if not url:
        raise HTTPException(status_code=400, detail="URL vacía.")
    if not url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="La URL debe comenzar con http:// o https://")
    try:
        import requests
        from bs4 import BeautifulSoup
        client = get_client()
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        text_content = soup.get_text(separator='\n')[:15000]
        prompt = (
            "Analiza el contenido de esta página web en busca de vulnerabilidades, "
            "malas prácticas de seguridad, exposición de información sensible, etc. "
            "Genera un reporte estructurado según metodología RAPTOR (Etapas A-D) en ESPAÑOL:\n\n"
            f"{text_content}"
        )
        return StreamingResponse(sse_stream_gemini(prompt, model, client), media_type="text/event-stream")
    except ImportError:
        raise HTTPException(status_code=500, detail="Dependencias 'requests' y 'beautifulsoup4' requeridas para análisis de URL.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ── SAST Scan ─────────────────────────────────────────────────────────────

@app.post("/api/scan")
async def scan_sast(request: Request):
    body = await request.json()
    ruta = body.get("path", "").strip()
    tool = body.get("tool", "all")
    model = body.get("model", DEFAULT_MODEL)
    if not os.path.exists(ruta):
        raise HTTPException(status_code=400, detail=f"La ruta '{ruta}' no existe.")
    reportes_sast = ejecutar_escaneo_sast(ruta, tool=tool)
    sast_resumen = ""
    for clave, salida in reportes_sast.items():
        sast_resumen += f"=== REPORTE DE {clave.upper()} ===\n{salida}\n\n"
    client = get_client()
    prompt = (
        "Interpreta la salida de las siguientes herramientas SAST locales sobre el código del proyecto.\n"
        "Identifica los fallos reales de los falsos positivos y genera un reporte en ESPAÑOL "
        "estructurado según la metodología RAPTOR (Etapas A-D):\n\n"
        f"{sast_resumen}"
    )
    return StreamingResponse(sse_stream_gemini(prompt, model, client), media_type="text/event-stream")

# ── Chat ──────────────────────────────────────────────────────────────────

@app.post("/api/chat/start")
async def chat_start(request: Request):
    body = await request.json()
    model = body.get("model", DEFAULT_MODEL)
    gemini_client = get_client()
    session_id = str(uuid.uuid4())
    try:
        chat = gemini_client.iniciar_chat(model=model)
        chat_sessions[session_id] = {"chat": chat, "client": gemini_client}
        return {"session_id": session_id, "model": model}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"No se pudo iniciar el chat: {str(e)}")

@app.post("/api/chat/message")
async def chat_message(request: Request):
    body = await request.json()
    session_id = body.get("session_id", "")
    message = body.get("message", "").strip()
    if not session_id or session_id not in chat_sessions:
        raise HTTPException(status_code=400, detail="Sesión de chat no válida o expirada.")
    if not message:
        raise HTTPException(status_code=400, detail="Mensaje vacío.")
    chat = chat_sessions[session_id]["chat"]
    return StreamingResponse(sse_stream_chat(chat, message), media_type="text/event-stream")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
