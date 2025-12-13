# path: api_server.py
# Synara PARS - Enterprise API (V2.5 - DB Integrated)

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import uuid
import os
import sys
import asyncio
import json
import datetime

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from core.engine import SynaraScannerEngine, SCAN_PROFILES
from core.ai_analyst import AIAnalyst
from core.database import init_db # FAZ 27: DB Başlatma

app = FastAPI(title="PARS Security API", version="2.5.0")

# --- CORS AYARLARI ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- WebSocket Connection Manager ---
class ConnectionManager:
    """
    WebSocket bağlantılarını yöneten ve mesaj yayınlayan sınıf.
    """
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        print(f"[WS] Yeni bağlantı. Aktif: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            print(f"[WS] Bağlantı koptu. Aktif: {len(self.active_connections)}")

    async def broadcast(self, message: str):
        """Tüm bağlı istemcilere mesaj gönderir."""
        for connection in self.active_connections[:]:
            try:
                await connection.send_text(message)
            except Exception:
                self.disconnect(connection)

manager = ConnectionManager()

# Ana Event Loop referansı (Thread-safe broadcast için gerekli)
MAIN_LOOP = None

@app.on_event("startup")
async def startup_event():
    global MAIN_LOOP
    MAIN_LOOP = asyncio.get_running_loop()
    
    # FAZ 27: Uygulama başladığında veritabanı tablolarını oluştur.
    print("[DB] Veritabanı başlatılıyor (SQLite/SQLAlchemy)...")
    init_db()
    print("[DB] Veritabanı başlatma tamamlandı.")

# --- Veri Modelleri ---
class ScanRequest(BaseModel):
    target_url: str
    profile: str = "BUG_BOUNTY_CORE"
    user_id: str = "DEVELOPER_TEST" 
    api_key: Optional[str] = None

class ScanStatus(BaseModel):
    scan_id: str
    status: str
    progress: float
    score: float
    findings_count: int
    current_phase: str
    logs: List[str]

class AIRequest(BaseModel):
    prompt: str
    context_scan_id: Optional[str] = None
    api_key: Optional[str] = None 

# --- Bellek İçi Veritabanı ---
# Not: ACTIVE_SCANS artık sadece Engine referanslarını, durumu ve logları tutar. 
# Zafiyetler DB'ye taşındı.
ACTIVE_SCANS = {}

# --- Logger & WebSocket Broadcaster ---
def _headless_logger(scan_id: str, message: str, level: str):
    """
    Logları hem belleğe yazar hem de WebSocket üzerinden canlı yayınlar.
    """
    if scan_id in ACTIVE_SCANS:
        log_entry = f"[{level}] {message}"
        ACTIVE_SCANS[scan_id]["logs"].append(log_entry)
        
        # Son 500 logu tut (Memory Optimization)
        if len(ACTIVE_SCANS[scan_id]["logs"]) > 500:
            ACTIVE_SCANS[scan_id]["logs"].pop(0)
            
        print(f"[{scan_id}] {log_entry}")

        # WebSocket Broadcast (Thread-Safe)
        if MAIN_LOOP and manager.active_connections:
            payload = json.dumps({
                "type": "log",
                "scan_id": scan_id,
                "category": level,
                "level": level,
                "message": message,
                "timestamp": datetime.datetime.now().strftime("%H:%M:%S")
            })
            asyncio.run_coroutine_threadsafe(manager.broadcast(payload), MAIN_LOOP)

def _headless_progress(scan_id: str, ratio: float, phase: str):
    if scan_id in ACTIVE_SCANS:
        ACTIVE_SCANS[scan_id]["progress"] = ratio
        ACTIVE_SCANS[scan_id]["current_phase"] = phase
        
        # Progress bilgisini de WS ile gönder
        if MAIN_LOOP and manager.active_connections:
            payload = json.dumps({
                "type": "progress",
                "scan_id": scan_id,
                "progress": ratio,
                "phase": phase
            })
            asyncio.run_coroutine_threadsafe(manager.broadcast(payload), MAIN_LOOP)

def run_scan_background(scan_id: str, url: str, profile: str, user_id: str):
    # Faz Tahminleyici
    def api_progress_callback(ratio):
        phase = "SCANNING"
        if ratio < 0.1: phase = "RECONNAISSANCE"
        elif ratio < 0.3: phase = "DISCOVERY"
        elif ratio < 0.7: phase = "VULNERABILITY ASSESSMENT"
        elif ratio < 0.95: phase = "EXPLOIT ATTEMPT"
        else: phase = "REPORTING & ANALYSIS"
        _headless_progress(scan_id, ratio, phase)

    try:
        ACTIVE_SCANS[scan_id]["status"] = "running"
        ACTIVE_SCANS[scan_id]["current_phase"] = "INITIALIZING CORE"
        _headless_logger(scan_id, "Scanner Engine başlatılıyor...", "HEADER")
        
        engine = SynaraScannerEngine(
            logger_callback=lambda msg, lvl: _headless_logger(scan_id, msg, lvl),
            progress_callback=api_progress_callback,
            config_profile=profile
        )
        
        ACTIVE_SCANS[scan_id]["engine"] = engine
        final_score = engine.start_scan(url, profile)
        
        if ACTIVE_SCANS[scan_id]["status"] != "aborted":
            html_path, pdf_path = engine.save_report()
            
            # FAZ 27: Raporlama yapıldıktan sonra zafiyet sayısını DB'den çekmeliyiz.
            findings = []
            if engine.report_manager:
                findings = engine.report_manager.get_vulnerabilities()
            
            ACTIVE_SCANS[scan_id]["status"] = "completed"
            ACTIVE_SCANS[scan_id]["score"] = final_score
            ACTIVE_SCANS[scan_id]["report_path"] = html_path
            ACTIVE_SCANS[scan_id]["findings_count"] = len(findings) # DB'den gelen sonuç sayısı
            _headless_logger(scan_id, f"Tarama tamamlandı. Skor: {final_score:.1f}/100", "SUCCESS")

    except Exception as e:
        if scan_id in ACTIVE_SCANS and ACTIVE_SCANS[scan_id]["status"] != "aborted":
            ACTIVE_SCANS[scan_id]["status"] = "failed"
            _headless_logger(scan_id, f"Kritik Motor Hatası: {str(e)}", "CRITICAL")
    finally:
        if scan_id in ACTIVE_SCANS and ACTIVE_SCANS[scan_id]["status"] not in ["completed", "failed", "aborted"]:
             ACTIVE_SCANS[scan_id]["status"] = "failed"
             _headless_logger(scan_id, "Tarama beklenmedik şekilde sonlandı.", "CRITICAL")
             
        if scan_id in ACTIVE_SCANS:
            ACTIVE_SCANS[scan_id]["engine"] = None 

# --- Endpoints ---

@app.get("/")
def root():
    return {"system": "PARS Security Core", "status": "online", "version": "v2.5 DB-Integrated"}

@app.websocket("/ws/logs")
async def websocket_endpoint(websocket: WebSocket):
    """
    Canlı log akışı için WebSocket endpoint'i.
    Dashboard buraya bağlanarak logları anlık alır.
    """
    await manager.connect(websocket)
    try:
        while True:
            # Client'dan gelen ping/pong mesajlarını bekle (Keep-alive)
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)

@app.post("/api/v1/scan/start", response_model=Dict[str, str])
def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    if request.profile not in SCAN_PROFILES:
        raise HTTPException(status_code=400, detail="Geçersiz tarama profili.")
        
    scan_id = str(uuid.uuid4())
    
    ACTIVE_SCANS[scan_id] = {
        "target": request.target_url,
        "status": "initializing",
        "progress": 0.0,
        "score": 100.0,
        "findings_count": 0,
        "logs": [f"[HEADER] New Scan Job ({scan_id}) Initialized by User: {request.user_id}"],
        "engine": None,
        "report_path": None,
        "current_phase": "Waiting for Core Engine"
    }
    
    background_tasks.add_task(run_scan_background, scan_id, request.target_url, request.profile, request.user_id)
    return {"scan_id": scan_id, "message": "Tarama başlatıldı."}

@app.get("/api/v1/scan/{scan_id}/status", response_model=ScanStatus)
def get_scan_status(scan_id: str):
    if scan_id not in ACTIVE_SCANS:
        raise HTTPException(status_code=404, detail="Tarama bulunamadı.")
        
    data = ACTIVE_SCANS[scan_id]
    findings_count = data.get("findings_count", 0) 
    score = data.get("score", 100.0) 
    recent_logs = data["logs"] if data["logs"] else []
    
    return ScanStatus(
        scan_id=scan_id, 
        status=data["status"], 
        progress=data["progress"],
        score=score, 
        findings_count=findings_count, 
        current_phase=data["current_phase"],
        logs=recent_logs
    )

@app.post("/api/v1/scan/{scan_id}/stop")
def stop_scan(scan_id: str):
    if scan_id not in ACTIVE_SCANS:
        raise HTTPException(status_code=404, detail="Tarama bulunamadı.")
        
    data = ACTIVE_SCANS[scan_id]
    
    if data["status"] in ["completed", "failed", "aborted"]:
        return JSONResponse(status_code=200, content={"message": "Tarama zaten sonlanmış."})

    engine = data.get("engine")
    if engine:
        engine.stop_scan()
        data["status"] = "aborted"
        data["current_phase"] = "MANUALLY ABORTED"
        _headless_logger(scan_id, "Tarama kullanıcı tarafından durduruldu.", "WARNING")
        return {"message": "Tarama durdurma komutu gönderildi."}
    else:
        data["status"] = "aborted"
        data["current_phase"] = "ABORTED BEFORE START"
        _headless_logger(scan_id, "Tarama başlatılmadan önce durduruldu.", "WARNING")
        return {"message": "Tarama durduruldu (Engine başlamadı)."}

@app.get("/api/v1/scan/{scan_id}/results")
def get_scan_results(scan_id: str):
    if scan_id not in ACTIVE_SCANS:
        raise HTTPException(status_code=404, detail="Tarama bulunamadı.")
        
    data = ACTIVE_SCANS[scan_id]
    engine = data.get("engine")
    
    # FAZ 27: Sonuçları DB'den çekmek için ReportManager'ı kullan.
    if engine and engine.report_manager:
        results = engine.report_manager.get_vulnerabilities()
    else:
        # Eğer engine başlatılmadıysa, boş liste döndür.
        results = [] 
        
    return {"results": results}

@app.post("/api/v1/ai/analyze")
async def analyze_with_ai(request: AIRequest):
    dummy_logger = lambda msg, lvl: print(f"[AI] {msg}")
    analyst = AIAnalyst(dummy_logger)
    
    if not request.context_scan_id:
        # DB Entegrasyonundan sonra dahi AI Analyst'in beklediği format (category, level, message) korunmalıdır.
        chat_data = [{"category": "CHAT", "level": "INFO", "message": request.prompt}]
        response = await analyst.analyze_results(chat_data, 100.0, api_key=request.api_key) 
        return {"response": response}

    if request.context_scan_id not in ACTIVE_SCANS:
        raise HTTPException(status_code=404, detail="Referans tarama bulunamadı.")
    
    data = ACTIVE_SCANS[request.context_scan_id]
    engine = data.get("engine")
    
    # FAZ 27: Analiz için veriyi DB'den çek
    if engine and engine.report_manager:
        results_for_ai = engine.report_manager.get_vulnerabilities()
    else:
        results_for_ai = []
    
    if not results_for_ai:
        return {"response": "Tarama verisi henüz oluşmadı veya zafiyet bulunamadı."}
    
    response = await analyst.analyze_results(results_for_ai, engine.score, api_key=request.api_key)
    return {"response": response}

if __name__ == "__main__":
    print("[*] PARS API Server Başlatılıyor (Port: 8000)...")
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)