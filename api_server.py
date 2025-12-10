# path: api_server.py
# Synara PARS - Enterprise API (V2.2 - AI Support)

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import uuid
import os
import sys
import asyncio

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from core.engine import SynaraScannerEngine, SCAN_PROFILES
from core.ai_analyst import AIAnalyst # YENİ IMPORT

app = FastAPI(title="PARS Security API", version="2.2.0")

# --- Veri Modelleri ---
class ScanRequest(BaseModel):
    target_url: str
    profile: str = "BUG_BOUNTY_CORE"
    api_key: Optional[str] = None

class ScanStatus(BaseModel):
    scan_id: str
    status: str
    progress: float
    score: float
    findings_count: int
    logs: List[str]

class AIRequest(BaseModel):
    prompt: str
    context_scan_id: Optional[str] = None # Hangi tarama ile ilgili olduğu

# --- Bellek İçi Veritabanı ---
ACTIVE_SCANS = {}

# --- Logger (Değişmedi) ---
def _headless_logger(scan_id: str, message: str, level: str):
    if scan_id in ACTIVE_SCANS:
        log_entry = f"[{level}] {message}"
        ACTIVE_SCANS[scan_id]["logs"].append(log_entry)
        if len(ACTIVE_SCANS[scan_id]["logs"]) > 500:
             ACTIVE_SCANS[scan_id]["logs"].pop(0)
        print(f"[{scan_id}] {log_entry}")

def _headless_progress(scan_id: str, ratio: float):
    if scan_id in ACTIVE_SCANS:
        ACTIVE_SCANS[scan_id]["progress"] = ratio

def run_scan_background(scan_id: str, url: str, profile: str):
    try:
        ACTIVE_SCANS[scan_id]["status"] = "running"
        engine = SynaraScannerEngine(
            logger_callback=lambda msg, lvl: _headless_logger(scan_id, msg, lvl),
            progress_callback=lambda val: _headless_progress(scan_id, val),
            config_profile=profile
        )
        ACTIVE_SCANS[scan_id]["engine"] = engine
        final_score = engine.start_scan(url, profile)
        html_path, pdf_path = engine.save_report()
        
        ACTIVE_SCANS[scan_id]["status"] = "completed"
        ACTIVE_SCANS[scan_id]["score"] = final_score
        ACTIVE_SCANS[scan_id]["report_path"] = html_path
        _headless_logger(scan_id, f"Tarama tamamlandı. Skor: {final_score}", "SUCCESS")
    except Exception as e:
        ACTIVE_SCANS[scan_id]["status"] = "failed"
        _headless_logger(scan_id, f"Kritik Motor Hatası: {str(e)}", "CRITICAL")

# --- Endpoints ---

@app.get("/")
def root():
    return {"system": "PARS Security Core", "status": "online", "version": "v2.2 AI-Enabled"}

@app.post("/scan/start", response_model=Dict[str, str])
def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    if request.profile not in SCAN_PROFILES:
        raise HTTPException(status_code=400, detail="Geçersiz tarama profili.")
    scan_id = str(uuid.uuid4())
    ACTIVE_SCANS[scan_id] = {
        "target": request.target_url,
        "status": "initializing",
        "progress": 0.0,
        "score": 100.0,
        "logs": [],
        "engine": None,
        "report_path": None
    }
    background_tasks.add_task(run_scan_background, scan_id, request.target_url, request.profile)
    return {"scan_id": scan_id, "message": "Tarama başlatıldı."}

@app.get("/scan/{scan_id}/status", response_model=ScanStatus)
def get_scan_status(scan_id: str):
    if scan_id not in ACTIVE_SCANS:
        raise HTTPException(status_code=404, detail="Tarama bulunamadı.")
    data = ACTIVE_SCANS[scan_id]
    engine = data.get("engine")
    findings_count = len(engine.results) if engine else 0
    if engine: data["score"] = engine.score
    recent_logs = data["logs"][-50:] if data["logs"] else []
    return ScanStatus(
        scan_id=scan_id, status=data["status"], progress=data["progress"],
        score=data["score"], findings_count=findings_count, logs=recent_logs
    )

@app.get("/scan/{scan_id}/results")
def get_scan_results(scan_id: str):
    if scan_id not in ACTIVE_SCANS:
        raise HTTPException(status_code=404, detail="Tarama bulunamadı.")
    engine = ACTIVE_SCANS[scan_id].get("engine")
    return {"results": engine.results if engine else []}

# --- YENİ AI ENDPOINT ---
@app.post("/ai/analyze")
async def analyze_with_ai(request: AIRequest):
    """
    Yapay zeka analizi yapar. 
    Eğer context_scan_id verilirse o taramanın sonuçlarını kullanır,
    yoksa sadece prompt'u chat olarak işler.
    """
    
    # Sunucu tarafında dummy bir logger kullanalım
    dummy_logger = lambda msg, lvl: print(f"[AI] {msg}")
    analyst = AIAnalyst(dummy_logger)
    
    # 1. Chat Modu (Sadece soru sorma)
    if not request.context_scan_id:
        # Chat için özel yapı: Kategori CHAT
        chat_data = [{"category": "CHAT", "level": "INFO", "message": request.prompt}]
        response = await analyst.analyze_results(chat_data, 100.0)
        return {"response": response}

    # 2. Bağlamsal Analiz (Tarama sonuçları üzerine)
    if request.context_scan_id not in ACTIVE_SCANS:
        raise HTTPException(status_code=404, detail="Referans tarama bulunamadı.")
    
    engine = ACTIVE_SCANS[request.context_scan_id].get("engine")
    if not engine:
        return {"response": "Tarama verisi henüz oluşmadı."}
        
    response = await analyst.analyze_results(engine.results, engine.score)
    return {"response": response}