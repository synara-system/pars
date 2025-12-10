# path: api_server.py
# Synara PARS - Profesyonel API Sunucusu (FastAPI)
# MESTEG TEKNOLOJİ | Enterprise Security Core
# V2.1 GÜNCELLEMESİ: Log kaybını önlemek için liste tabanlı loglama.

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends
from pydantic import BaseModel
from typing import Optional, List, Dict
import uuid
import os
import sys
import threading
import asyncio

# Core modülleri yola ekle
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.engine import SynaraScannerEngine, SCAN_PROFILES

app = FastAPI(
    title="PARS Security API",
    description="Pentest Autonomous Recon System - Enterprise API",
    version="2.1.0"
)

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
    logs: List[str] # GÜNCELLENDİ: Tek satır yerine liste dönüyor

# --- Bellek İçi Veritabanı ---
ACTIVE_SCANS = {}

# --- Yardımcı Fonksiyonlar ---

def _headless_logger(scan_id: str, message: str, level: str):
    if scan_id in ACTIVE_SCANS:
        log_entry = f"[{level}] {message}"
        # Logları listeye ekle (Sınırsız değil, son 500 logu tutalım)
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
    return {"system": "PARS Security Core", "status": "online", "version": "v2.1 Enterprise"}

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
    
    scan_data = ACTIVE_SCANS[scan_id]
    engine = scan_data.get("engine")
    findings_count = len(engine.results) if engine else 0
    if engine: scan_data["score"] = engine.score

    # Son 50 logu döndür (Hepsini döndürmek ağı olabilir, GUI sonuncuları alıp birleştirsin)
    recent_logs = scan_data["logs"][-50:] if scan_data["logs"] else []

    return ScanStatus(
        scan_id=scan_id,
        status=scan_data["status"],
        progress=scan_data["progress"],
        score=scan_data["score"],
        findings_count=findings_count,
        logs=recent_logs # GÜNCELLENDİ: Liste dönüyor
    )

@app.get("/scan/{scan_id}/results")
def get_scan_results(scan_id: str):
    if scan_id not in ACTIVE_SCANS:
        raise HTTPException(status_code=404, detail="Tarama bulunamadı.")
    engine = ACTIVE_SCANS[scan_id].get("engine")
    return {"results": engine.results if engine else []}