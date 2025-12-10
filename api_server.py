# path: api_server.py
# Synara PARS - Profesyonel API Sunucusu (FastAPI)
# MESTEG TEKNOLOJİ | Enterprise Security Core

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

# API Uygulaması Başlatma
app = FastAPI(
    title="PARS Security API",
    description="Pentest Autonomous Recon System - Enterprise API",
    version="2.0.0"
)

# --- Veri Modelleri ---
class ScanRequest(BaseModel):
    target_url: str
    profile: str = "BUG_BOUNTY_CORE"
    api_key: Optional[str] = None

class ScanStatus(BaseModel):
    scan_id: str
    status: str # running, completed, failed
    progress: float
    score: float
    findings_count: int
    current_log: str

# --- Bellek İçi Veritabanı (Simülasyon - İleride PostgreSQL olacak) ---
# {scan_id: {engine: SynaraScannerEngine, status: str, logs: list}}
ACTIVE_SCANS = {}

# --- Yardımcı Fonksiyonlar ---

def _headless_logger(scan_id: str, message: str, level: str):
    """Motorun ürettiği logları API belleğine kaydeder."""
    if scan_id in ACTIVE_SCANS:
        # Son 100 logu tutalım (Bellek yönetimi için)
        log_entry = f"[{level}] {message}"
        ACTIVE_SCANS[scan_id]["logs"].append(log_entry)
        if len(ACTIVE_SCANS[scan_id]["logs"]) > 100:
             ACTIVE_SCANS[scan_id]["logs"].pop(0)
        
        # Konsola da bas (Sunucu logları için)
        print(f"[{scan_id}] {log_entry}")

def _headless_progress(scan_id: str, ratio: float):
    """İlerleme durumunu günceller."""
    if scan_id in ACTIVE_SCANS:
        ACTIVE_SCANS[scan_id]["progress"] = ratio

def run_scan_background(scan_id: str, url: str, profile: str):
    """Arka planda taramayı yürüten worker fonksiyonu."""
    try:
        ACTIVE_SCANS[scan_id]["status"] = "running"
        
        # Motoru başlat (Callbackleri lambda ile bağlıyoruz)
        engine = SynaraScannerEngine(
            logger_callback=lambda msg, lvl: _headless_logger(scan_id, msg, lvl),
            progress_callback=lambda val: _headless_progress(scan_id, val),
            config_profile=profile
        )
        
        ACTIVE_SCANS[scan_id]["engine"] = engine
        
        # Taramayı başlat (Bloklayan işlem)
        # Not: engine.start_scan async çalıştırılmalı veya thread içinde olmalı.
        # SynaraScannerEngine.start_scan şu an senkron bir wrapper, içinde async loop yönetiyor.
        # Bu yüzden direkt çağırabiliriz.
        final_score = engine.start_scan(url, profile)
        
        # Rapor oluştur
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
    return {"system": "PARS Security Core", "status": "online", "version": "v2.0 Enterprise"}

@app.post("/scan/start", response_model=Dict[str, str])
def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Yeni bir tarama başlatır."""
    if request.profile not in SCAN_PROFILES:
        raise HTTPException(status_code=400, detail="Geçersiz tarama profili.")
        
    scan_id = str(uuid.uuid4())
    
    # Tarama kaydını oluştur
    ACTIVE_SCANS[scan_id] = {
        "target": request.target_url,
        "status": "initializing",
        "progress": 0.0,
        "score": 100.0,
        "logs": [],
        "engine": None,
        "report_path": None
    }
    
    # Arka plan görevini başlat
    background_tasks.add_task(run_scan_background, scan_id, request.target_url, request.profile)
    
    return {"scan_id": scan_id, "message": "Tarama kuyruğa alındı ve başlatılıyor."}

@app.get("/scan/{scan_id}/status", response_model=ScanStatus)
def get_scan_status(scan_id: str):
    """Taramanın anlık durumunu sorgular."""
    if scan_id not in ACTIVE_SCANS:
        raise HTTPException(status_code=404, detail="Tarama bulunamadı.")
    
    scan_data = ACTIVE_SCANS[scan_id]
    engine = scan_data.get("engine")
    
    findings_count = 0
    if engine:
        findings_count = len(engine.results)
        # Skoru da güncelle
        scan_data["score"] = engine.score

    last_log = scan_data["logs"][-1] if scan_data["logs"] else "Başlatılıyor..."

    return ScanStatus(
        scan_id=scan_id,
        status=scan_data["status"],
        progress=scan_data["progress"],
        score=scan_data["score"],
        findings_count=findings_count,
        current_log=last_log
    )

@app.get("/scan/{scan_id}/results")
def get_scan_results(scan_id: str):
    """Tarama sonuçlarını JSON olarak döner."""
    if scan_id not in ACTIVE_SCANS:
        raise HTTPException(status_code=404, detail="Tarama bulunamadı.")
        
    engine = ACTIVE_SCANS[scan_id].get("engine")
    if not engine:
        return {"results": []}
        
    return {"results": engine.results}

# Çalıştırma: uvicorn api_server:app --reload