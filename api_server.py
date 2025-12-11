# path: api_server.py
# Synara PARS - Enterprise API (V2.3 - Web Ready)

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware # YENİ: Web tarayıcı izni
from fastapi.responses import JSONResponse # Hata yanıtları için eklendi
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import uuid
import os
import sys
import asyncio

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from core.engine import SynaraScannerEngine, SCAN_PROFILES
from core.ai_analyst import AIAnalyst

# FastAPI uygulamasını başlatırken, endpoint'lere /api/v1 ön eki eklemek için APIRouter kullanmak daha temizdir.
# Ancak, mevcut kodda sadece FastAPI nesnesi kullanıldığı için, endpoint yollarını manuel olarak düzenliyorum.
app = FastAPI(title="PARS Security API", version="2.3.0")

# --- KRİTİK: CORS AYARLARI (Web Arayüzü İçin) ---
# Web tarayıcılarının (web_dashboard.html) bu sunucuya erişmesine izin verir.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Geliştirme için tüm sitelere izin ver. (PROD ortamında kısıtlanmalı)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# -----------------------------------------------------

# --- Veri Modelleri ---
class ScanRequest(BaseModel):
    target_url: str
    profile: str = "BUG_BOUNTY_CORE"
    # user_id alanı eklendi, çünkü web_dashboard bunu gönderiyor.
    user_id: str = "DEVELOPER_TEST" 
    api_key: Optional[str] = None

class ScanStatus(BaseModel):
    scan_id: str
    status: str
    progress: float
    score: float
    findings_count: int
    current_phase: str # Yeni eklendi (Arayüzde gösteriliyor)
    logs: List[str]

class AIRequest(BaseModel):
    prompt: str
    context_scan_id: Optional[str] = None

# --- Bellek İçi Veritabanı ---
ACTIVE_SCANS = {}

# --- Logger ---
def _headless_logger(scan_id: str, message: str, level: str):
    if scan_id in ACTIVE_SCANS:
        log_entry = f"[{level}] {message}"
        ACTIVE_SCANS[scan_id]["logs"].append(log_entry)
        
        # Son 500 logu tut
        if len(ACTIVE_SCANS[scan_id]["logs"]) > 500:
            ACTIVE_SCANS[scan_id]["logs"].pop(0)
            
        print(f"[{scan_id}] {log_entry}")

def _headless_progress(scan_id: str, ratio: float, phase: str):
    """Progress callback'i, faz bilgisini de alacak şekilde güncellendi."""
    if scan_id in ACTIVE_SCANS:
        ACTIVE_SCANS[scan_id]["progress"] = ratio
        ACTIVE_SCANS[scan_id]["current_phase"] = phase

def run_scan_background(scan_id: str, url: str, profile: str, user_id: str):
    # KRİTİK DÜZELTME: Progress callback'i faz bilgisini almalıdır. 
    # Ancak core/engine.py'nin buna uygun olması gerekir. 
    # Şimdilik lambda'yı eski haline getiriyor ve API tarafında faz yönetimini yapıyorum.
    
    # Geçici faz güncelleme fonksiyonu (Engine'i değiştirene kadar)
    def api_progress_callback(ratio):
        # Basit faz tahminleyici
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
            # Geçici progress callback'ini kullan
            progress_callback=api_progress_callback,
            config_profile=profile
        )
        
        ACTIVE_SCANS[scan_id]["engine"] = engine
        final_score = engine.start_scan(url, profile)
        
        # Tarama tamamlandıktan sonra skor ve bulgu sayısını güncelle
        if ACTIVE_SCANS[scan_id]["status"] != "aborted":
            html_path, pdf_path = engine.save_report()
            
            ACTIVE_SCANS[scan_id]["status"] = "completed"
            ACTIVE_SCANS[scan_id]["score"] = final_score
            ACTIVE_SCANS[scan_id]["report_path"] = html_path
            ACTIVE_SCANS[scan_id]["findings_count"] = len(engine.results)
            _headless_logger(scan_id, f"Tarama tamamlandı. Skor: {final_score:.1f}/100", "SUCCESS")

    except Exception as e:
        if scan_id in ACTIVE_SCANS and ACTIVE_SCANS[scan_id]["status"] != "aborted":
            ACTIVE_SCANS[scan_id]["status"] = "failed"
            _headless_logger(scan_id, f"Kritik Motor Hatası: {str(e)}", "CRITICAL")
    finally:
         # Eğer tarama biterse, %100 yap
        if scan_id in ACTIVE_SCANS and ACTIVE_SCANS[scan_id]["status"] not in ["completed", "failed", "aborted"]:
             ACTIVE_SCANS[scan_id]["status"] = "failed" # Varsayılan olarak başarısız kabul et
             _headless_logger(scan_id, "Tarama beklenmedik şekilde sonlandı (failed).", "CRITICAL")
             
        # Her durumda, engine referansını temizle (bellek yönetimi için)
        if scan_id in ACTIVE_SCANS:
            ACTIVE_SCANS[scan_id]["engine"] = None 

# --- Endpoints ---

@app.get("/")
def root():
    """Bağlantı kontrolü için ana yol (web_dashboard tarafından kontrol edilir)"""
    return {"system": "PARS Security Core", "status": "online", "version": "v2.3 Web-Ready"}


@app.post("/api/v1/scan/start", response_model=Dict[str, str])
def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    [CRITICAL ENDPOINT] Yeni bir tarama işini arka planda başlatır.
    Web Dashboard tarafından çağrılır.
    """
    if request.profile not in SCAN_PROFILES:
        raise HTTPException(status_code=400, detail="Geçersiz tarama profili.")
        
    scan_id = str(uuid.uuid4())
    
    ACTIVE_SCANS[scan_id] = {
        "target": request.target_url,
        "status": "initializing",
        "progress": 0.0,
        "score": 100.0, # Başlangıç skoru
        "findings_count": 0,
        "logs": [f"[HEADER] New Scan Job ({scan_id}) Initialized by User: {request.user_id}"],
        "engine": None,
        "report_path": None,
        "current_phase": "Waiting for Core Engine"
    }
    
    # Arka plan görevini başlatırken user_id bilgisini de gönderiyoruz.
    background_tasks.add_task(run_scan_background, scan_id, request.target_url, request.profile, request.user_id)
    
    return {"scan_id": scan_id, "message": "Tarama başlatıldı."}


@app.get("/api/v1/scan/{scan_id}/status", response_model=ScanStatus)
def get_scan_status(scan_id: str):
    """
    [CRITICAL ENDPOINT] Devam eden veya bitmiş taramanın durumunu ve loglarını döndürür.
    Web Dashboard tarafından Polling için çağrılır.
    """
    if scan_id not in ACTIVE_SCANS:
        raise HTTPException(status_code=404, detail="Tarama bulunamadı.")
        
    data = ACTIVE_SCANS[scan_id]
    
    # Engine referansı temizlenmiş olsa bile son verileri kullan
    findings_count = data.get("findings_count", 0) 
    score = data.get("score", 100.0) 
    
    # Logları tersine çevirmeden (en yeni altta) gönder
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

# --- YENİ: TARAMA DURDURMA ENDPOINT'i ---
@app.post("/api/v1/scan/{scan_id}/stop")
def stop_scan(scan_id: str):
    """
    [NEW ENDPOINT] Devam eden taramayı manuel olarak durdurur.
    """
    if scan_id not in ACTIVE_SCANS:
        raise HTTPException(status_code=404, detail="Tarama bulunamadı.")
        
    data = ACTIVE_SCANS[scan_id]
    
    if data["status"] in ["completed", "failed", "aborted"]:
        return JSONResponse(status_code=200, content={"message": "Tarama zaten sonlanmış."})

    engine = data.get("engine")
    
    if engine:
        engine.stop_scan() # Engine'deki durdurma metodunu çağır
        data["status"] = "aborted"
        data["current_phase"] = "MANUALLY ABORTED"
        _headless_logger(scan_id, "Tarama kullanıcı tarafından durduruldu.", "WARNING")
        return {"message": "Tarama durdurma komutu gönderildi."}
    else:
        # Eğer engine daha başlamadıysa, durumu direkt değiştir
        data["status"] = "aborted"
        data["current_phase"] = "ABORTED BEFORE START"
        _headless_logger(scan_id, "Tarama başlatılmadan önce durduruldu.", "WARNING")
        return {"message": "Tarama durduruldu (Engine başlamadı)."}


@app.get("/api/v1/scan/{scan_id}/results")
def get_scan_results(scan_id: str):
    if scan_id not in ACTIVE_SCANS:
        raise HTTPException(status_code=404, detail="Tarama bulunamadı.")
    engine = ACTIVE_SCANS[scan_id].get("engine")
    return {"results": engine.results if engine else []}

@app.post("/api/v1/ai/analyze")
async def analyze_with_ai(request: AIRequest):
    dummy_logger = lambda msg, lvl: print(f"[AI] {msg}")
    analyst = AIAnalyst(dummy_logger)
    
    if not request.context_scan_id:
        chat_data = [{"category": "CHAT", "level": "INFO", "message": request.prompt}]
        # KRİTİK DÜZELTME: analyze_results çağrısına api_key eklenmeli.
        response = await analyst.analyze_results(chat_data, 100.0, api_key=request.api_key) 
        return {"response": response}

    if request.context_scan_id not in ACTIVE_SCANS:
        raise HTTPException(status_code=404, detail="Referans tarama bulunamadı.")
    
    engine = ACTIVE_SCANS[request.context_scan_id].get("engine")
    if not engine:
        return {"response": "Tarama verisi henüz oluşmadı."}
    
    # KRİTİK DÜZELTME: analyze_results çağrısına api_key eklenmeli.
    response = await analyst.analyze_results(engine.results, engine.score, api_key=request.api_key)
    return {"response": response}