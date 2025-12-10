# path: Test/trigger_ai.py

import sys
import os
import json
import time

# Proje kök dizinini path'e ekle (core modülünü bulabilmesi için)
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.engine import SynaraScannerEngine

def log_callback(msg, level):
    print(f"[{level}] {msg}")

def progress_callback(val):
    pass

# Motoru başlat
# DEFAULT_PROFILE="BUG_BOUNTY_CORE" ile başlar
engine = SynaraScannerEngine(log_callback, progress_callback)
engine.target_url = "https://across.to" # Hedefi ayarla

# LFI Verisini Simüle Et (Loglardan aldık)
vuln_data = {
    "category": "LFI",
    "level": "CRITICAL",
    "message": "LFI tespit edildi! Param: 'top', Hedef: '/proc/self/environ', Payload: '../../..//proc/self/environ'. WAF: Cloudflare.",
    "context": "Sunucu Vercel/Cloudflare. 403 response dönüyor ama boyut ve benzerlik şüpheli."
}

print("\n--- AI ANALİZİ BAŞLATILIYOR ---")

# DÜZELTME: "LFI Analizi" stringi yerine, vuln_data'yı JSON string olarak gönderiyoruz.
# Böylece ExploitManager veya NeuralEngine bu veriyi parse edip kullanabilir.
exploit_payload = json.dumps(vuln_data)

# AI Analizini Tetikle (Manuel Exploit İsteği gibi davranır)
# 'AI_SSRF_ANALYSIS' tipi, ExploitManager içinde Neural Engine'e yönlendirilecektir.
engine.run_manual_exploit("AI_SSRF_ANALYSIS", exploit_payload)

print("[INFO] AI Analiz isteği gönderildi. Cevap bekleniyor (20sn)...")

# AI Cevabını bekle (Asenkron olduğu için)
time.sleep(20) 
print("\n--- İŞLEM TAMAMLANDI ---")