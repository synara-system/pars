# path: core/neural_engine.py
import aiohttp
import asyncio
import json
import os
import time
import random
from typing import Dict, Any, Optional, List

# Local Imports
from .data_simulator import DataSimulator

# --- ORKESTRA ŞEFİ AYARLARI (Conductor Settings) ---
# AI'ın sistemi kilitlemesini önlemek için agresif zamanlamalar.
MAX_RETRIES = 2               # DÜŞÜRÜLDÜ: Israr etme, hızlı karar ver.
INITIAL_BACKOFF = 1
CRITICAL_COOLDOWN_TIME = 60   # ARTTIRILDI: Hata varsa daha uzun süre kenara çekil.
MAX_CONSECUTIVE_ERRORS = 3    # YENİ: 3 Hata yapan oyuncu (AI) oyundan alınır.

# MODEL FALLBACK LİSTESİ (Öncelik Sırasına Göre)
AVAILABLE_MODELS = [
    "gemini-1.5-flash",          # Standart
    "gemini-1.5-flash-001",      # Alternatif
    "gemini-2.0-flash-exp",      # YENİ: Deneysel Hızlı Model
    "gemini-exp-1206",           # YENİ: Aralık Güncellemesi
    "gemini-1.5-pro",            # Güçlü
    "gemini-1.5-pro-001",        # Pro Alternatif
    "gemini-pro"                 # Legacy
]

class NeuralEngine:
    """
    PARS NEURAL ENGINE (v24.5 - Orchestra Conductor Mode)
    
    Yapay Zeka entegrasyonunu yöneten beyin.
    
    Güncellemeler (v24.5):
    - Conductor Mode: AI yanıt vermezse sistemi bekletmez, hemen simülasyona geçer.
    - Strike System: Üst üste hata durumunda AI'ı tamamen devre dışı bırakır (Offline Mode).
    - Fail Fast: Timeout süreleri kısaltıldı (60s -> 20s).
    """
    
    def __init__(self, logger_callback, api_key: str = ""):
        self.log = logger_callback
        
        # API Anahtarını al ve temizle
        raw_key = api_key or os.getenv("GOOGLE_API_KEY", "") or os.getenv("GEMINI_API_KEY", "")
        self.api_key = str(raw_key).strip().strip("'").strip('"').strip('[').strip(']')
        
        # Dinamik Model Yönetimi
        self.current_model_index = 0
        self.model_name = AVAILABLE_MODELS[0]
        self.base_url_template = "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent"
        
        self.is_active = bool(self.api_key) and len(self.api_key) > 10
        self.api_fail_cooldown_until = 0
        
        # Orkestra Durumu
        self.consecutive_errors = 0   # Hata sayacı
        self.offline_mode = False     # Kalıcı sessizlik modu
        
        if self.is_active:
            masked_key = f"******{self.api_key[-4:]}" if len(self.api_key) > 4 else "******"
            self.log(f"[NEURAL] Şef Podyumda (v24.5). Model: {self.model_name} | Timeout: 20s", "SUCCESS")
        else:
            self.log("[NEURAL] API Anahtarı eksik. Simülasyon modunda çalışılacak.", "WARNING")

    def _get_current_url(self) -> str:
        """Şu anki aktif model ile URL oluşturur."""
        return self.base_url_template.format(self.model_name)

    def _switch_model(self):
        """Bir sonraki modele geçer (Fallback)."""
        old_model = self.model_name
        self.current_model_index = (self.current_model_index + 1) % len(AVAILABLE_MODELS)
        self.model_name = AVAILABLE_MODELS[self.current_model_index]
        self.log(f"[NEURAL] Model Rotasyonu: {old_model} -> {self.model_name}", "WARNING")

    def _clean_json_markdown(self, text: str) -> str:
        text = text.strip()
        if text.startswith("```"):
            if text.startswith("```json"):
                text = text[7:]
            else:
                text = text[3:]
        if text.endswith("```"):
            text = text[:-3]
        return text.strip()

    async def generate_ai_payloads(self, context_data: Dict[str, Any], vulnerability_type: str, count: int = 5) -> List[str]:
        # Eğer offline moddaysak hiç vakit kaybetme
        if not self.is_active or self.offline_mode:
            return DataSimulator.simulate_ai_payloads(vulnerability_type, count)

        context_str = json.dumps(context_data)
        prompt = f"""
        Sen kıdemli bir siber güvenlik fuzzer'ısın. Hedef zafiyet türü: {vulnerability_type}. 
        Mevcut tarama bağlamı: {context_str}. 
        WAF bypass potansiyeli olan {count} adet benzersiz payload üret. 
        Sadece JSON dizisi döndür. Örnek: ["p1", "p2"]
        """
        
        ai_response_text = await self._query_gemini(prompt, is_json=True)
        
        # Hata aldıysak hemen yedeğe geç
        if ai_response_text.startswith("API_ERROR") or ai_response_text.startswith("COOLDOWN"):
            # Log kirliliği yapma, sessizce geçiş yap
            return DataSimulator.simulate_ai_payloads(vulnerability_type, count)

        try:
            clean_json_text = self._clean_json_markdown(ai_response_text)
            payload_list = json.loads(clean_json_text)
            if isinstance(payload_list, list):
                return [str(p) for p in payload_list if isinstance(p, (str, int, float))][:count]
            return DataSimulator.simulate_ai_payloads(vulnerability_type, count)
        except:
            return DataSimulator.simulate_ai_payloads(vulnerability_type, count)

    async def analyze_vulnerability(self, vuln_data: Dict[str, Any]) -> str:
        if not self.is_active or self.offline_mode: return "AI Analizi Devre Dışı (Offline Mode)."

        prompt = f"""
        Zafiyet Analizi Yap:
        Kategori: {vuln_data.get('category', 'UNKNOWN')}
        Bulgu: {vuln_data.get('message', '')}
        
        1. False Positive ihtimali nedir?
        2. Doğrulama için tek bir teknik komut/payload öner.
        Çok kısa ve teknik cevap ver.
        """
        return await self._query_gemini(prompt)

    async def generate_payload(self, context: str) -> str:
        if not self.is_active or self.offline_mode: return ""
        prompt = f"Hata/Bağlam: '{context}'. WAF atlatacak tek bir payload yaz. Açıklama yok."
        return await self._query_gemini(prompt)

    async def _query_gemini(self, prompt: str, is_json: bool = False) -> str:
        # 1. Devre Kesici Kontrolü
        if self.offline_mode:
            return "API_ERROR: Offline Mode"
            
        if time.time() < self.api_fail_cooldown_until:
            return "COOLDOWN"

        headers = {"Content-Type": "application/json"}
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.2, "maxOutputTokens": 512}
        }
        if is_json:
            payload['generationConfig']['responseMimeType'] = "application/json"

        # Retry Döngüsü
        for attempt in range(MAX_RETRIES):
            current_base_url = self._get_current_url()
            
            try:
                clean_base = current_base_url.strip().strip("'").strip('"')
                url = f"{clean_base}?key={self.api_key}"
                
                # DÜZELTME: Timeout 20 saniyeye çekildi. Sistem beklemez.
                connector = aiohttp.TCPConnector(ssl=False)
                timeout_settings = aiohttp.ClientTimeout(total=20)
                
                async with aiohttp.ClientSession(connector=connector, trust_env=True, timeout=timeout_settings) as session:
                    async with session.post(url, headers=headers, json=payload) as resp:
                        
                        if resp.status == 200:
                            # BAŞARI: Sayaçları sıfırla
                            self.api_fail_cooldown_until = 0 
                            self.consecutive_errors = 0 
                            
                            data = await resp.json()
                            try:
                                return data['candidates'][0]['content']['parts'][0]['text'].strip()
                            except:
                                return "API_ERROR: Yapısal Hata"
                        
                        # HATA YÖNETİMİ
                        elif resp.status == 404:
                            self._switch_model()
                            continue 
                        
                        elif resp.status == 429:
                            # Rate limit yedik, biraz geri çekil ama ısrar etme
                            self.api_fail_cooldown_until = time.time() + CRITICAL_COOLDOWN_TIME
                            return "API_ERROR: Rate Limit"
                            
                        else:
                            # Diğer hatalar
                            self.consecutive_errors += 1
                            return f"API_ERROR: {resp.status}"

            except Exception as e:
                # Bağlantı hataları (Timeout vb.)
                if attempt == MAX_RETRIES - 1:
                    self.consecutive_errors += 1
                    # Eşik aşıldı mı?
                    if self.consecutive_errors >= MAX_CONSECUTIVE_ERRORS:
                        self.offline_mode = True
                        self.log("[NEURAL] ⚠️ Orkestra Şefi: AI çok yavaş, 'Offline Mod'a geçildi. Taramalar hızlanacak.", "WARNING")
                    
                    return f"API_ERROR: {str(e)[:50]}"
                await asyncio.sleep(1)
                
        return "API_ERROR: Timeout"