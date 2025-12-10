# path: core/neural_engine.py

import aiohttp
import asyncio
import json
import os
import time
import random # KRİTİK DÜZELTME: random.uniform kullanıldığı için eklendi
from typing import Dict, Any, Optional

# API İstekleri için Ustel Geri Çekilme (Exponential Backoff) Sabitleri
MAX_RETRIES = 3
INITIAL_BACKOFF = 2  # Saniye

class NeuralEngine:
    """
    PARS NEURAL ENGINE (v23.0 - Mini Brain)
    
    Google Gemini 1.5 Flash API kullanarak tespit edilen zafiyetler için
    ikinci bir göz (AI Verification) ve sömürü önerisi (Exploit Suggestion) sağlar.
    """
    
    def __init__(self, logger_callback, api_key: str = ""):
        self.log = logger_callback
        # API Anahtarını çevresel değişkenden veya parametreden al
        # Not: Güvenilirliğini artırmak için API URL'de model belirtiliyor.
        self.api_key = api_key or os.getenv("GEMINI_API_KEY", "")
        self.base_url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent"
        self.is_active = bool(self.api_key)
        
        if self.is_active:
            self.log("[NEURAL] Yapay Zeka Motoru (Gemini 1.5 Flash) AKTİF.", "SUCCESS")
        else:
            self.log("[NEURAL] API Anahtarı bulunamadı. Yapay Zeka devre dışı.", "WARNING")

    async def analyze_vulnerability(self, vuln_data: Dict[str, Any]) -> str:
        """
        Bir zafiyet bulgusunu analiz eder ve doğrulama/exploit önerisi ister.
        """
        if not self.is_active:
            return "AI Devre Dışı."

        category = vuln_data.get('category', 'UNKNOWN')
        message = vuln_data.get('message', '')
        
        # Prompt Hazırlığı
        prompt = f"""
        Sen kıdemli bir siber güvenlik uzmanısın. Aşağıdaki zafiyet bulgusunu analiz et.
        
        Kategori: {category}
        Bulgu: {message}
        
        Lütfen şunları yap:
        1. Bu bulgunun "False Positive" (Yanlış Alarm) olma ihtimalini değerlendir.
        2. Eğer gerçekse, bunu doğrulamak veya sömürmek (exploit) için spesifik bir payload veya yöntem öner.
        3. Cevabı çok kısa (maksimum 2 cümle) ve teknik tut. Asla genel tavsiye verme.
        """
        
        return await self._query_gemini(prompt)

    async def generate_payload(self, context: str) -> str:
        """
        Belirli bir bağlam (örn: SQL hatası) için WAF bypass payload'u üretir.
        """
        if not self.is_active:
            return ""

        prompt = f"""
        Hedef sistemde şu hatayı/bağlamı aldım: "{context}"
        
        Buna göre WAF (Cloudflare/ModSecurity) atlatabilecek, özelleştirilmiş tek bir saldırı payload'ı ver.
        Sadece payload'ı yaz, açıklama yapma.
        """
        
        return await self._query_gemini(prompt)

    async def _query_gemini(self, prompt: str) -> str:
        """
        [RESILIENCE CORE] Google Gemini API'sine üstel geri çekilme ile istek atar.
        """
        headers = {"Content-Type": "application/json"}
        payload = {
            "contents": [{
                "parts": [{"text": prompt}]
            }],
            "generationConfig": {
                "temperature": 0.2, # Daha deterministik ve teknik cevaplar için düşük sıcaklık
                "maxOutputTokens": 100
            }
        }
        
        url = f"{self.base_url}?key={self.api_key}"
        
        for attempt in range(MAX_RETRIES):
            try:
                async with aiohttp.ClientSession() as session:
                    # Timeout 30 saniyeye çıkarıldı (Stabilite için)
                    async with session.post(url, headers=headers, json=payload, timeout=30) as resp:
                        
                        # 200 OK
                        if resp.status == 200:
                            data = await resp.json()
                            try:
                                # Gemini Response Parsing
                                text = data['candidates'][0]['content']['parts'][0]['text']
                                return text.strip()
                            except (KeyError, IndexError):
                                self.log(f"[NEURAL] HATA: API yanıtı ayrıştırılamadı. Yanıt: {await resp.text()[:100]}...", "CRITICAL")
                                return "AI Cevabı ayrıştırılamadı."
                        
                        # Hata Kodları (Retry Gerekli)
                        elif resp.status in [429, 500, 503]:
                            self.log(f"[NEURAL] HATA: API sunucu/limit hatası aldı ({resp.status}). {attempt + 1}/{MAX_RETRIES} tekrar deneniyor...", "WARNING")
                            if attempt < MAX_RETRIES - 1:
                                backoff_time = INITIAL_BACKOFF * (2 ** attempt) + random.uniform(0, 1)
                                await asyncio.sleep(backoff_time)
                            else:
                                return f"API Hatası: {resp.status}. Tüm denemeler başarısız."
                        
                        # Diğer Client Hataları (Retry Yok)
                        else:
                            error_text = await resp.text()
                            self.log(f"[NEURAL] HATA: API client hatası aldı ({resp.status}). {error_text[:100]}...", "CRITICAL")
                            return f"API Hatası: {resp.status}"
                            
            except (aiohttp.client_exceptions.ClientConnectorError, asyncio.TimeoutError) as e:
                self.log(f"[NEURAL] HATA: Bağlantı/Zaman Aşımı Hatası. {attempt + 1}/{MAX_RETRIES} tekrar deneniyor...", "WARNING")
                if attempt < MAX_RETRIES - 1:
                    backoff_time = INITIAL_BACKOFF * (2 ** attempt) + random.uniform(0, 1)
                    await asyncio.sleep(backoff_time)
                else:
                    return f"Bağlantı Hatası: {str(e)[:50]}. Tüm denemeler başarısız."
            except Exception as e:
                self.log(f"[NEURAL] KRİTİK HATA: Beklenmedik hata: {str(e)[:50]}", "CRITICAL")
                return f"Beklenmedik Hata: {str(e)[:50]}"
                
        return "Tüm AI denemeleri başarısız oldu."