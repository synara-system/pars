# path: core/neural_engine.py

import aiohttp
import asyncio
import json
import os
import time
import random
from typing import Dict, Any, Optional, List # List eklendi

# Local Imports
from .data_simulator import DataSimulator # DataSimulator import edildi

# API İstekleri için Ustel Geri Çekilme (Exponential Backoff) Sabitleri
MAX_RETRIES = 5  # API limitine karşı daha dayanıklı.
INITIAL_BACKOFF = 1  # İlk bekleme süresini kısaltır.
CRITICAL_COOLDOWN_TIME = 30 # KRİTİK EKLENTİ: Tam 429 başarısızlığından sonra bekleme süresi (saniye)

class NeuralEngine:
    """
    PARS NEURAL ENGINE (v23.0 - Mini Brain)
    
    Google Gemini 2.5 Flash API kullanarak tespit edilen zafiyetler için
    ikinci bir göz (AI Verification) ve sömürü önerisi (Exploit Suggestion) sağlar.
    Akıllı API Yönetimi: Sürekli 429 hatası alındığında kısa süreli (Circuit Breaker) cooldown uygular.
    """
    
    def __init__(self, logger_callback, api_key: str = ""):
        self.log = logger_callback
        # API Anahtarını çevresel değişkenden veya parametreden al
        # Not: Güvenilirliğini artırmak için API URL'de model belirtiliyor.
        self.api_key = api_key or os.getenv("GEMINI_API_KEY", "")
        
        # KRİTİK DÜZELTME: API 404 hatasını çözmek için model adı güncellendi.
        self.base_url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
        
        self.is_active = bool(self.api_key)
        
        # Devre Kesici (Circuit Breaker) Durumu
        self.api_fail_cooldown_until = 0 # KRİTİK EKLENTİ: API'ye tekrar deneme yapmadan önce beklenecek zaman damgası
        
        if self.is_active:
            self.log("[NEURAL] Yapay Zeka Motoru (Gemini 2.5 Flash) AKTİF.", "SUCCESS")
        else:
            self.log("[NEURAL] API Anahtarı bulunamadı. Yapay Zeka devre dışı.", "WARNING")

    async def generate_ai_payloads(self, context_data: Dict[str, Any], vulnerability_type: str, count: int = 5) -> List[str]:
        """
        FAZ 29: Payload Generator'a AI tarafından üretilmiş payload'ları sağlar.
        API aktif değilse, DataSimulator'dan mock verileri alır (List[str] döndürür).
        """
        # Hata 1'i çözen kritik eksik metot eklendi.
        if not self.is_active:
            # AI pasifken DataSimulator'dan simüle edilmiş listeyi döndür
            return DataSimulator.simulate_ai_payloads(vulnerability_type, count)

        # 1. Prompt Hazırlığı (Gerçek AI isteği)
        context_str = json.dumps(context_data)
        prompt = f"""
        Sen kıdemli bir siber güvenlik fuzzer'ısın. Hedef zafiyet türü: {vulnerability_type}. 
        Mevcut tarama bağlamı/parametreler: {context_str}. 
        
        Bu bağlama özel olarak hazırlanmış, WAF'ı (Cloudflare, ModSecurity) atlatma potansiyeli olan {count} adet benzersiz payload üret. 
        Yanıtı sadece payload'ların bulunduğu bir JSON dizisi (List of Strings) olarak döndür. 
        Örnek format: ["payload1", "payload2", "payload3"]
        """
        
        # 2. AI Sorgusunu Çalıştır (JSON formatını zorla)
        ai_response_text = await self._query_gemini(prompt, is_json=True)
        
        # KRİTİK KONTROL: Eğer yanıt bir hata mesajı içeriyorsa (örn: "API Hatası: 403"), simülasyona dön.
        if ai_response_text.startswith("API Hatası:") or ai_response_text.startswith("Beklenmedik Hata:") or ai_response_text.startswith("Bağlantı Hatası:") or ai_response_text.startswith("COOLDOWN"): # COOLDOWN hatası eklendi
            self.log(f"[NEURAL] KRİTİK YEDEK: API hatası ({ai_response_text[:15]}) nedeniyle simülasyon kullanılıyor.", "WARNING")
            return DataSimulator.simulate_ai_payloads(vulnerability_type, count)

        # 3. Yanıtı Ayrıştır (List[str] bekleniyor)
        try:
            # ai_response_text bir JSON stringi olmalıdır (örn: "[\"p1\", \"p2\"]")
            payload_list = json.loads(ai_response_text)
            if isinstance(payload_list, list):
                # Başarılı JSON ve List ayrıştırması
                return payload_list[:count]
            else:
                # Başarısız JSON formatı (Liste değilse)
                self.log(f"[NEURAL] HATA: AI yanıtı Liste formatında değil: {ai_response_text[:50]}...", "WARNING")
                return DataSimulator.simulate_ai_payloads(vulnerability_type, count)
        except json.JSONDecodeError:
            # JSON ayrıştırma hatası (Raw string gelirse)
            self.log(f"[NEURAL] HATA: AI yanıtı JSON ayrıştırılamadı. Raw text: {ai_response_text[:50]}...", "WARNING")
            return DataSimulator.simulate_ai_payloads(vulnerability_type, count)


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

    async def _query_gemini(self, prompt: str, is_json: bool = False) -> str: # is_json parametresi eklendi
        """
        [RESILIENCE CORE] Google Gemini API'sine üstel geri çekilme ile istek atar.
        """
        
        # --- KRİTİK EKLENTİ: COOLDOWN KONTROLÜ (Circuit Breaker) ---
        if time.time() < self.api_fail_cooldown_until:
            wait_time = self.api_fail_cooldown_until - time.time()
            self.log(f"[NEURAL] COOLDOWN: API Motoru {wait_time:.1f} saniye boyunca pasif (Rate Limit sonrası).", "WARNING")
            return f"COOLDOWN: API Motoru beklemede ({wait_time:.1f}s)."
        # -----------------------------------------------------------------

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

        # YENİ: JSON Format Zorlaması
        if is_json:
            payload['generationConfig'] = {
                "responseMimeType": "application/json",
                "responseSchema": {
                    "type": "ARRAY",
                    "items": {"type": "STRING"}
                },
                "temperature": 0.2,
                "maxOutputTokens": 512 # Payload listeleri daha uzun olabilir
            }


        url = f"{self.base_url}?key={self.api_key}"
        
        for attempt in range(MAX_RETRIES):
            try:
                async with aiohttp.ClientSession() as session:
                    # Timeout 30 saniyeye çıkarıldı (Stabilite için)
                    async with session.post(url, headers=headers, json=payload, timeout=30) as resp:
                        
                        # 200 OK
                        if resp.status == 200:
                            # Başarılı istekte cooldown durumunu sıfırla
                            self.api_fail_cooldown_until = 0 
                            
                            data = await resp.json()
                            try:
                                # Gemini Response Parsing
                                if is_json:
                                    # JSON zorlaması yapılırken, content'in ilk part'ı JSON stringi olarak döner.
                                    text = data['candidates'][0]['content']['parts'][0]['text']
                                else:
                                    # Standart metin yanıtı
                                    text = data['candidates'][0]['content']['parts'][0]['text']
                                return text.strip()

                            except (KeyError, IndexError):
                                self.log(f"[NEURAL] HATA: API yanıtı ayrıştırılamadı. Yanıt: {await resp.text()[:100]}...", "CRITICAL")
                                # Hata durumunda ayrıştırma hatası mesajını döndür
                                return "AI Cevabı ayrıştırılamadı."
                        
                        # Hata Kodları (Retry Gerekli)
                        elif resp.status in [429, 500, 503]:
                            self.log(f"[NEURAL] HATA: API sunucu/limit hatası aldı ({resp.status}). {attempt + 1}/{MAX_RETRIES} tekrar deneniyor...", "WARNING")
                            if attempt < MAX_RETRIES - 1:
                                backoff_time = INITIAL_BACKOFF * (2 ** attempt) + random.uniform(0, 1)
                                await asyncio.sleep(backoff_time)
                            else:
                                # Son deneme başarısız
                                # KRİTİK EKLENTİ: Tam 429 hatası durumunda Cooldown başlat
                                if resp.status == 429:
                                    self.api_fail_cooldown_until = time.time() + CRITICAL_COOLDOWN_TIME
                                    self.log(f"[NEURAL] KRİTİK COOLDOWN BAŞLATILDI: 429 hatası nedeniyle {CRITICAL_COOLDOWN_TIME}s pasif kalacak.", "CRITICAL")

                                return f"API Hatası: {resp.status}. Tüm denemeler başarısız."
                        
                        # Diğer Client Hataları (Retry Yok)
                        else:
                            # 403 gibi hatalar burada yakalanır.
                            error_text = await resp.text()
                            self.log(f"[NEURAL] HATA: API client hatası aldı ({resp.status}). {error_text[:100]}...", "CRITICAL")
                            # Hata mesajını döndür, böylece çağıran fonksiyon (generate_ai_payloads) yakalayabilir.
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