# path: core/scanners/http_smuggling_scanner.py

import aiohttp
import asyncio
import re
import json
from time import time
from typing import Callable, List, Dict, Any, Optional
from urllib.parse import urlparse, urljoin

from core.scanners.base_scanner import BaseScanner
from core.data_simulator import DataSimulator # Random string generation için

class HTTPSmugglingScanner(BaseScanner):
    """
    [FAZ 32 - SMUGGLING HUNTER]
    HTTP Request Smuggling zafiyetlerini (CL.TE, TE.CL) tespit etmek için
    gelişmiş test vektörleri kullanır.
    """

    PER_MODULE_LIMIT = 3 # Smuggling testleri yavaş olabilir

    # --- KRİTİK SMUGGLING VARYASYONLARI ---
    # Bu varyasyonlar, önde ve arkadaki sunucuların HTTP başlıklarını
    # farklı yorumlamasını (Content-Length vs. Transfer-Encoding) sağlar.
    SMUGGLING_VECTORS = {
        "CL.TE_Standard": {
            "CL": "Content-Length: {cl_value}",
            "TE": "Transfer-Encoding: chunked",
            "BODY_TEMPLATE": "{crlf}0{crlf}{crlf}GET /smuggle_test?{random_id} HTTP/1.1{crlf}Host: {host}{crlf}X-Smuggled: 1{crlf}{crlf}",
            "TEST_CASE": "CL.TE: Content-Length'i ön sunucu, Transfer-Encoding'i arka sunucu okur."
        },
        "TE.CL_Standard": {
            "CL": "Content-Length: {cl_value}",
            "TE": "Transfer-Encoding: chunked",
            "BODY_TEMPLATE": "{smuggled_chunk}{crlf}GET /smuggle_test?{random_id} HTTP/1.1{crlf}Host: {host}{crlf}X-Smuggled: 1{crlf}{crlf}",
            "TEST_CASE": "TE.CL: Transfer-Encoding'i ön sunucu, Content-Length'i arka sunucu okur."
        },
        "H2.CL_DESYNC": {
            "CL": "Content-Length: {cl_value}",
            "TE": "Transfer-Encoding: chunked",
            "BODY_TEMPLATE": "{crlf}0{crlf}{crlf}GET /h2_desync?{random_id} HTTP/1.1{crlf}Host: {host}{crlf}X-Desync: 1{crlf}{crlf}",
            "TEST_CASE": "HTTP/2 Desync: TE başlığını H2'ye gizleyerek arka sunucuyu karıştırma."
        },
        "CL.TE_LF_SMUGGLE": {
            "CL": "Content-Length: {cl_value}",
            "TE": "Transfer-Encoding: chunked",
            "BODY_TEMPLATE": "{lf}0{lf}{lf}GET /lf_smuggle?{random_id} HTTP/1.1{lf}Host: {host}{lf}X-LF: 1{lf}{lf}",
            "TEST_CASE": "CL.TE (LF Only): CR/LF normalizasyonu ile bypass denemesi."
        }
    }
    # EOL Karakterleri
    CRLF = "\r\n"
    LF = "\n"

    def __init__(self, logger, results_callback, request_callback: Callable[[], None]):
        super().__init__(logger, results_callback, request_callback)
        self.module_semaphore = asyncio.Semaphore(self.PER_MODULE_LIMIT)

    @property
    def name(self):
        return "HTTP Request Smuggling Tarayıcısı"

    @property
    def category(self):
        return "HTTP_SMUGGLING"

    async def scan(self, url: str, session: aiohttp.ClientSession, completed_callback: Callable[[], None]):
        self.log(f"[{self.category}] HTTP Smuggling testleri başlatılıyor...", "INFO")
        
        host = self._get_host_header(url)
        if not host:
            self.log(f"[{self.category}] Geçersiz URL formatı, tarama durduruldu.", "WARNING")
            completed_callback()
            return

        tasks = []
        for vector_name, vector in self.SMUGGLING_VECTORS.items():
            tasks.append(self._test_smuggling_vector(url, host, session, vector_name, vector))

        await asyncio.gather(*tasks)

        completed_callback()
        
    def _get_host_header(self, url: str) -> str:
        """URL'den Host başlığını (port dahil) ayıklar."""
        try:
            return urlparse(url).netloc
        except:
            return ""

    def _prepare_request(self, host: str, vector: Dict[str, Any], vector_name: str) -> Optional[bytes]:
        """
        Belirtilen vektöre göre kaçakçılık isteğini hazırlar.
        """
        # KRİTİK DÜZELTME 3: DataSimulator.generate_random_string sınıf metodudur.
        random_id = DataSimulator.generate_random_string(8) 

        # Varsayılan EOL olarak CRLF kullan (LF Only testleri hariç)
        eol = self.CRLF
        if "LF_SMUGGLE" in vector_name:
            eol = self.LF
        
        # SMUGGLED REQUEST'i oluştur
        smuggled_request = vector["BODY_TEMPLATE"].format(
            crlf=self.CRLF,
            lf=self.LF,
            host=host,
            random_id=random_id,
            smuggled_chunk=f"0{eol}{eol}G" if "TE.CL" in vector_name else "" # TE.CL için ilk chunk'ı ayarla (G harfi fazlalık)
        )
        
        # CONTENT-LENGTH (CL) hesaplaması: Smuggled request'in tamamını kapsayacak uzunluk
        smuggled_length = len(smuggled_request.encode('utf-8'))
        cl_value = smuggled_length
        
        # TE.CL için: İlk isteğin gövdesi (Transfer-Encoding)
        if "TE.CL" in vector_name:
            chunked_body = f"{hex(smuggled_length)[2:]}{eol}{smuggled_request}{eol}0{eol}{eol}"
            cl_value = len(chunked_body.encode('utf-8'))
            body = chunked_body
        
        # CL.TE için: İlk isteğin gövdesi (Content-Length)
        elif "CL.TE" in vector_name or "H2.CL" in vector_name:
            body = f"{smuggled_request}X" # Fazladan bir byte ekleyerek ikinci isteği başlatır
        
        else:
            return None # Bilinmeyen vektör

        # Başlıkları formatla
        cl_header = vector["CL"].format(cl_value=cl_value)
        te_header = vector["TE"]

        # Ana isteği (H2/H1) oluştur
        request_line = f"POST / HTTP/1.1{eol}"
        headers = f"Host: {host}{eol}{cl_header}{eol}{te_header}{eol}Connection: close{eol}{eol}"
        
        # TE.CL için TE başlığı bazen gizlenmelidir (Smuggling bypass)
        if "TE.CL" in vector_name and "H2" not in vector_name:
             headers = headers.replace("Transfer-Encoding:", "X-Transfer-Encoding:")

        full_request = request_line + headers + body
        
        return full_request.encode('utf-8')


    async def _test_smuggling_vector(self, url: str, host: str, session: aiohttp.ClientSession, 
                                     vector_name: str, vector: Dict[str, Any]):
        """
        Tek bir Smuggling vektörünü dener ve yanıt gecikmesini/kodunu izler.
        """
        request_bytes = self._prepare_request(host, vector, vector_name)
        if not request_bytes:
            return

        # KRİTİK DÜZELTME: Random ID'yi request_bytes'tan değil, template'den çekmeye çalışır.
        match = re.search(r'\?(\w+)\s', request_bytes.decode('utf-8', errors='ignore'))
        random_id = match.group(1) if match else "N/A"
        
        self.log(f"[{self.category}] Deneniyor ({vector_name}): {vector['TEST_CASE']}", "INFO")

        SMUGGLING_TIMEOUT = 10 
        
        try:
            self.request_callback()
            start_time = time()
            
            async with session.post(url, data=request_bytes, headers={'Content-Type': 'text/plain'}, timeout=aiohttp.ClientTimeout(total=SMUGGLING_TIMEOUT)) as res:
                end_time = time()
                latency = end_time - start_time
                
                response_text = await res.text()
                
                is_time_based = latency > SMUGGLING_TIMEOUT * 0.8
                is_reflected = f"?{random_id}" in response_text
                
                # --- SMUGGLING TESPİT MANTIĞI ---
                if res.status in [404, 400, 500] and is_time_based:
                    message = f"Potansiyel TE.CL/CL.TE Smuggling Tespiti (Time-Based) - Arka sunucu {latency:.2f}s gecikti. Vektör: {vector_name}"
                    self._report_smuggling(message, request_bytes, vector_name, url)
                    
                elif is_reflected:
                    message = f"KRİTİK SMUGGLING TESPİTİ (Reflection): Smuggled ID ({random_id}) yanıtta yansıdı. Vektör: {vector_name}"
                    self._report_smuggling(message, request_bytes, vector_name, url)
                    
                else:
                    self.log(f"[{self.category}] Başarısız ({vector_name}): Status {res.status}, Gecikme {latency:.2f}s.", "INFO")

        except asyncio.TimeoutError:
            message = f"Potansiyel CL.TE/TE.CL Smuggling Tespiti (Hard Timeout) - Sunucu {SMUGGLING_TIMEOUT}s sonra yanıt vermeyi kesti. Vektör: {vector_name}"
            self._report_smuggling(message, request_bytes, vector_name, url)
            
        except Exception as e:
            self.log(f"[{self.category}] Genel Hata ({vector_name}): {type(e).__name__}", "WARNING")

    def _report_smuggling(self, message: str, request_bytes: bytes, vector_name: str, url: str):
        """
        Smuggling bulgusunu formatlayıp raporlar.
        """
        srp_score = 25.0 
        
        raw_request_str = request_bytes.decode('utf-8').replace("\r\n", "\\r\\n")
        
        poc_data = {
            "url": url,
            "vector": vector_name,
            "raw_request": raw_request_str,
            "description": message
        }

        self.add_result(
            self.category,
            "CRITICAL",
            f"[SMUGGLING HATA TAŞIYICI] {message}",
            srp_score,
            poc_data=poc_data
        )

        self.log(f"[{self.category} | CRITICAL] {message}", "CRITICAL")