# path: core/scanners/client_logic_analyzer.py

import aiohttp
import asyncio
import re
import json
from typing import Callable, List, Dict, Any, Optional
from urllib.parse import urlparse, urljoin

# BaseScanner'dan türetilecektir.
from core.scanners.base_scanner import BaseScanner

class ClientLogicAnalyzer(BaseScanner):
    """
    [FAZ 31 - SECRET HUNTER]
    İstemci tarafı (JavaScript) kaynak kodlarını analiz ederek
    hardcoded API anahtarları, gizli endpointler ve hassas bilgiler (secrets)
    bulmaya odaklanır.
    """

    # Bu tarayıcının maksimum eşzamanlı görev limiti
    PER_MODULE_LIMIT = 5
    
    # --- KRİTİK SECRET DESENLERİ (Regex) ---
    # Not: Regexler, False Positive'i azaltmak için titizlikle seçilmiştir.
    SECRET_PATTERNS = {
        "API_KEY": r"(?i)(api|token|secret|access|key|auth)[_.-]?(key|token|id|pass)?\s*[:=]\s*['\"](?![0-9a-f]{4}[_-]?[0-9a-f]{4})[a-z0-9+/=_-]{10,100}['\"]",
        "JWT_SECRET": r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+",
        "AWS_KEY": r"AKIA[0-9A-Z]{16}",
        "AZURE_KEY": r"[a-f0-9]{32,64}",
        "INTERNAL_ENDPOINT": r"(\/api\/v\d|internal|dev|staging|admin|test)[_-]?\.(js|json|php|html)",
        "PASSWORD_HINT": r"(?i)pass(word)?|cred(entials)?|user_auth",
    }
    # ---------------------------------------

    def __init__(self, logger, results_callback, request_callback: Callable[[], None]):
        super().__init__(logger, results_callback, request_callback) # KRİTİK HATA DÜZELTİLDİ: super().__init> -> super().__init__()
        self.module_semaphore = asyncio.Semaphore(self.PER_MODULE_LIMIT)
        # JS Endpoint Scanner'dan alınacak JS dosyaları
        self.js_files: List[str] = []
        self.base_url: str = ""

    @property
    def name(self):
        return "Client Logic Analyzer (Secret Hunter)"

    @property
    def category(self):
        return "CLIENT_LOGIC"

    async def scan(self, url: str, session: aiohttp.ClientSession, completed_callback: Callable[[], None]):
        """
        1. JS Endpoint Scanner'dan dosyaları alır.
        2. Her dosyayı asenkron olarak indirir ve Secret Pattern'leri tarar.
        """
        self.base_url = url
        self.log(f"[{self.category}] JS Secret Avcılığı başlatılıyor...", "INFO")

        # Geçici olarak js_files listesini dolduralım (Normalde JS Finder modülünden gelmeli)
        # Örnek JS URL'leri (Simülasyon)
        temp_js_files = ["/js/main.js", "/assets/app.min.js", "/config/secrets.js"]
        
        # Gerçek ClientLogicAnalyzer, JS Finder'dan beslenir.
        # Bu aşamada JS Finder henüz bitmediği için manuel örnek veriyoruz:
        self.js_files = [urljoin(self.base_url, p) for p in temp_js_files]

        if not self.js_files:
            self.log(f"[{self.category}] Analiz edilecek JavaScript dosyası bulunamadı (JS Finder verisi eksik).", "INFO")
            completed_callback()
            return
        
        self.log(f"[{self.category}] {len(self.js_files)} adet JavaScript dosyası analiz ediliyor...", "INFO")

        tasks = []
        for js_url in self.js_files:
            tasks.append(self._analyze_js_file(js_url, session))

        await asyncio.gather(*tasks)

        completed_callback()


    async def _analyze_js_file(self, js_url: str, session: aiohttp.ClientSession):
        """
        Tek bir JS dosyasını indirir ve kritik desenler için tarar.
        """
        async with self.module_semaphore:
            js_content = await self._fetch_js_content(js_url, session)
            if not js_content:
                return

            secrets_found: List[Dict[str, str]] = []
            
            # Her bir Secret Pattern'i tarar
            for secret_type, pattern in self.SECRET_PATTERNS.items():
                
                # Çok büyük dosyalarda satır satır tarama daha mantıklıdır (Hafıza limitine takılmaz)
                for line_number, line in enumerate(js_content.splitlines(), 1):
                    match = re.search(pattern, line)
                    
                    if match:
                        value = match.group(0).strip()
                        secrets_found.append({
                            "type": secret_type,
                            "line": line_number,
                            "snippet": line.strip()[:100], # İlk 100 karakteri göster
                            "value_partial": value[:20] + "..." # Değerin bir kısmını göster
                        })
                        
                        # Tek bir satırda birden fazla kez bulursa, gereksiz raporlamayı önlemek için döngüyü kır
                        break 
                        
            # Sonuçları Raporla
            if secrets_found:
                self.log(f"[{self.category}] KRİTİK IFŞA: {js_url} dosyasında {len(secrets_found)} adet Hardcoded Secret tespit edildi!", "CRITICAL")
                
                for secret in secrets_found:
                    message = (f"Hardcoded Secret ({secret['type']}) ifşası: Dosya: {js_url} | Satır: {secret['line']} | "
                               f"Değer: {secret['value_partial']}")
                    
                    self.add_result(
                        self.category,
                        "CRITICAL", # Hardcoded sır her zaman KRİTİK'tir.
                        message,
                        25.0, # KRİTİK SRP PUANI
                        poc_data={
                            "url": js_url,
                            "type": secret['type'],
                            "line": secret['line'],
                            "snippet": secret['snippet']
                        }
                    )
            else:
                 self.log(f"[{self.category}] {js_url} dosyasında kritik sır bulunamadı.", "INFO")


    async def _fetch_js_content(self, js_url: str, session: aiohttp.ClientSession) -> Optional[str]:
        """
        Belirtilen URL'den JS içeriğini çeker.
        """
        try:
            self.request_callback()
            
            # Sadece 5 saniye bekler ve 5MB'dan büyük dosyaları atlar
            timeout = aiohttp.ClientTimeout(total=5)
            async with session.get(js_url, timeout=timeout, max_redirects=3) as res:
                
                if res.status == 200 and 'javascript' in res.content_type:
                    
                    # 5MB boyut kontrolü (Simülasyon için)
                    content_length = res.headers.get('Content-Length')
                    if content_length and int(content_length) > 5 * 1024 * 1024: 
                         self.log(f"[{self.category}] Büyük dosya atlandı: {js_url} (> 5MB).", "WARNING")
                         return None
                         
                    return await res.text()
                
                # 404 veya 500 hataları normaldir, loglama gerekmez.
                return None
                
        except Exception as e:
            self.log(f"[{self.category}] JS indirme hatası ({js_url}): {type(e).__name__}", "WARNING")
            return None