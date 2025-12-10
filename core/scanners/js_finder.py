# path: core/scanners/js_finder.py

import aiohttp
import asyncio
import re
import random
from typing import Callable, List, Tuple, Set, Optional, Dict
from urllib.parse import urljoin, urlparse

# YENİ: DynamicScanner tipini almak için
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from core.dynamic_scanner import DynamicScanner 

from core.scanners.base_scanner import BaseScanner

class JSEndpointScanner(BaseScanner):
    """
    [AR-GE v2.0 - SPECTRE HUNTER]
    Hedefteki JavaScript dosyalarını statik olarak analiz eder.
    1. Gizli API Endpointlerini (Rest, GraphQL) bulur.
    2. Hassas Verileri (API Key, Token, Credentials) avlar (Secret Hunting).
    3. Source Map (.map) dosyalarını tespit eder.
    """

    PER_MODULE_LIMIT = 5

    # HTML üzerinde JS dosyalarını yakalayan regex
    JS_SOURCE_PATTERN = re.compile(
        r'<script[^>]+src=["\'](.*?\.js)[^>]*>',
        re.IGNORECASE
    )

    # 1. ENDPOINT PATTERNS (Gelişmiş)
    # Sadece /api/ değil, kod içi çağrıları da yakalar
    ENDPOINT_REGEXES = [
        # Standart yollar: /api/v1/user, /auth/login
        re.compile(r"[\"'](\/[a-zA-Z0-9_\-\/]+)[\"']", re.IGNORECASE),
        # Tam URL'ler (sadece hedef domain filtrelenecek)
        re.compile(r"[\"'](https?:\/\/[a-zA-Z0-9_\-\.\/]+)[\"']", re.IGNORECASE),
        # GraphQL
        re.compile(r"[\"'](\/graphql)[\"']", re.IGNORECASE),
    ]

    # 2. SECRET PATTERNS (Hazine Haritası)
    # JS içine gömülmüş kritik anahtarlar
    SECRET_REGEXES = {
        "AWS API Key": re.compile(r"((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})"),
        "Google API Key": re.compile(r"(AIza[0-9A-Za-z-_]{35})"),
        "Generic API Key": re.compile(r"[\"'](api_?key|access_?token|secret)[\"']\s*[:=]\s*[\"']([a-zA-Z0-9_\-]{20,})[\"']", re.IGNORECASE),
        "JWT Token": re.compile(r"(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})"),
        "Slack Webhook": re.compile(r"(https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8}\/B[a-zA-Z0-9_]{8}\/[a-zA-Z0-9_]{24})"),
    }

    # YENİ: DynamicScanner referansı
    dynamic_scanner: Optional['DynamicScanner']

    def __init__(self, logger_callback, result_callback, request_callback, endpoint_pattern=None, dynamic_scanner_instance=None):
        super().__init__(logger_callback, result_callback, request_callback)
        
        self.dynamic_scanner = dynamic_scanner_instance 

        self.discovered_endpoints = set()
        self.discovered_secrets = set()
        self.module_semaphore = asyncio.Semaphore(self.PER_MODULE_LIMIT)

    @property
    def name(self):
        return "Spectre JS Hunter (Endpoint & Secrets)"

    @property
    def category(self):
        return "JS_ENDPOINT"

    async def _fetch_url(self, url: str, session: aiohttp.ClientSession) -> Tuple[str, int]:
        """URL'den içerik çeker, jitter/throttle uygular."""
        try:
            if hasattr(self, '_apply_jitter_and_throttle'):
                await self._apply_jitter_and_throttle()

            self.request_callback()

            # JS dosyaları büyük olabilir, timeout'u esnet
            async with self.module_semaphore:
                async with session.get(url, allow_redirects=True, timeout=aiohttp.ClientTimeout(total=15)) as res:
                    # Büyük dosyaları okumak için read() kullanabiliriz ama text() decode eder.
                    # JS dosyaları genelde utf-8'dir.
                    content = await res.text(errors='ignore') 
                    return content, res.status

        except Exception as e:
            self.log(f"[{self.category}] Fetch Hatası ({type(e).__name__}): {url}", "WARNING")
            return "", 0

    def _analyze_content(self, content: str, js_url: str):
        """
        JS içeriğini analiz eder: Endpointler ve Secretlar.
        """
        # 1. Endpoint Taraması
        for regex in self.ENDPOINT_REGEXES:
            for match in regex.finditer(content):
                endpoint = match.group(1)
                
                # Çok kısa veya gürültülü şeyleri ele
                if len(endpoint) < 4 or " " in endpoint or "\n" in endpoint:
                    continue
                if endpoint.startswith("//"): continue # Yorum satırı veya protocol-relative link (dikkatli olunmalı)

                # Tam URL ise, scope kontrolü yapılmalı (burada basitçe kaydediyoruz, engine süzer)
                self._save_endpoint(endpoint, js_url)

        # 2. Secret Taraması (YENİ)
        for secret_name, regex in self.SECRET_REGEXES.items():
            for match in regex.finditer(content):
                # Yakalanan secret (group 1 veya 2 olabilir regex'e göre)
                secret_val = match.group(1) if match.lastindex >= 1 else match.group(0)
                
                # Context (Bağlam) Al - Secret'ın etrafındaki 50 karakter
                start = max(0, match.start() - 20)
                end = min(len(content), match.end() + 20)
                context = content[start:end].replace("\n", " ").strip()

                if secret_val not in self.discovered_secrets:
                    self.discovered_secrets.add(secret_val)
                    
                    msg = f"HASSAS VERİ BULUNDU ({secret_name}): {secret_val[:10]}... | Dosya: {js_url.split('/')[-1]} | Context: {context}"
                    
                    # Kritik seviyede raporla
                    self.add_result(
                        "FILES", # Secrets genelde Files veya Info Leak kategorisine girer
                        "CRITICAL",
                        msg,
                        5.0 # SRP Cezası
                    )
                    self.log(f"[{self.category}] {msg}", "CRITICAL")

        # 3. Source Map Kontrolü
        # Genelde dosyanın sonunda "//# sourceMappingURL=file.js.map" olur
        if "sourceMappingURL=" in content:
            self.log(f"[{self.category}] Source Map İzi Bulundu: {js_url}", "HIGH")
            self.add_result(
                "FILES",
                "INFO",
                f"Source Map tespit edildi. Kaynak kodları geri derlenebilir: {js_url}",
                0.0
            )

    def _save_endpoint(self, endpoint: str, js_url: str):
        """Bulunan endpoint'i normalize edip kaydeder."""
        try:
            absolute = urljoin(js_url, endpoint)
            p = urlparse(absolute)
            
            # Sadece http/https şemalarını al
            if p.scheme not in ['http', 'https']:
                return

            clean = f"{p.scheme}://{p.netloc}{p.path}"

            if clean not in self.discovered_endpoints:
                self.discovered_endpoints.add(clean)
                
                # Engine'e bildir (Fuzzing için)
                if hasattr(self, 'engine_instance'):
                    self.engine_instance.add_discovered_param(clean)
                
                # Konsolu kirletmemek için sadece ilk 10 tanesini veya önemli görünenleri logla
                if "/api/" in clean or "admin" in clean or "v1" in clean:
                    self.log(f"[{self.category}] API Endpoint: {clean}", "SUCCESS")
        except Exception:
            pass

    async def scan(self, url: str, session: aiohttp.ClientSession, completed_callback: Callable[[], None]):
        """Tüm JS endpoint tarama süreci."""
        self.log(f"[{self.category}] Spectre JS Hunter Başlatıldı: {url}", "INFO")
        self.discovered_endpoints.clear()
        self.discovered_secrets.clear()

        # 1. Ana sayfayı çek
        html, status = await self._fetch_url(url, session)
        
        if not html:
            self.log(f"[{self.category}] Ana URL çekilemedi (Status: {status}). Keşif atlandı.", "CRITICAL")
            completed_callback()
            return
            
        # 2. Dahili JS dosyalarını bul
        js_urls = set()
        for match in self.JS_SOURCE_PATTERN.finditer(html):
            rel = match.group(1)
            abs_url = urljoin(url, rel)

            # Sadece hedef domain'deki JS dosyalarını tara (CDN'leri atla - opsiyonel)
            # CDN'lerde de bazen API key unutulur ama şimdilik hedef odaklı gidelim.
            if urlparse(abs_url).netloc == urlparse(url).netloc:
                js_urls.add(abs_url)

        self.log(f"[{self.category}] {len(js_urls)} adet dahili JS dosyası analiz edilecek.", "INFO")

        # 3. Her bir JS dosyasını paralel işle
        tasks = []
        for js_url in js_urls:
            tasks.append(self._process_js_file_aio(js_url, session))
            
        if tasks:
            await asyncio.gather(*tasks)

        # 4. Özet Rapor
        if self.discovered_endpoints:
            count = len(self.discovered_endpoints)
            self.log(f"[{self.category}] Toplam {count} adet endpoint ve yol haritası çıkarıldı.", "SUCCESS")
            
            # Sadece bilgi olarak ekle, secret'lar zaten CRITICAL olarak eklendi
            self.add_result(
                self.category,
                "INFO",
                f"{count} adet endpoint js dosyalarından çıkarıldı.",
                0
            )
        else:
            self.log(f"[{self.category}] JS dosyalarından kayda değer yapı çıkarılamadı.", "INFO")

        completed_callback()
        
    async def _process_js_file_aio(self, js_url: str, session: aiohttp.ClientSession):
        """
        JS dosyasını indir ve analiz et.
        """
        content, status = await self._fetch_url(js_url, session)
        if status == 200 and content:
            self._analyze_content(content, js_url)
        else:
            self.log(f"[{self.category}] JS Erişilemedi ({status}): {js_url}", "WARNING")