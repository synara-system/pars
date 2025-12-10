# path: core/scanners/client_logic_analyzer.py

import aiohttp
import asyncio
import re
import json
from typing import Callable, List, Dict, Any, Optional
from urllib.parse import urlparse, urljoin

from .base_scanner import BaseScanner # KRİTİK DÜZELTME: BaseScanner için göreceli import


class ClientLogicAnalyzer(BaseScanner):
    """
    [AR-GE v1.0 - CLIENT-SIDE LOGIC BREAKER]
    Ön yüz (Client-Side) kodlarında hardcoded sırlar, API anahtarları, 
    dahili URL'ler ve mantık hatalarını tespit eder.
    Source Map (.map) dosyalarını kullanarak de-obfuscation simülasyonu yapar.
    """

    # Yüksek riskli secret regex'leri (JsFinder'dakinden daha detaylı)
    SECRET_REGEXES = {
        "AWS_KEY_ID": re.compile(r"(AKIA[0-9A-Z]{16})", re.IGNORECASE),
        "AZURE_KEY": re.compile(r"([a-f0-9]{32,64})[\s]*?([a-zA-Z0-9_\-]{20,})", re.IGNORECASE), # Heuristic for long hex strings that might be keys
        "GENERIC_JWT_SECRET": re.compile(r"JWT_SECRET\s*[:=]\s*[\"']([a-zA-Z0-9_\-!@#$%^&*()+=]{20,})[\"']", re.IGNORECASE),
        "API_ENDPOINT_HARDCODED": re.compile(r"fetch\(?[\"'](\/api\/admin\/[a-zA-Z0-9_\-\/]+)[\"']", re.IGNORECASE),
    }
    
    # Maksimum de-obfuscate edilecek JS dosya boyutu (MB)
    MAX_FILE_SIZE_MB = 5 

    @property
    def name(self):
        return "Client Logic Analyzer"

    @property
    def category(self):
        return "CLIENT_LOGIC" 

    def __init__(self, logger, results_callback, request_callback: Callable[[], None]):
        super().__init__(logger, results_callback, request_callback)

    async def scan(
        self,
        url: str,
        session: aiohttp.ClientSession,
        completed_callback: Callable[[], None],
    ):
        self.log(f"[{self.category}] Client-side Logic Analizi başlatılıyor...", "INFO")
        
        # Simülasyon: Engine'in tüm JS dosyalarını ve Source Map'leri bulduğunu varsayıyoruz
        # Normalde bu veri Heuristic veya JsFinder'dan gelmelidir.
        base_domain = urlparse(url).netloc
        js_files = [] # Örnek için boş bırakıldı

        # İleride, gerçek implementasyonda buradan toplanan tüm JS dosyaları alınacaktır.
        
        # Biz burada, en kritik senaryo olan: Ana JS dosyasının Source Map'ini deneyelim.
        # Bu genelde <domain>/static/js/main.chunk.js.map şeklindedir
        
        main_js_url = f"http://{base_domain}/static/js/main.chunk.js"
        map_url = f"{main_js_url}.map"
        
        # Bu tek bir görevi senkronize bir şekilde yapabiliriz:
        await self._analyze_source_map_and_code(main_js_url, map_url, session)

        self.add_result(self.category, "SUCCESS", "Client-side Logic taraması tamamlandı.", 0)
        completed_callback()

    async def _analyze_source_map_and_code(self, js_url: str, map_url: str, session: aiohttp.ClientSession):
        """Source map dosyasını ve kodunu indirip sırları arar."""
        
        js_content = await self._fetch_content(js_url, session, is_map=False)
        if not js_content: return

        # Source Map dosyasını indir
        map_content_json = await self._fetch_content(map_url, session, is_map=True)
        
        # De-obfuscation/Secret Hunting yapacağımız asıl metin (Map içeriği ya da minified JS)
        target_text = map_content_json if map_content_json else js_content
        
        # Sırları ara
        self._find_secrets_in_text(target_text, map_url if map_content_json else js_url)

    async def _fetch_content(self, url: str, session: aiohttp.ClientSession, is_map: bool) -> Optional[str]:
        """URL'den içerik çeker ve boyutu kontrol eder."""
        try:
            # Throttle uygula
            if hasattr(self, '_apply_jitter_and_throttle'):
                await self._apply_jitter_and_throttle()
            self.request_callback()

            async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as res:
                if res.status != 200:
                    return None
                    
                size_bytes = int(res.headers.get("Content-Length", 0))
                if size_bytes > self.MAX_FILE_SIZE_MB * 1024 * 1024:
                    self.log(f"[{self.category}] Dosya boyutu sınırı aşıldı ({size_bytes / 1024 / 1024:.1f}MB). Analiz atlandı.", "WARNING")
                    return None
                
                # Sadece Map dosyalarında JSON ayrıştırması deneriz
                if is_map:
                    try:
                        data = await res.json()
                        # Source map'in 'sources' veya 'mappings' alanı varsa orijinal kaynak kodunu içeriyordur
                        if 'sources' in data and 'mappings' in data:
                            return json.dumps(data.get('sourcesContent', [])) + " " + json.dumps(data)
                        return None
                    except Exception:
                        # JSON hatası FP değildir
                        return None 
                
                # Normal JS dosyası metin olarak döner
                return await res.text(errors='ignore')
                
        except Exception:
            return None

    def _find_secrets_in_text(self, text: str, source_url: str):
        """Verilen metinde sırları arar."""
        secrets_found = False
        
        for secret_name, regex in self.SECRET_REGEXES.items():
            for match in regex.finditer(text):
                # Değer, regex'in yakalama grubuna göre değişir
                secret_value = match.group(1).strip() if match.lastindex >= 1 else match.group(0).strip()
                
                # Değerin placeholder veya çok yaygın bir string olmadığını kontrol et
                if len(secret_value) < 16 or "placeholder" in secret_value.lower() or "secret_token" in secret_value.lower():
                    continue

                self.add_result(
                    "INTERNAL_SCAN", # Hardcoded sır olduğu için bu kategoride raporla
                    "CRITICAL",
                    f"KRİTİK HARDCODED SECRET: Gizli anahtar '{secret_name}' bulundu! Kaynak: {source_url} | Değer: {secret_value[:20]}...",
                    self._calculate_score_deduction("CRITICAL")
                )
                secrets_found = True
        
        if secrets_found:
            self.log(f"[{self.category}] KRİTİK: {source_url} içinde hardcoded sırlar tespit edildi.", "CRITICAL")
        else:
            self.log(f"[{self.category}] {source_url} içinde kritik sır bulunamadı.", "INFO")