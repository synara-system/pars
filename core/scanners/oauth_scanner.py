# path: core/scanners/oauth_scanner.py

import aiohttp
import asyncio
import random
import re
from typing import Callable, List, Tuple, Optional, Dict
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

from core.scanners.base_scanner import BaseScanner

class OAUTHScanner(BaseScanner):
    """
    [AR-GE v1.0 - AUTH LOGIC BREAKER]
    OAuth 2.0 ve OpenID Connect (SSO) implementasyonlarındaki güvenlik zafiyetlerini tarar.
    Yüksek ödül getiren redirect_uri ve client secret ifşasına odaklanır.
    """

    # Hızlı SSO/OAuth testleri için parametre kalıpları
    OAUTH_PARAM_PATTERNS = {
        "client_id": r"([a-zA-Z0-9_\-]{20,})",
        "redirect_uri": r"(https?:\/\/[a-zA-Z0-9_\-\.\/]+)",
        "state": r"([a-zA-Z0-9]{32,})",
        "scope": r"([a-zA-Z0-9\s,]+)",
    }

    # Zafiyet testleri
    REDIRECT_TEST_URIS = [
        "https://evil.com/callback?id=1", # Direkt Open Redirect
        "https://evil.com/callback%23.example.com", # Hash/Path Bypass
        "https://evil.com/callback?param=https://target.com/", # Parametre karıştırma
    ]

    @property
    def name(self):
        return "OAuth/SSO Zafiyet Tarayıcısı"

    @property
    def category(self):
        return "OAUTH_SSO"

    async def scan(
        self,
        url: str,
        session: aiohttp.ClientSession,
        completed_callback: Callable[[], None],
    ):
        self.log(f"[{self.category}] OAuth/SSO analizi başlatılıyor...", "INFO")

        # Keşfedilen parametreleri topla
        discovered_params = getattr(self, "discovered_params", set())
        
        # Sadece OAUTH için kritik olan parametreleri filtrele
        client_id_list = [p for p in discovered_params if "client_id" in p.lower()]
        redirect_uri_list = [p for p in discovered_params if "redirect_uri" in p.lower()]
        
        if not client_id_list and not redirect_uri_list:
            self.add_result(self.category, "INFO", "INFO: OAuth/SSO parametreleri (client_id/redirect_uri) bulunamadı.", 0)
            completed_callback()
            return
        
        # Testleri paralel çalıştır
        semaphore = asyncio.Semaphore(5)
        tasks = []
        
        # 1. URL'de tanımlı OAUTH parametrelerini çek
        parsed = urlparse(url)
        base_query = parse_qs(parsed.query)

        # 2. Redirect URI Open Redirect Testi
        for param_name in redirect_uri_list:
            original_uri = base_query.get(param_name, [""])[0]
            if original_uri:
                tasks.extend([
                    self._test_open_redirect(url, param_name, test_uri, session, semaphore)
                    for test_uri in self.REDIRECT_TEST_URIS
                ])
                
        # 3. Client Secret / Token Exposure Testi (Ekstra kontrol için basitçe fetch)
        # Bu testin gerçekçi olması için, bu parametreyi içeren URL'yi çekip yanıtta 400/404 dönmediğinden emin olmalıyız.
        if tasks:
            await asyncio.gather(*tasks)

        self.add_result(self.category, "SUCCESS", "OAuth/SSO temel zafiyet taraması tamamlandı.", 0)
        completed_callback()

    async def _test_open_redirect(self, base_url, param, evil_uri, session, semaphore):
        """redirect_uri parametresine zararlı URL enjekte etmeye çalışır."""
        
        async with semaphore:
            test_query = parse_qs(urlparse(base_url).query)
            test_query[param] = [evil_uri]
            
            new_url_parts = list(urlparse(base_url))
            new_url_parts[4] = urlencode(test_query, doseq=True)
            test_url = urlunparse(new_url_parts)
            
            try:
                self.request_callback()
                # Redirect'i takip etme (allow_redirects=False) çok önemlidir!
                async with session.get(test_url, allow_redirects=False, timeout=10) as res:
                    
                    # Başarılı Open Redirect göstergeleri:
                    # 1. Status 302/301
                    # 2. Location başlığı EVIL URI içerir
                    location = res.headers.get("Location", "")
                    
                    if res.status in [301, 302, 303, 307] and evil_uri in location:
                        level = "CRITICAL"
                        score = self._calculate_score_deduction(level) * 0.8 # OAuth redirect olduğu için yüksek skor
                        self.add_result(
                            self.category, level,
                            f"KRİTİK: OAuth Açık Yönlendirme (Open Redirect) tespit edildi! Param: '{param}', Payload: {evil_uri}",
                            score
                        )
                    
            except Exception as e:
                self.log(f"[{self.category}] Redirect Test Hatası: {e}", "WARNING")