# path: core/scanners/subdomain_takeover.py

import aiohttp
import asyncio
from typing import Callable, Dict, List, Optional
from urllib.parse import urlparse

from core.scanners.base_scanner import BaseScanner

class SubdomainTakeoverScanner(BaseScanner):
    """
    [AR-GE v19.0 - DOMAIN SNATCHER]
    Subdomain Takeover zafiyetlerini tespit eder ve Kanıt (POC) üretir.
    
    Yöntem:
    - Alt alan adlarına HTTP isteği gönderir.
    - Yanıt gövdesinde bilinen bulut servislerinin "Sahipsiz Kaynak" hata mesajlarını (Fingerprints) arar.
    - Auto-POC: Zafiyet durumunda doğrulama komutları (dig/nslookup) ve HTTP kanıtı üretir.
    """

    # 30+ Popüler Servis İmza Veritabanı
    # Format: "Servis Adı": ["Hata Mesajı İmzası 1", "Hata Mesajı İmzası 2"]
    TAKEOVER_SIGNATURES = {
        "GitHub Pages": [
            "There isn't a GitHub Pages site here.",
            "For root URLs (like http://example.com/) you must provide an index.html file"
        ],
        "Heroku": [
            "herokucdn.com/error-pages/no-such-app.html",
            "No such app",
            "Heroku | Welcome to your new app!"
        ],
        "AWS S3": [
            "The specified bucket does not exist",
            "Repository not found",
            "NoSuchBucket"
        ],
        "Azure": [
            "The resource you are looking for has been removed, had its name changed, or is temporarily unavailable."
        ],
        "Shopify": [
            "Sorry, this shop is currently unavailable.",
            "Only one step left!"
        ],
        "Tumblr": [
            "Whatever you were looking for doesn't currently exist at this address."
        ],
        "WordPress.com": [
            "Do you want to register",
            "is not a valid blog address"
        ],
        "Ghost": [
            "The thing you were looking for is no longer here",
            "The page you were looking for doesn't exist"
        ],
        "BigCartel": [
            "<h1>404</h1>",
            "The shop you were looking for does not exist."
        ],
        "Bitbucket": [
            "Repository not found",
            "The requested repository either does not exist or you do not have access."
        ],
        "Campaign Monitor": [
            "Double check the URL",
            "<strong>Trying to access your account?</strong>"
        ],
        "Cargo": [
            "If you're moving your domain away from Cargo you must make this configuration through your registrar's DNS control panel."
        ],
        "FeedPress": [
            "The feed has not been found."
        ],
        "Surge.sh": [
            "project not found"
        ],
        "Zendesk": [
            "Help Center Closed"
        ],
        "Readme.io": [
            "Project doesnt exist... yet!"
        ],
        "Kinsta": [
            "No Site For Domain"
        ],
        "LaunchRock": [
            "It looks like you may have taken a wrong turn somewhere. Don't worry...it happens to all of us."
        ],
        "Pantheon": [
            "The gods are wise, but do not know of the site which you seek."
        ],
        "Tilda": [
            "Domain has been assigned"
        ],
        "Teamwork": [
            "Oops - We didn't find your site."
        ],
        "Help Juice": [
            "We could not find what you're looking for."
        ],
        "Helpscout": [
            "No settings were found for this company:"
        ],
        "S3 Bucket (Generic)": [
            "NoSuchBucket",
            "The specified bucket does not exist"
        ],
        "Squarespace": [
            "Squarespace - Claim This Domain"
        ],
        "Vercel": [
            "404: THE_DEPLOYMENT_COULD_NOT_BE_FOUND",
            "DEPLOYMENT_NOT_FOUND"
        ],
        "Netlify": [
            "Not Found - Request ID:"
        ]
    }

    def __init__(self, logger, results_callback, request_callback: Callable[[], None]):
        super().__init__(logger, results_callback, request_callback)

    @property
    def name(self):
        return "Subdomain Takeover Tarayıcı (Domain Snatcher)"

    @property
    def category(self):
        return "SUBDOMAIN_TAKEOVER"

    async def scan(self, url: str, session: aiohttp.ClientSession, completed_callback: Callable[[], None]):
        """
        Subdomain Takeover tarama mantığı.
        Keşfedilen tüm subdomain'leri kontrol eder.
        """
        self.log(f"[{self.category}] Subdomain Takeover analizi başlatılıyor...", "INFO")

        # Keşfedilen tüm potansiyel subdomainleri topla
        target_subdomains = set()
        
        # 1. Ana hedefi ekle
        parsed_target = urlparse(url)
        target_subdomains.add(f"{parsed_target.scheme}://{parsed_target.netloc}")

        # 2. Engine'den keşfedilen parametreleri/URL'leri al
        discovered_items = getattr(self, "discovered_params", set())
        for item in discovered_items:
            if item.startswith("http"):
                try:
                    p = urlparse(item)
                    base = f"{p.scheme}://{p.netloc}"
                    target_subdomains.add(base)
                except:
                    pass

        if not target_subdomains:
            self.log(f"[{self.category}] Taranacak subdomain bulunamadı.", "INFO")
            completed_callback()
            return

        self.log(f"[{self.category}] {len(target_subdomains)} adet hedef üzerinde sahipsiz servis kontrolü yapılıyor...", "INFO")

        tasks = []
        # Concurrency limiti
        semaphore = getattr(self, 'module_semaphore', asyncio.Semaphore(10)) 

        for sub_url in target_subdomains:
            tasks.append(self._check_takeover(sub_url, session, semaphore))

        await asyncio.gather(*tasks)

        completed_callback()

    async def _check_takeover(self, target_url: str, session: aiohttp.ClientSession, semaphore: asyncio.Semaphore):
        """
        Tek bir hedef için takeover kontrolü yapar ve POC üretir.
        """
        async with semaphore:
            try:
                # Jitter ve Throttle
                if hasattr(self, '_apply_jitter_and_throttle'):
                    await self._apply_jitter_and_throttle()
                
                self.request_callback()

                # Sadece GET isteği yeterli
                async with session.get(target_url, timeout=aiohttp.ClientTimeout(total=10), allow_redirects=True) as res:
                    content = await res.text()
                    
                    # İmzaları kontrol et
                    for service, signatures in self.TAKEOVER_SIGNATURES.items():
                        for sig in signatures:
                            if sig in content:
                                # KRİTİK BULGU!
                                parsed = urlparse(target_url)
                                domain = parsed.netloc

                                msg = f"KRİTİK: Subdomain Takeover Potansiyeli! Servis: {service}. Hedef: {target_url}"
                                
                                # DNS Doğrulama Komutu Önerisi
                                verification_cmd = f"dig CNAME {domain} +short"

                                self.add_result(
                                    self.category,
                                    "CRITICAL",
                                    msg,
                                    self._calculate_score_deduction("CRITICAL"),
                                    poc_data={
                                        "url": target_url,
                                        "method": "GET",
                                        "attack_vector": f"Subdomain Takeover ({service})",
                                        "data": None,
                                        "headers": {},
                                        # Rapora ek not olarak düşülecek
                                        "description": f"The domain {domain} points to a {service} resource that does not exist. Verify CNAME record: `{verification_cmd}`"
                                    }
                                )
                                self.log(f"[{self.category}] {msg}", "CRITICAL")
                                return # Bir tane bulduysak yeterli

            except Exception:
                pass # Bağlantı hatalarını yoksay