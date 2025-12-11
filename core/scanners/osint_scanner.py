# path: core/scanners/osint_scanner.py

import aiohttp
import asyncio
import socket
import json
from typing import Callable, List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse

# BaseScanner'dan türetilecektir.
from core.scanners.base_scanner import BaseScanner

class OSINTScanner(BaseScanner):
    """
    [FAZ 19 - OSINT HUNTER]
    Pasif İstihbarat (OSINT) Toplama Modülü.
    
    Yöntemler:
    - DNS Çözümleme (A, AAAA, MX, NS kayıtları)
    - Whois Simülasyonu (Domain kayıt, e-posta, tarih)
    """

    # Bu tarayıcının maksimum eşzamanlı görev limiti
    PER_MODULE_LIMIT = 5
    
    # Whois sorgusu için kullanılan (simüle edilen) API'ler
    WHOIS_APIS = [
        "https://api.whois.com/v1/{domain}",
        "https://rdap.arin.net/registry/ip/{domain}",
    ]

    def __init__(self, logger, results_callback, request_callback: Callable[[], None]):
        super().__init__(logger, results_callback, request_callback)
        self.module_semaphore = asyncio.Semaphore(self.PER_MODULE_LIMIT)
        # DNS çözünürlüğünün tutulacağı yer
        self.resolved_ips: List[str] = []

    @property
    def name(self):
        return "Pasif İstihbarat (OSINT) Tarayıcı"

    @property
    def category(self):
        return "OSINT"

    async def scan(self, url: str, session: aiohttp.ClientSession, completed_callback: Callable[[], None]):
        """
        OSINT tarama mantığını uygular.
        """
        self.log(f"[{self.category}] OSINT Keşfi başlatılıyor (DNS, Whois)...", "INFO")

        try:
            domain = self._get_hostname(url)
            if not domain:
                self.log(f"[{self.category}] Geçersiz domain, tarama durduruldu.", "WARNING")
                completed_callback()
                return

            # DNS Çözümleme (Blocking I/O olduğu için executor içinde çalışmalı)
            await self._run_dns_lookup(domain)

            # Whois Simülasyonu (API çağrısı)
            await self._run_whois_lookup(domain, session)

            if self.resolved_ips:
                 self.add_result(self.category, "SUCCESS", f"DNS ve IP adresi çözüldü: {', '.join(self.resolved_ips)}", 0.0)
            else:
                 self.add_result(self.category, "INFO", "Temel DNS çözünürlüğü sağlanamadı.", 0.0)

        except Exception as e:
            self.log(f"[{self.category}] Kritik Hata: {type(e).__name__} ({e})", "CRITICAL")
            self.add_result(self.category, "CRITICAL", f"OSINT Tarama Hatası: {str(e)}", 0.0)

        completed_callback()

    def _get_hostname(self, url: str) -> str:
        """URL'den hostname'i ayıklar."""
        try:
            parsed = urlparse(url)
            netloc = parsed.netloc.split(':')[0]
            if netloc.startswith('www.'):
                return netloc[4:]
            return netloc
        except:
            return ""

    async def _run_dns_lookup(self, domain: str):
        """
        Blocking DNS çözümlemesini asyncio executor ile sarmalar.
        """
        loop = asyncio.get_running_loop()
        
        try:
            # socket.gethostbyname blocking'dir, bu yüzden executor kullanıyoruz.
            ip_address = await loop.run_in_executor(None, socket.gethostbyname, domain)
            self.resolved_ips.append(ip_address)
            self.log(f"[{self.category}] DNS A Kaydı Çözüldü: {ip_address}", "SUCCESS")
            
        except socket.gaierror:
            self.log(f"[{self.category}] DNS Çözümleme Hatası: {domain} için A kaydı bulunamadı.", "WARNING")
        except Exception as e:
            self.log(f"[{self.category}] Beklenmedik DNS Hatası: {e}", "WARNING")

    async def _run_whois_lookup(self, domain: str, session: aiohttp.ClientSession):
        """
        Whois API'lerinden pasif bilgi toplama simülasyonu.
        """
        
        tasks = []
        for api_url in self.WHOIS_APIS:
            target_url = api_url.format(domain=domain)
            tasks.append(self._fetch_whois_info(target_url, session))
            
        whois_results: List[Optional[Dict]] = await asyncio.gather(*tasks)

        for result in whois_results:
            if result:
                self.log(f"[{self.category}] Whois/RDAP Bilgisi bulundu (Simülasyon):", "INFO")
                
                # Kritik bilgileri raporla (Simülasyon)
                if result.get("domain"):
                    self.add_result(self.category, "INFO", f"Whois: Alan Adı: {result['domain']}", 0.0)
                
                if result.get("emails"):
                     # Hardcoded e-posta ifşası olarak kabul edelim (yüksek riskli bilgi)
                     msg = f"Whois: Potansiyel Admin E-postası ifşası: {result['emails'][0]}"
                     self.add_result(self.category, "WARNING", msg, 4.0) 
                     self.log(f"[{self.category}] {msg}", "WARNING")
                
                if result.get("nameservers"):
                    self.add_result(self.category, "INFO", f"Whois: Name Server: {result['nameservers'][0]}...", 0.0)
                    
        # Eğer hiç Whois/RDAP sonucu bulunamazsa genel bir bilgi notu
        if not any(whois_results):
            self.log(f"[{self.category}] Whois/RDAP API'lerinden bilgi alınamadı.", "INFO")

    async def _fetch_whois_info(self, url: str, session: aiohttp.ClientSession) -> Optional[Dict[str, Any]]:
        """API'den Whois bilgisini çeker (Simülasyon)."""
        async with self.module_semaphore:
            try:
                self.request_callback()
                
                # Whois API'leri bazen 400/404 dönebilir, sorun değil.
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as res:
                    if res.status == 200:
                        data = await res.json()
                        
                        # Basitçe Whois yanıtını simüle et
                        if 'domain' in data or 'name' in data:
                             return {
                                 "domain": data.get('domain') or data.get('name'),
                                 "emails": data.get('emails', ['admin@example.com']),
                                 "nameservers": data.get('nameservers', ['ns1.dns.com']),
                                 "raw_data": json.dumps(data)[:100] + "..."
                             }
                        
            except Exception:
                pass
            return None