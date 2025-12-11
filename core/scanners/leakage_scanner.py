# path: core/scanners/leakage_scanner.py

import aiohttp
import asyncio
import json
from typing import Callable, List, Dict, Any, Optional
from urllib.parse import urlparse

from core.scanners.base_scanner import BaseScanner
# Hardcoded sırların ve potansiyel e-posta formatlarının simülasyonu için
from core.data_simulator import DataSimulator 

class LeakageScanner(BaseScanner):
    """
    [FAZ 24 - PII HUNTER]
    Kritik Veri Sızıntısı (PII, API Keys, Hardcoded Secrets) Analiz Modülü.
    
    Yöntemler:
    - Dark Web / Pastebin (Simülasyon)
    - Açık Git Repo Taraması (Simülasyon)
    
    Bu modül, keşif aşamasından (OSINT, Subdomain) gelen bilgileri kullanır.
    """

    # Bu tarayıcının maksimum eşzamanlı görev limiti
    PER_MODULE_LIMIT = 3 # Düşük limit, hassas ve yavaş API'ler simüle edilir.

    def __init__(self, logger, results_callback, request_callback: Callable[[], None]):
        super().__init__(logger, results_callback, request_callback)
        self.module_semaphore = asyncio.Semaphore(self.PER_MODULE_LIMIT)
        
        # Keşif modüllerinden enjekte edilecek veriler
        self.target_emails: List[str] = []
        self.target_domains: List[str] = []
        self.target_base_url: str = ""

    @property
    def name(self):
        return "Kritik Veri Sızıntısı Tarayıcı (PII/Secrets)"

    @property
    def category(self):
        return "LEAKAGE"

    async def scan(self, url: str, session: aiohttp.ClientSession, completed_callback: Callable[[], None]):
        """
        Kritik sızıntı tarama mantığını uygular.
        """
        
        # Engine'den enjekte edilen target_base_url'yi al
        self.target_base_url = self._get_hostname(url)
        if not self.target_base_url:
            self.log(f"[{self.category}] Geçersiz domain, tarama durduruldu.", "WARNING")
            completed_callback()
            return
            
        self.log(f"[{self.category}] Kritik sızıntı keşfi başlatılıyor ({len(self.target_emails)} e-posta, {len(self.target_domains)} alan adı)...", "INFO")

        try:
            tasks = []
            
            # 1. API Key ve Secret Key Sızıntısı Kontrolü (Alan Adı Bazlı)
            tasks.append(self._check_git_leakage(self.target_base_url, session))
            
            # 2. PII / Çalışan Kimlik Bilgileri Sızıntısı Kontrolü (E-posta Bazlı)
            for email in self.target_emails:
                tasks.append(self._check_dark_web_leakage(email, session))
                
            # Tarama sonuçlarını bekle
            await asyncio.gather(*tasks)

        except Exception as e:
            self.log(f"[{self.category}] Kritik Hata: {type(e).__name__} ({e})", "CRITICAL")
            self.add_result(self.category, "CRITICAL", f"Sızıntı Tarama Motoru Hatası: {str(e)}", 0.0)

        completed_callback()

    def _get_hostname(self, url: str) -> str:
        """URL'den hostname'i ayıklar."""
        try:
            parsed = urlparse(url)
            netloc = parsed.netloc.split(':')[0]
            if netloc.startswith('www.'):
                netloc = netloc[4:]
            return netloc
        except:
            return ""

    async def _fetch_simulated_leak(self, url: str, session: aiohttp.ClientSession) -> Optional[Dict[str, Any]]:
        """Sızıntı API'sinden (Simülasyon) veri çeker."""
        # API çağrısını simüle et
        async with self.module_semaphore:
            self.request_callback()
            try:
                # 3 saniye rastgele gecikme ekleyerek yavaş ve stealth API simülasyonu yapılır
                await asyncio.sleep(self.engine_instance.throttle_delay_ms / 1000 + 1.0)
                
                # Simülasyon: DataSimulator'dan sızıntı verisini çek
                leak_data = DataSimulator.simulate_leakage_api(url)
                
                if leak_data:
                    return leak_data
                
            except Exception:
                pass
            return None


    async def _check_git_leakage(self, domain: str, session: aiohttp.ClientSession):
        """
        Açık Git repolarında hardcoded sırları simüle eder.
        """
        self.log(f"[{self.category}] Açık Git/API Anahtarı sızıntısı kontrol ediliyor...", "INFO")
        
        # Simüle edilmiş bir API çağrısı
        leak_info = await self._fetch_simulated_leak(f"https://api.gitfind.com/search?domain={domain}&type=secret", session)
        
        if leak_info and leak_info.get("type") == "SECRET_KEY":
            secret = leak_info["data"]
            self.log(f"[{self.category}] KRİTİK IFŞA: Açık Git reposunda Hardcoded Secret Key bulundu! Kaynak: {leak_info['source']}", "CRITICAL")
            self.add_result(
                self.category, 
                "CRITICAL", 
                f"Hardcoded API/Secret Key ifşası. Kaynak: Git/Cloud. İlk 10 karakter: {secret[:10]}...", 
                25.0, # KRİTİK SRP PUANI
                poc_data={"secret_type": "API_KEY", "value": secret, "source": leak_info['source']}
            )
        else:
             self.log(f"[{self.category}] Açık Git repolarında kritik sır bulunamadı.", "INFO")

    async def _check_dark_web_leakage(self, email: str, session: aiohttp.ClientSession):
        """
        E-posta bazlı PII sızıntılarını ve şifre ifşasını simüle eder.
        """
        self.log(f"[{self.category}] Dark Web/PII sızıntısı kontrol ediliyor (E-posta: {email})...", "INFO")
        
        # Simüle edilmiş bir API çağrısı
        leak_info = await self._fetch_simulated_leak(f"https://api.darkscan.io/query?email={email}", session)

        if leak_info and leak_info.get("type") == "PII_CREDENTIALS":
            password_hash = leak_info["data"]
            self.log(f"[{self.category}] KRİTİK IFŞA: Çalışan Kimlik Bilgisi sızıntısı bulundu! E-posta: {email} | Kaynak: {leak_info['source']}", "CRITICAL")
            self.add_result(
                self.category, 
                "CRITICAL", 
                f"Çalışan e-posta ve şifre (hash/plaintext) ifşası. E-posta: {email}. Password Hash: {password_hash[:20]}...", 
                25.0, # KRİTİK SRP PUANI
                poc_data={"email": email, "password_hash": password_hash, "source": leak_info['source']}
            )
        else:
            self.log(f"[{self.category}] E-posta ({email}) için kritik PII sızıntısı bulunamadı.", "INFO")