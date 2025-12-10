# path: core/proxy_manager.py

import aiohttp
import asyncio
import random
import time
from typing import List, Set, Optional

class ProxyManager:
    """
    PARS LIVE PROXY ENGINE (V21.3 - Bypass Mode Added)
    
    V21.3 Değişiklikleri:
    - 'enabled' bayrağı eklendi. False ise proxy kullanımı tamamen kapatılır (Direct Mode).
    """
    
    def __init__(self, logger_callback, enabled: bool = True):
        self.log = logger_callback
        self.enabled = enabled  # YENİ: Aktif/Pasif kontrolü
        self.proxies: List[str] = []
        self.bad_proxies: Set[str] = set()
        self.is_running = False
        self.last_update = 0
        
        self.sources = [
            "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
            "https://www.proxy-list.download/api/v1/get?type=http"
        ]

    async def start_updater(self):
        """Arka plan güncelleme döngüsünü başlatır."""
        if not self.enabled:
            self.log("[PROXY_ENGINE] Proxy Motoru DEVRE DIŞI (Direct Mode). Doğrudan bağlantı kullanılacak.", "WARNING")
            return

        self.is_running = True
        self.log("[PROXY_ENGINE] Canlı Proxy Motoru başlatıldı. Kaynaklar taranıyor...", "INFO")
        
        while self.is_running:
            if len(self.proxies) < 10 or (time.time() - self.last_update > 300):
                await self.fetch_and_validate()
            await asyncio.sleep(60)

    def stop_updater(self):
        self.is_running = False
        if self.enabled:
            self.log("[PROXY_ENGINE] Motor durduruluyor...", "INFO")

    async def fetch_and_validate(self):
        if not self.enabled: return

        self.log("[PROXY_ENGINE] Yeni vekil sunucular toplanıyor...", "INFO")
        raw_proxies = set()
        
        timeout = aiohttp.ClientTimeout(total=20)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            for source in self.sources:
                try:
                    async with session.get(source) as resp:
                        if resp.status == 200:
                            text = await resp.text()
                            for line in text.splitlines():
                                line = line.strip()
                                if line and ":" in line and line not in self.bad_proxies:
                                    if "://" not in line:
                                        raw_proxies.add("http://" + line)
                                    else:
                                        raw_proxies.add(line)
                except Exception as e:
                    pass # Sessiz hata
        
        if not raw_proxies:
            self.log("[PROXY_ENGINE] Kaynaklardan proxy alınamadı.", "WARNING")
            return

        candidates = list(raw_proxies)
        random.shuffle(candidates)
        TEST_LIMIT = 500
        candidates = candidates[:TEST_LIMIT]
        
        self.log(f"[PROXY_ENGINE] {len(raw_proxies)} aday arasından {TEST_LIMIT} tanesi test ediliyor...", "INFO")
        
        valid_proxies = []
        sem = asyncio.Semaphore(50)
        
        async def bounded_check(p):
            async with sem:
                return await self._check_proxy(session, p)

        tasks = [bounded_check(p) for p in candidates]
        results = await asyncio.gather(*tasks)
        
        for proxy in results:
            if proxy:
                valid_proxies.append(proxy)
        
        current_set = set(self.proxies)
        for p in valid_proxies:
            current_set.add(p)
        
        self.proxies = list(current_set)
        self.last_update = time.time()
        
        new_count = len(self.proxies)
        if new_count > 0:
            self.log(f"[PROXY_ENGINE] Havuz güncellendi! Toplam Aktif: {new_count}", "SUCCESS")
        else:
            self.log("[PROXY_ENGINE] Uyarı: Hiçbir proxy doğrulanamadı.", "WARNING")

    async def _check_proxy(self, session, proxy):
        try:
            # Bing testi
            target = "https://www.bing.com" 
            async with session.get(target, proxy=proxy, timeout=10, allow_redirects=True) as resp:
                if resp.status == 200:
                    return proxy
        except:
            pass
        return None

    def get_proxy(self) -> Optional[str]:
        """Havuzdan rastgele bir proxy döndürür. Bypass modundaysa None döner."""
        if not self.enabled:
            return None
            
        if not self.proxies:
            return None
        return random.choice(self.proxies)

    def report_bad_proxy(self, proxy):
        if not self.enabled: return
        if not proxy: return
        
        if proxy in self.proxies:
            self.proxies.remove(proxy)
        self.bad_proxies.add(proxy)