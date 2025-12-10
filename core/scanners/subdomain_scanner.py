# path: core/scanners/subdomain_scanner.py

import aiohttp
import asyncio
import json
import re
from typing import Callable, Set, List, Optional, Tuple # KRİTİK DÜZELTME: Tuple, Optional eklendi
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse # KRİTİK DÜZELTME: Tüm urllib.parse fonksiyonları eklendi

from core.scanners.base_scanner import BaseScanner


class DiscoveryOrchestrator(BaseScanner):
    """
    [AR-GE v3.0 - DEEP HARVEST]
    Subdomain, Wayback Machine ve Pasif Kaynaklardan kritik saldırı yüzeylerini (yollar, parametreler, sublar) keşfeder.
    Bulguları doğrudan ana fuzzing motoruna (Engine) besler.
    """

    CRT_SH_URL = "https://crt.sh/?q=%.{}&output=json"
    
    # YENİ: Wayback Machine CDX API'si (10000 kayıt sınırı ile gürültüyü engelle)
    WAYBACK_CDX_URL = "http://web.archive.org/cdx/search/cdx?url=*.{}/*&output=json&limit=10000"
    
    # Retry Ayarları
    MAX_RETRIES = 3
    RETRY_DELAY = 2 # saniye (her denemede artar)

    @property
    def name(self):
        return "Discovery Orchestrator (Deep Harvest)"

    @property
    def category(self):
        # Category adı aynı kalmalı, çünkü Engine o isimle arıyor
        return "SUBDOMAIN" 

    def __init__(self, logger, results_callback, request_callback: Callable[[], None]):
        super().__init__(logger, results_callback, request_callback)

    async def scan(self, url: str, session: aiohttp.ClientSession, completed_callback: Callable[[], None]):
        """
        Deep Harvest tarama mantığını uygular (Subdomain + Wayback).
        """
        try:
            domain = self._get_domain(url)
            if not domain:
                self.log(f"[{self.category}] Geçersiz domain, tarama durduruldu.", "WARNING")
                completed_callback()
                return

            self.log(
                f"[{self.category}] {domain} için Deep Harvest başlatılıyor (Subdomain + Wayback)...",
                "INFO",
            )
            
            discovered_subdomains = set()
            discovered_paths = set()
            
            # --- 1. KAYNAK: crt.sh (Sertifika Şeffaflığı) ---
            subdomains_from_crt = await self._query_crt_sh_with_retry(domain, session)
            discovered_subdomains.update(subdomains_from_crt)

            # --- 2. KAYNAK: Fallback (Eğer crt.sh başarısız olursa) ---
            if not subdomains_from_crt:
                self.log(f"[{self.category}] crt.sh yanıt vermedi. Yedek subdomain kaynağa geçiliyor.", "WARNING")
                subdomains_from_fallback = await self._query_alternative_source(domain, session)
                discovered_subdomains.update(subdomains_from_fallback)
            
            # Ana domaini de test listesine ekle
            discovered_subdomains.add(domain)

            # --- 3. KAYNAK: Wayback Machine (Tarihsel Endpoint Avı) ---
            self.log(f"[{self.category}] Wayback Machine'den tarihsel URL'ler toplanıyor...", "INFO")
            
            # Asıl domain ve bulunan sublar için Wayback'i sorgula
            wayback_tasks = [
                self._query_wayback_machine(sub, session) for sub in list(discovered_subdomains)[:5] # Sadece ilk 5 sub/domain için sorgula (hız optimizasyonu)
            ]
            wayback_results: List[Set[str]] = await asyncio.gather(*wayback_tasks)
            
            for result_set in wayback_results:
                for full_url in result_set:
                    # Endpoint ve parametreleri ayır
                    self._extract_path_and_params_from_url(full_url, discovered_paths)

            # --- 4. SONUÇ RAPORLAMA VE BESLEME ---
            
            # Subdomain Raporu
            if discovered_subdomains:
                sub_list = [s for s in discovered_subdomains if s != domain] # Ana domain hariç
                count = len(sub_list)
                examples = ", ".join(list(sub_list)[:5])
                msg = f"Başarılı: {count} adet alt alan adı tespit edildi. Örn: {examples}"
                self.add_result(self.category, "INFO", msg, 0)
                self.log(
                    f"[{self.category}] Tespit edilen alt alan adları: {', '.join(sub_list)}",
                    "SUCCESS",
                )
            
            # Endpoint Raporu
            if discovered_paths:
                self.log(f"[{self.category}] {len(discovered_paths)} adet yeni URL/Endpoint keşfedildi.", "SUCCESS")
                
                # Kritik: Engine'e besle
                for path in discovered_paths:
                     self.engine_instance.add_discovered_param(path) # Bu metot hem path hem de query param ekler

                self.add_result(
                    "PRE_SCAN", # Pre-Scan kategorisi altında raporla
                    "INFO", 
                    f"Wayback/Pasif Kaynaklardan {len(discovered_paths)} adet yeni URL/yol haritası fuzzing kuyruğuna beslendi.",
                    0
                )
            else:
                 self.log(f"[{self.category}] Wayback Machine'den yeni endpoint bulunamadı.", "INFO")


        except Exception as e:
            self.log(f"[{self.category}] Kritik Tarama Hatası: {type(e).__name__} ({e})", "CRITICAL")

        completed_callback()

    def _extract_path_and_params_from_url(self, full_url: str, path_set: Set[str]):
        """
        Verilen URL'den temiz yolu ve tüm query parametre adlarını çıkarır.
        """
        try:
            parsed = urlparse(full_url)
            
            # 1. Temiz yolu kaydet (Fuzzing için)
            if parsed.path and parsed.path not in ["/", ""]:
                path_set.add(parsed.path)
            
            # 2. Query parametre adlarını kaydet (Pre-Scan'e beslemek için)
            query_params = parse_qs(parsed.query)
            for param_name in query_params.keys():
                # Engine'in Pre-Scan'e beslemesi için:
                # Parametre adlarını da ekleyelim ki, engine bunları LFI/SSRF ile test edebilsin.
                self.engine_instance.add_discovered_param(param_name) 

        except Exception:
            pass


    def _get_domain(self, url: str) -> str:
        """URL'den ana domaini ayıklar."""
        try:
            parsed = urlparse(url)
            netloc = parsed.netloc.split(":")[0]
            parts = netloc.split(".")

            if len(parts) >= 2:
                # Eğer www ile başlıyorsa temizle
                if parts[0] == 'www':
                    return ".".join(parts[1:])
                return netloc

            return netloc
        except:
            return ""

    async def _query_crt_sh_with_retry(self, domain: str, session: aiohttp.ClientSession) -> Set[str]:
        """
        crt.sh kaynağını retry mekanizması ile sorgular.
        """
        target_url = self.CRT_SH_URL.format(domain)
        subdomains = set()

        for attempt in range(1, self.MAX_RETRIES + 1):
            try:
                if hasattr(self, '_apply_jitter_and_throttle'):
                    await self._apply_jitter_and_throttle()
                self.request_callback()
                
                # Timeout süresini her denemede artır (15s -> 25s -> 40s)
                current_timeout = 15 + (attempt * 10)
                
                async with session.get(
                    target_url,
                    timeout=aiohttp.ClientTimeout(total=current_timeout),
                    ssl=False
                ) as response:

                    if response.status != 200:
                        self.log(f"[{self.category}] crt.sh hatası ({response.status}). Deneme {attempt}/{self.MAX_RETRIES}", "WARNING")
                        await asyncio.sleep(self.RETRY_DELAY * attempt)
                        continue

                    text_data = await response.text()

                    # JSON Parse Denemesi
                    try:
                        data = json.loads(text_data)
                    except Exception:
                        self.log(f"[{self.category}] crt.sh geçersiz yanıt döndü. Deneme {attempt}/{self.MAX_RETRIES}", "WARNING")
                        await asyncio.sleep(self.RETRY_DELAY * attempt)
                        continue

                    # Veriyi işle
                    for entry in data:
                        name_value = entry.get("name_value", "")
                        for sub in name_value.split("\n"):
                            sub = sub.strip().lower()
                            if not sub or "*" in sub: continue
                            if sub.endswith(domain) and sub != domain:
                                subdomains.add(sub)
                    
                    if subdomains:
                        return subdomains
                    else:
                        return subdomains

            except (asyncio.TimeoutError, aiohttp.ClientError) as e:
                self.log(f"[{self.category}] crt.sh Bağlantı Sorunu ({type(e).__name__}). Deneme {attempt}/{self.MAX_RETRIES}", "WARNING")
                await asyncio.sleep(self.RETRY_DELAY * attempt)
            except Exception as e:
                self.log(f"[{self.category}] Beklenmedik Hata: {e}", "WARNING")
                break 

        return subdomains

    async def _query_alternative_source(self, domain: str, session: aiohttp.ClientSession) -> Set[str]:
        """
        Yedek (Fallback) Kaynak: Yaygın Subdomain Taraması.
        """
        subdomains = set()
        
        common_prefixes = ["www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", "test", "dev", "shop", "api", "vpn", "secure", "status", "support", "beta", "cdn", "portal"]
        
        self.log(f"[{self.category}] Yedek Strateji: Yaygın alt alan adları taranıyor ({len(common_prefixes)} adet)...", "INFO")
        
        sem = asyncio.Semaphore(5)
        
        async def check_sub(prefix):
            target = f"http://{prefix}.{domain}"
            async with sem:
                try:
                    if hasattr(self, '_apply_jitter_and_throttle'):
                        await self._apply_jitter_and_throttle()
                    self.request_callback()
                    # HEAD isteğiyle DNS çözülmesini ve HTTP yanıtını kontrol et
                    # KRİTİK: self.TIMEOUT yerine sabit 5s kullandık
                    async with session.head(target, timeout=aiohttp.ClientTimeout(total=5), allow_redirects=False) as res: 
                        return f"{prefix}.{domain}"
                except:
                    return None

        tasks = [check_sub(p) for p in common_prefixes]
        results = await asyncio.gather(*tasks)
        
        for res in results:
            if res:
                subdomains.add(res)
                
        return subdomains

    async def _query_wayback_machine(self, domain: str, session: aiohttp.ClientSession) -> Set[str]:
        """
        [KRİTİK DÜZELTME] Wayback Machine'den bilinen URL'leri çeker.
        CDX formatı (liste listesi) için daha kararlı parse mantığı kullanıldı.
        """
        target_url = self.WAYBACK_CDX_URL.format(domain)
        urls = set()
        
        try:
            self.request_callback()
            async with session.get(target_url, timeout=aiohttp.ClientTimeout(total=30)) as response:
                if response.status != 200:
                    self.log(f"[{self.category}] Wayback CDX sorgusu başarısız oldu ({response.status}).", "WARNING")
                    return urls
                    
                data = await response.text()
                
                # CDX formatı genellikle ilk satırda başlıkları içerir.
                lines = data.strip().splitlines()
                if not lines:
                    return urls
                
                # İlk satırı atla (Başlık satırı)
                raw_entries = []
                
                for line in lines[1:]:
                    try:
                        # Her satır bir JSON listesi olmalı
                        entry = json.loads(line)
                        if isinstance(entry, list):
                            raw_entries.append(entry)
                    except json.JSONDecodeError:
                        continue

                # Veriyi işle
                for entry in raw_entries:
                    # CDX formatında URL, listenin 2. index'inde (0 tabanlı) bulunur.
                    if len(entry) > 2:
                        original_url = entry[2]
                        urls.add(original_url)

        except Exception as e:
            self.log(f"[{self.category}] Wayback Sorgu Hatası: {type(e).__name__}", "WARNING")

        return urls