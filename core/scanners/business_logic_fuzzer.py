# path: core/scanners/business_logic_fuzzer.py

import aiohttp
import asyncio
import re
import json
import random
# KRİTİK DÜZELTME: Tüm gerekli tipler ve urllib.parse fonksiyonları tek yerden import edildi.
from typing import Callable, List, Dict, Any, Optional, Union, Set, Tuple # KRİTİK DÜZELTME: Tuple eklendi
from urllib.parse import urlparse, parse_qs, urlencode, urljoin, urlunparse 

from core.scanners.base_scanner import BaseScanner

class BusinessLogicFuzzer(BaseScanner):
    """
    [AR-GE v1.0 - STATEFUL LOGIC BREAKER]
    Uygulamanın iş mantığı (business logic) hatalarını tarar.
    Özellikle OTP, ödeme akışları ve limit kontrollerini hedefler.
    """

    # Mantık hatası içeren işlemleri tetikleyen API yolları (heuristic)
    CRITICAL_PATHS = [
        "/api/reset_password",
        "/api/verify_otp",
        "/api/checkout",
        "/api/place_order",
        "/api/update_limit",
        "/account/settings",
    ]
    
    # Kapsam dışı tutulacak genel yollar
    IGNORE_PATHS = ["/login", "/auth", "/logout"]

    # Ödeme/Limit Manipülasyonu için test edilecek parametreler
    MONEY_PARAMS = ["price", "amount", "total", "limit", "cost"]
    
    # OTP/Sıra tabanlı parametreler
    SEQUENCE_PARAMS = ["otp", "code", "token", "verification_code", "step"]

    @property
    def name(self):
        return "Business Logic Fuzzer"

    @property
    def category(self):
        return "BUSINESS_LOGIC" 

    def __init__(self, logger, results_callback, request_callback: Callable[[], None]):
        super().__init__(logger, results_callback, request_callback)
        # Yanıt boyutunu baseline olarak tut (Race condition simülasyonu için)
        self.baseline_responses: Dict[str, Dict[str, Any]] = {} 

    async def scan(
        self,
        url: str,
        session: aiohttp.ClientSession,
        completed_callback: Callable[[], None],
    ):
        self.log(f"[{self.category}] Stateful İş Mantığı Fuzzing'i başlatılıyor...", "INFO")
        
        # Hata olan satır (Tip tanımı artık doğru)
        discovered_paths: Set[str] = getattr(self, "discovered_params", set())
        
        # Kritik test edilecek URL'leri topla
        target_urls = set()
        
        # 1. Önceden keşfedilen yolları filtrele
        for path in discovered_paths:
            if any(crit_path in path.lower() for crit_path in self.CRITICAL_PATHS):
                target_urls.add(path)
                
        # 2. Ana URL'yi temel path'lerle birleştir (eğer query yoksa)
        for path in self.CRITICAL_PATHS:
            # Hata olan satır (urljoin artık doğru import edildi)
            target_urls.add(urljoin(url, path))

        if not target_urls:
            self.add_result(self.category, "INFO", "INFO: İş mantığı testi için kritik yol bulunamadı.", 0)
            completed_callback()
            return

        semaphore = asyncio.Semaphore(4)
        tasks = []
        
        for target_url in target_urls:
            tasks.append(
                self._run_all_logic_tests(target_url, session, semaphore)
            )

        if tasks:
            await asyncio.gather(*tasks)

        self.add_result(self.category, "SUCCESS", "Stateful İş Mantığı Fuzzing'i tamamlandı.", 0)
        completed_callback()

    async def _fetch_url_and_get_baseline(self, url: str, session: aiohttp.ClientSession) -> Tuple[int, int]:
        """Baseline yanıtı çeker."""
        try:
            if hasattr(self, '_apply_jitter_and_throttle'):
                await self._apply_jitter_and_throttle()
            self.request_callback()
            async with session.head(url, timeout=10, allow_redirects=True) as res:
                content_len = int(res.headers.get("Content-Length", 0))
                return res.status, content_len
        except Exception:
            return 0, 0


    async def _run_all_logic_tests(self, url: str, session: aiohttp.ClientSession, semaphore: asyncio.Semaphore):
        """Bir URL için tüm logic testlerini yürütür."""
        
        # OTP/Code reset testi
        await self._test_sequence_manipulation(url, session, semaphore)
        
        # Ödeme/Limit manipülasyonu testi (sadece query'si varsa anlamlı)
        if urlparse(url).query:
            await self._test_money_limit_manipulation(url, session, semaphore)

    
    async def _test_sequence_manipulation(self, url: str, session: aiohttp.ClientSession, semaphore: asyncio.Semaphore):
        """
        OTP/Code ve sıra numarası manipülasyonunu test eder.
        OTP Rate Limit Bypass / Parçalı (Brute Force) OTP Tahmini.
        """
        
        async with semaphore:
            parsed = urlparse(url)
            base_query = parse_qs(parsed.query)
            
            for param in base_query.keys():
                if param.lower() in self.SEQUENCE_PARAMS:
                    
                    self.log(f"[{self.category}] SEQUENCE TESTİ başlatıldı: Param '{param}'", "INFO")
                    
                    # 1. Test: Basit Brute Force Simülasyonu (OTP Replay)
                    # Orijinal değeri tekrar dene (eğer ilk basamak değilse)
                    original_value = base_query.get(param, ["1234"])[0]
                    
                    for i in range(5): # 5 deneme simüle et
                        try:
                            # Payload: Rastgele 4-6 haneli sayı veya artırma
                            test_value = str(int(original_value) + i + random.randint(10, 50)) 
                            
                            test_query = dict(base_query)
                            test_query[param] = [test_value]
                            
                            new_parts = list(parsed)
                            new_parts[4] = urlencode(test_query, doseq=True)
                            # Hata olan satır (urlunparse artık doğru import edildi)
                            test_url = urlunparse(new_parts)
                            
                            self.request_callback()
                            async with session.get(test_url, timeout=5) as res:
                                text = await res.text()
                                # Başarı sinyalleri: Hata mesajı yok, 200/302 OK, ve sonraki adıma geçiş kelimeleri
                                is_success = res.status in [200, 302] and ("success" in text.lower() or "dashboard" in text.lower())
                                
                                if is_success:
                                    self.add_result(
                                        self.category, "CRITICAL", 
                                        f"KRİTİK: Sequence/OTP Bypass Şüphesi! Param '{param}' rastgele değerle başarılı oldu. Payload: {test_value}",
                                        self._calculate_score_deduction("CRITICAL")
                                    )
                                    return
                        except Exception:
                            continue


    async def _test_money_limit_manipulation(self, url: str, session: aiohttp.ClientSession, semaphore: asyncio.Semaphore):
        """
        Para birimi/Limit parametrelerini (price, amount) manipüle eder.
        """
        
        async with semaphore:
            parsed = urlparse(url)
            base_query = parse_qs(parsed.query)
            
            for param in base_query.keys():
                if param.lower() in self.MONEY_PARAMS:
                    
                    original_value_str = base_query.get(param, ["100"])[0]
                    try:
                        original_value = float(original_value_str)
                    except ValueError:
                        continue
                        
                    # 1. Test: Negatif Değer Enjeksiyonu (iade/limit bypass)
                    await self._send_logic_payload(url, param, -1.0, original_value_str, "Negatif değer", session)
                    
                    # 2. Test: Sıfır Değer Enjeksiyonu (ücretsiz işlem)
                    await self._send_logic_payload(url, param, 0.0, original_value_str, "Sıfır değer", session)


    async def _send_logic_payload(self, url: str, param: str, test_value: Union[float, int], original_value: str, test_type: str, session: aiohttp.ClientSession):
        """Ödeme manipülasyonu için tek bir isteği gönderir ve yanıtı kontrol eder."""
        
        parsed = urlparse(url)
        base_query = parse_qs(parsed.query)
        
        # Payload'ı oluştur
        test_query = dict(base_query)
        test_query[param] = [str(test_value)]
        
        new_parts = list(parsed)
        new_parts[4] = urlencode(test_query, doseq=True)
        # Hata olan satır (urlunparse artık doğru import edildi)
        test_url = urlunparse(new_parts)

        # Baseline: Orijinal değerin yanıt uzunluğunu/status'ünü al
        status_orig, len_orig = await self._fetch_url_and_get_baseline(url, session)

        try:
            self.request_callback()
            async with session.get(test_url, timeout=10) as res:
                
                # Başarılı Smuggling/Logic Error sinyali:
                # 1. Status: 200 (Hata yok)
                # 2. Boyut: Baseline'dan anlamlı derecede farklı (Küçülme)
                # 3. İçerik: Hata mesajı içermiyor (veya 'Success', 'Payment Approved' gibi kelimeler içeriyor)
                
                text = await res.text()
                
                is_successful_status = res.status in [200, 201, 202]
                is_not_error_message = not ("error" in text.lower() or "fail" in text.lower() or "invalid" in text.lower())

                if is_successful_status and is_not_error_message:
                    # Başarıya ulaşan Negatif/Sıfır değer, yüksek risk taşır.
                    
                    # Heuristic kontrol: Yanıt uzunluğu, orijinal yanıta çok benziyorsa
                    len_curr = len(text)
                    length_diff_ratio = abs(len_curr - len_orig) / max(len_orig, 1)

                    if length_diff_ratio < 0.2: # %20'den az fark varsa (yani sayfa yapısı aynı kalmış)
                         # Fiyatı 0 yapan istek başarılı olduysa kritik
                         if test_value <= 0:
                              self.add_result(
                                  self.category, "CRITICAL", 
                                  f"KRİTİK: Fiyat Manipülasyonu (Price/Limit Bypass)! Param '{param}' için '{test_value}' denemesi başarılı oldu (Yanıt Status {res.status}).",
                                  self._calculate_score_deduction("CRITICAL")
                              )
                              return
                    
                    # Eğer çok büyük bir fark varsa (yeni sayfa/içerik) ve hata yoksa şüpheli
                    elif length_diff_ratio > 0.5:
                         self.add_result(
                            self.category, "WARNING", 
                            f"RİSK: İş Mantığı Sapması ({test_type})! Param '{param}' manipülasyonu sonucu yanıt içeriği ciddi değişti (Status {res.status}).",
                            self._calculate_score_deduction("WARNING")
                         )
                         
        except Exception:
            return