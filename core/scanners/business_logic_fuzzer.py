# path: core/scanners/business_logic_fuzzer.py

import aiohttp
import asyncio
import json
from time import time
from typing import Callable, List, Dict, Any, Optional, Union, Set, Tuple 
from urllib.parse import urlparse, parse_qs, urlencode, urljoin, urlunparse 
import random 

from core.scanners.base_scanner import BaseScanner
from core.data_simulator import DataSimulator 
from core.payload_generator import PayloadGenerator # FAZ 34: Payload Generator import edildi

class BusinessLogicFuzzer(BaseScanner):
    """
    [FAZ 33/34 - BUSINESS LOGIC FUZZER]
    Uygulamanın iş mantığı akışındaki (örnek: ödeme, sepet, kupon kullanımı)
    kritik zafiyetleri (Yarış Koşulu, Fiyat Manipülasyonu, Yetki Atlaması) bulmaya odaklanır.
    """

    PER_MODULE_LIMIT = 5
    
    # --- KRİTİK İŞ MANTIĞI VEKTÖRLERİ (Simülasyon) ---
    LOGIC_VECTORS = {
        "PRICE_MANIPULATION": {
            "ENDPOINT": "/api/v1/cart/update",
            "METHOD": "POST",
            "BODY": {"item_id": 1234, "quantity": 1, "price": -1}, # Negatif fiyat enjeksiyonu
            "ANOMALY_CHECK": 200, 
            "RISK": "HIGH",
            "DESC": "Negatif fiyat/miktar enjeksiyonu ile bakiye manipülasyonu denemesi."
        },
        "RACE_CONDITION_SIMPLE": {
            "ENDPOINT": "/api/v1/coupons/apply",
            "METHOD": "POST",
            "BODY": {"coupon_code": "DISC_SINGLE_USE_100", "user_id": "CURRENT_USER"},
            "ANOMALY_CHECK": 200, 
            "RISK": "CRITICAL",
            "DESC": "Tek kullanımlık kuponun birden fazla istek ile aynı anda kullanımı (Race Condition) denemesi."
        },
        "IDOR_IN_LOGIC": {
            "ENDPOINT": "/api/v1/orders/view",
            "METHOD": "GET",
            "PARAMS": {"order_id": "999999", "user_id": "OTHER_USER_ID"}, # Başka bir kullanıcı ID'si
            "ANOMALY_CHECK": 200, 
            "RISK": "HIGH",
            "DESC": "Yetkilendirme olmadan başka bir kullanıcıya ait ID'ye erişim denemesi (IDOR)."
        }
    }
    # ------------------------------------------------

    def __init__(self, logger, results_callback, request_callback: Callable[[], None]):
        super().__init__(logger, results_callback, request_callback) 
        self.module_semaphore = asyncio.Semaphore(self.PER_MODULE_LIMIT)
        self.host_url: str = ""
        self.baseline_responses: Dict[str, Dict[str, Any]] = {} 
        self.CRITICAL_PATHS = [
            "/api/reset_password", "/api/verify_otp", "/api/checkout",
            "/api/place_order", "/api/update_limit", "/account/settings",
        ]
        self.SEQUENCE_PARAMS = ["otp", "code", "token", "verification_code", "step"]
        self.MONEY_PARAMS = ["price", "amount", "total", "limit", "cost"]
        
        # FAZ 34: Engine'den enjekte edilen Payload Generator'ı tut
        self.payload_generator: Optional[PayloadGenerator] = None 


    @property
    def name(self):
        return "Business Logic Fuzzer"

    @property
    def category(self):
        return "BUSINESS_LOGIC" 

    async def scan(
        self,
        url: str,
        session: aiohttp.ClientSession,
        completed_callback: Callable[[], None],
    ):
        self.log(f"[{self.category}] Stateful İş Mantığı Fuzzing'i başlatılıyor...", "INFO")
        
        discovered_paths: Set[str] = getattr(self, "discovered_params", set())
        
        target_urls = set()
        
        for path in discovered_paths:
            if any(crit_path in path.lower() for crit_path in self.CRITICAL_PATHS):
                target_urls.add(path)
                
        for path in self.CRITICAL_PATHS:
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
                    
                    original_value = base_query.get(param, ["1234"])[0]
                    
                    try:
                        original_int = int(original_value)
                    except ValueError:
                        self.log(f"[{self.category}] Sequence/OTP Parametresi '{param}' sayısal değil, atlanıyor.", "INFO")
                        continue

                    # 1. Test: Basit Brute Force Simülasyonu (OTP Replay)
                    for i in range(5): 
                        try:
                            # KRİTİK DÜZELTME: Sadece sayısal değerlerle işlem yapılıyor.
                            test_value = str(original_int + i + random.randint(10, 50)) 
                            
                            test_query = dict(base_query)
                            test_query[param] = [test_value]
                            
                            new_parts = list(parsed)
                            new_parts[4] = urlencode(test_query, doseq=True)
                            test_url = urlunparse(new_parts)
                            
                            self.request_callback()
                            async with session.get(test_url, timeout=5) as res:
                                text = await res.text()
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
        Para birimi/Limit parametrelerini (price, amount) manipüle eder ve AI'dan destek alır.
        """
        
        async with semaphore:
            parsed = urlparse(url)
            base_query = parse_qs(parsed.query)
            
            # FAZ 34 KRİTİK: AI'dan Business Logic için özel payload'lar iste
            ai_payloads = []
            if self.payload_generator and self.payload_generator.neural_engine.is_active:
                context = {
                    "url": url,
                    "params": list(base_query.keys()),
                    "target": "Price Manipulation / Limit Bypass"
                }
                # AI'dan Business Logic için AI-Driven payload'lar iste
                ai_payloads_list = await self.payload_generator.neural_engine.generate_ai_payloads(context, "LOGIC_FUZZ")
                
                # AI'dan gelen payload'ları sadece MONEY_PARAMS üzerinde test et
                for ai_value in ai_payloads_list:
                    # AI'dan gelen değeri float'a çevirip test etmek için ekle
                    try:
                        ai_payloads.append(float(ai_value))
                    except ValueError:
                        # Eğer AI string bazlı (kupon kodu gibi) bir şey döndürdüyse, onu da işlemek gerekebilir.
                        # Şimdilik sadece sayısal manipülasyonlara odaklanalım.
                        pass
            
            
            for param in base_query.keys():
                if param.lower() in self.MONEY_PARAMS:
                    
                    original_value_str = base_query.get(param, ["100"])[0]
                    try:
                        original_value = float(original_value_str)
                    except ValueError:
                        self.log(f"[{self.category}] Money Parametresi '{param}' sayısal değil, atlanıyor.", "INFO")
                        continue
                        
                    # 1. Test: Negatif Değer Enjeksiyonu (iade/limit bypass)
                    await self._send_logic_payload(url, param, -1.0, original_value_str, "Negatif değer", session)
                    
                    # 2. Test: Sıfır Değer Enjeksiyonu (ücretsiz işlem)
                    await self._send_logic_payload(url, param, 0.0, original_value_str, "Sıfır değer", session)

                    # 3. Test: AI Tarafından Üretilen Değerler
                    for ai_test_value in ai_payloads:
                        # Eğer AI payload'ı sayısal ise test et
                        await self._send_logic_payload(url, param, ai_test_value, original_value_str, f"AI-Driven ({ai_test_value})", session)


    async def _send_logic_payload(self, url: str, param: str, test_value: Union[float, int], original_value: str, test_type: str, session: aiohttp.ClientSession):
        """Ödeme manipülasyonu için tek bir isteği gönderir ve yanıtı kontrol eder."""
        
        parsed = urlparse(url)
        base_query = parse_qs(parsed.query)
        
        # Payload'ı oluştur
        test_query = dict(base_query)
        test_query[param] = [str(test_value)]
        
        new_parts = list(parsed)
        new_parts[4] = urlencode(test_query, doseq=True)
        test_url = urlunparse(new_parts)

        # Baseline: Orijinal değerin yanıt uzunluğunu/status'ünü al
        status_orig, len_orig = await self._fetch_url_and_get_baseline(url, session)

        try:
            self.request_callback()
            async with session.get(test_url, timeout=10) as res:
                
                text = await res.text()
                
                is_successful_status = res.status in [200, 201, 202]
                is_not_error_message = not ("error" in text.lower() or "fail" in text.lower() or "invalid" in text.lower())

                if is_successful_status and is_not_error_message:
                    
                    len_curr = len(text)
                    length_diff_ratio = abs(len_curr - len_orig) / max(len_orig, 1)

                    if test_value <= 0 and is_successful_status: # Negatif/Sıfır değer başarılı oldu
                         self.add_result(
                             self.category, "CRITICAL", 
                             f"KRİTİK: Fiyat Manipülasyonu (Price/Limit Bypass)! Param '{param}' için '{test_value}' denemesi başarılı oldu (Yanıt Status {res.status}, Vektör: {test_type}).",
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
                         return
                            
        except Exception:
            return