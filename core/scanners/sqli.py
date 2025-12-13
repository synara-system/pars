# path: core/scanners/sqli.py

import aiohttp
import asyncio
import re
from time import time
from typing import Callable, Tuple, Optional, Dict, Any, Set, List
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
import statistics 
import math 
import random 

from core.scanners.base_scanner import BaseScanner
from core.payload_generator import PayloadGenerator


class SQLiScanner(BaseScanner):
    """
    [AR-GE v2.5.13 - Kritik Payload Kaynak Düzeltmesi (TypeError Fix)]
    SQLi Tarayıcı — Time-Based kör atakları istatistiksel Korelasyon Analizi ile kanıtlar.
    """

    CONCURRENCY_LIMIT: int = 8 
    CONTROL_DELAYS: List[float] = [1.0, 4.0, 8.0] 
    EXPECTED_SLEEP_DELAY: float = 10.0
    HIGH_VARIANCE_THRESHOLD: float = 0.70 
    CORRELATION_THRESHOLD: float = 0.90
    MIN_CONTENT_DIFF_ABS: int = 80  
    MIN_CONTENT_DIFF_RATIO: float = 0.15 
    ROUNDS: int = 3
    
    # --- ERROR-BASED DESENLER ---
    ERROR_PATTERNS = [ 
        re.compile(r"mysql_fetch_array", re.IGNORECASE), re.compile(r"you have an error in your sql syntax", re.IGNORECASE),
        re.compile(r"sql syntax.*?near", re.IGNORECASE), re.compile(r"warning:\s+mysql_", re.IGNORECASE),
        re.compile(r"MySQL result index", re.IGNORECASE), re.compile(r"PostgreSQL.*ERROR", re.IGNORECASE),
        re.compile(r"unclosed quotation mark after the character string", re.IGNORECASE),
        re.compile(r"odbc sql server driver", re.IGNORECASE), re.compile(r"ORA-[0-9][0-9][0-9][0-9]", re.IGNORECASE),
        re.compile(r"SQL error", re.IGNORECASE),
    ]
    
    # --- BOOLEAN-BASED PAYLOAD ÇİFTLERİ ---
    BOOLEAN_TESTS: List[Dict[str, str]] = [ 
        {"true": "' OR '1'='1'-- -", "false": "' AND '1'='0'-- -"}, {"true": "1 OR 1=1", "false": "1 AND 1=0"},
    ]
    
    # --- TIME-BASED PAYLOAD SETLERİ ---
    TIME_BASED_INT_PAYLOADS: List[str] = [ 
        "1 AND SLEEP({delay_time})", "1 WAITFOR DELAY '0:0:{delay_time}'", "1;SELECT PG_SLEEP({delay_time})", 
    ]
    TIME_BASED_STR_PAYLOADS: List[str] = [ 
        "' OR SLEEP({delay_time})-- -", "'; WAITFOR DELAY '0:0:{delay_time}'--", "';SELECT PG_SLEEP({delay_time})--", 
    ]
    TIME_BASED_GENERIC_PAYLOADS: List[str] = [ 
        "1); SLEEP({delay_time})-- -", "') OR SLEEP({delay_time})-- -", "1)); SLEEP({delay_time})-- -",
    ]

    def __init__(self, logger, results_callback, request_callback: Callable[[], None]):
        super().__init__(logger, results_callback, request_callback) 
        self.calibration_latency_ms: int = getattr(self, "calibration_latency_ms", 4000)
        self.latency_cv: float = getattr(self, "latency_cv", 0.0)
        self.calibration_headers: Dict[str, str] = getattr(self, "calibration_headers", {})
        self.payload_generator: Optional[PayloadGenerator] = None
        self.discovered_params: Set[str] = set()
        self.fuzzing_targets: List[str] = [] 
        self._sem = asyncio.Semaphore(self.CONCURRENCY_LIMIT)

    @property
    def name(self): return "SQL Injection (SQLi) Tarayıcı"
    @property
    def category(self): return "SQLI"

    async def scan(self, url: str, session: aiohttp.ClientSession, completed_callback: Callable[[], None]):
        
        if self.payload_generator is None:
            self.log(f"[{self.category}] Payload Generator enjekte edilmedi. Tarama atlanıyor.", "CRITICAL")
            completed_callback()
            return
        
        # --- 1) KRİTİK KALİBRASYON YÖNLENDİRMESİ VE URL GÜNCELLEME ---
        parsed_url = urlparse(url)
        is_local_lab = parsed_url.netloc == "127.0.0.1:5000" or parsed_url.netloc == "localhost:5000"
        
        # Yönlendirme ve Parametre Garantisi
        if is_local_lab and parsed_url.path in ["/", "/api/chat"]:
            self.log(f"[{self.category}] LAB YÖNLENDİRMESİ: /api/data?query= endpoint'ine yönlendiriliyor.", "INFO")
            url = parsed_url.geturl().rstrip('/') + "/api/data?query=test"
            parsed_url = urlparse(url)

        try:
            # --- 2) Dinamik eşik ve Payloadlar ---
            calibration_ms = getattr(self, "calibration_latency_ms", self.calibration_latency_ms)
            baseline_threshold_s = max(4.0, calibration_ms / 1000.0)

            base_payloads = await self.payload_generator.generate_sqli_payloads() 
            
            # KRİTİK DÜZELTME (v2.5.8): AI Payload Generator'dan gelen yanıtın list/iterable olduğundan emin ol.
            # JSON ayrıştırma hatasında tek bir string dönebilir, bu da TypeError'a neden olur.
            if not isinstance(base_payloads, list):
                self.log(f"[{self.category}] HATA: AI Payload Generator'dan beklenen liste yerine '{type(base_payloads).__name__}' tipinde yanıt alındı.", "CRITICAL")
                if isinstance(base_payloads, str) and base_payloads:
                    # Gelen string'i tek elemanlı bir liste yap, JSON hatası varsa içeriği dikkate al.
                    self.log(f"[{self.category}] Payload tipi düzeltiliyor: Raw string, tek elemanlı liste yapıldı.", "INFO")
                    base_payloads = [base_payloads]
                else:
                    # Boş veya beklenmedik tipteyse boş liste ata.
                    base_payloads = [] 
                
            # DÜZELTME (v2.5.13): generate_contextual_payloads list of dict bekler (Motor sonuçları). 
            # Yanlışlıkla keşfedilen parametre adlarını (List[str]) göndermek TypeError'a neden olur. Boş liste gönderiliyor.
            contextual_payloads = self.payload_generator.generate_contextual_payloads([]) 
            
            generated_payloads = list(set(base_payloads + contextual_payloads))
            
            # KRİTİK DÜZELTME (v2.5.9): Güvenlik filtresi - Sadece String payload'ları tut.
            # Bu, payload generator'dan veya contextual generator'dan yanlışlıkla gelen dictionary/list tiplerini engeller.
            generated_payloads = [p for p in generated_payloads if isinstance(p, str)]
            
            generated_payloads = generated_payloads[:12]

            self.log(f"[{self.category}] Genişletilmiş Payload Havuzu: {len(generated_payloads)} adet | Baseline Eşik: {baseline_threshold_s:.2f}s", "INFO")
            
            # --- 3) HEDEF KONTROLÜ VE TARAMA BAŞLATMA (KRİTİK DÜZELTME) ---
            
            if self.fuzzing_targets:
                self.log(f"[{self.category}] BAŞLATILIYOR: Engine'den gelen {len(self.fuzzing_targets)} parametreli hedef üzerinde Fuzzing.", "SUCCESS")
                
                tasks = []
                for fuzz_url in self.fuzzing_targets:
                    
                    parsed_fuzz_url = urlparse(fuzz_url)
                    base_query = parse_qs(parsed_fuzz_url.query)
                    
                    # Target'taki parametre adını bul 
                    param_name = list(base_query.keys())[0] 
                    
                    tasks.append(
                        self._scan_param(
                            url=fuzz_url, 
                            param=param_name, 
                            session=session, 
                            parsed_url=parsed_fuzz_url, 
                            base_query=base_query,
                            generated_payloads=generated_payloads, 
                            baseline_threshold_s=baseline_threshold_s,
                            time_based_allowed=True, 
                            exploit_manager=getattr(self, "exploit_manager", None)
                        )
                    )
                    
                if tasks: await asyncio.gather(*tasks)
                completed_callback()
                return

            # Eğer fuzzing_targets boşsa, geleneksel URL'den parametreleri çıkar (Fallback)
            query_params = parse_qs(parsed_url.query)
            all_target_params = set(query_params.keys())

            if is_local_lab and parsed_url.path in ["/api/data"]:
                all_target_params = {"query"}
                if "query" not in query_params:
                    query_params["query"] = ["test"]
                
            if not all_target_params:
                self.add_result(self.category, "INFO", "INFO: Taranacak sorgu parametresi (query parameter) bulunamadı.", 0)
                completed_callback()
                return

            # --- 4) Geleneksel Tarama Görevlerini Başlat (Fallback) ---
            exploit_manager = getattr(self, "exploit_manager", None)
            tasks = []
            
            for param in all_target_params:
                tasks.append(
                    self._scan_param(url=url, param=param, session=session, parsed_url=parsed_url, base_query=query_params,
                        generated_payloads=generated_payloads, baseline_threshold_s=baseline_threshold_s,
                        time_based_allowed=True, exploit_manager=exploit_manager)
                )

            if tasks: await asyncio.gather(*tasks)

        except Exception as e:
            error_message = f"Kritik Hata: {type(e).__name__} ({str(e)})"
            score_deduction = self._calculate_score_deduction("CRITICAL")
            self.add_result(self.category, "CRITICAL", error_message, score_deduction)
            self.log(f"[{self.category}] {error_message}", "CRITICAL")

        completed_callback()

    # ------------------------------------------------------------------ #
    # Parametre Bazlı Tarama (Yardımcı Metotların Tamamlanması)
    # ------------------------------------------------------------------ #
    
    async def _scan_param(
        self, url: str, param: str, session: aiohttp.ClientSession, parsed_url, 
        base_query: Dict[str, List[str]], generated_payloads: List[str], baseline_threshold_s: float, 
        time_based_allowed: bool, exploit_manager
    ):
        """ Her parametre için SQLi kontrol döngüsünü yönetir. """
        
        # Orijinal değeri güvenli bir şekilde çekiyoruz
        original_value = base_query.get(param, [""])[0] 
        context = self._infer_param_context(original_value)

        # 1) Boolean-based SQLi kontrolü
        if await self._run_boolean_based_checks(url, param, session, parsed_url, base_query):
            return 

        # 2) Error-based / Union-based SQLi kontrolü
        if await self._run_error_based_checks(url, param, session, parsed_url, base_query, generated_payloads):
            return

        # 3) Time-based (Kalibrasyon labı için her zaman çalışmalı)
        if time_based_allowed:
            time_based_payloads = self._select_time_based_payloads_for_context(context)

            for tb_payload in time_based_payloads: 
                await self._run_time_based_multi_round(
                    base_url=url, param=param, payload=tb_payload, session=session, parsed_url=parsed_url, 
                    base_query=base_query, baseline_threshold_s=baseline_threshold_s, 
                    time_based_allowed=time_based_allowed, exploit_manager=exploit_manager,
                )

    def _infer_param_context(self, value: str) -> str:
        if not value: return "generic"
        if value.isdigit(): return "int"
        if len(value) > 64: return "generic"
        return "string"

    def _select_time_based_payloads_for_context(self, context: str) -> List[str]:
        if context == "int": return self.TIME_BASED_INT_PAYLOADS
        if context == "string": return self.TIME_BASED_STR_PAYLOADS
        return self.TIME_BASED_GENERIC_PAYLOADS

    # ------------------------------------------------------------------ #
    # Boolean/Error/Time-based Helper Methods (Daha önce gönderilen tam haller)
    # ------------------------------------------------------------------ #

    async def _run_boolean_based_checks(self, base_url: str, param: str, session: aiohttp.ClientSession, parsed_url, base_query: Dict[str, List[str]]) -> bool:
        original_content, original_status = await self._send_simple_request(base_url, param, base_query, session, parsed_url, replacement=None)
        if original_status == 0: return False

        for test in self.BOOLEAN_TESTS:
            true_payload = test["true"]
            false_payload = test["false"]
            true_content, true_status = await self._send_simple_request(base_url, param, base_query, session, parsed_url, replacement=true_payload)
            false_content, false_status = await self._send_simple_request(base_url, param, base_query, session, parsed_url, replacement=false_payload)

            if true_status == 0 or false_status == 0 or true_status != false_status or true_content == false_content: continue

            len_true = len(true_content)
            len_false = len(false_content)
            max_len = max(len_true, len_false, 1)
            diff_abs = abs(len_true - len_false)
            diff_ratio = diff_abs / max_len

            if diff_abs >= self.MIN_CONTENT_DIFF_ABS and diff_ratio >= self.MIN_CONTENT_DIFF_RATIO:
                level = "WARNING"; score = self._calculate_score_deduction(level)
                
                # POC Hazırlığı
                poc_params = base_query.copy(); poc_params[param] = [true_payload]
                poc_qs = urlencode(poc_params, doseq=True); poc_url_parts = list(parsed_url); poc_url_parts[4] = poc_qs
                final_poc_url = urlunparse(poc_url_parts)

                self.add_result(self.category, level, (f"RİSK: Boolean-based SQLi şüphesi. Parametre: '{param}'. True/False yükleri farklı yanıt üretti (Δ≈{diff_abs} byte). Payload(OR): {true_payload}"), score,
                    poc_data={"url": final_poc_url, "method": "GET", "attack_vector": f"Boolean-Based SQLi (Param: {param})", "data": None, "headers": {}})
                return True
        return False

    async def _run_error_based_checks(
        self, base_url: str, param: str, session: aiohttp.ClientSession, parsed_url, 
        base_query: Dict[str, List[str]], generated_payloads: List[str]
    ) -> bool:
        candidate_payloads = generated_payloads[:50]
        for payload in candidate_payloads:
            try: # KRİTİK TRY-EXCEPT EKLENDİ
                # KRİTİK SON DÜZELTME (v2.5.11): Payload'ın string olduğundan emin ol
                safe_payload = str(payload)
                
                content, status = await self._send_simple_request(base_url, param, base_query, session, parsed_url, replacement=safe_payload)
                if status == 0: continue
                lower_content = content.lower()

                for pattern in self.ERROR_PATTERNS:
                    if pattern.search(lower_content):
                        level = "CRITICAL"; score = self._calculate_score_deduction(level)
                        
                        poc_params = base_query.copy(); poc_params[param] = [safe_payload]
                        poc_qs = urlencode(poc_params, doseq=True); poc_url_parts = list(parsed_url); poc_url_parts[4] = poc_qs
                        final_poc_url = urlunparse(poc_url_parts)

                        self.add_result(self.category, level, (f"KRİTİK: SQL Hata Mesajı İfşası (Error-Based SQLi). Parametre: '{param}'. Payload: {safe_payload}"), score,
                            poc_data={"url": final_poc_url, "method": "GET", "attack_vector": f"Error-Based SQLi (Param: {param})", "data": None, "headers": {}})
                        return True
            except TypeError as e:
                # Muhtemelen urlparse, parse_qs veya indeksleme hatası
                # Bu hata artık büyük ihtimalle buradaki dönüşümlerden değil, çağrı sırasında gelen hatalı inputtan kaynaklanıyor olmalı.
                self.log(f"[{self.category}] Pipeline Hata Teşhisi (TypeError): Param '{param}'. Payload: {payload}. Hata: {str(e)}", "CRITICAL")
            except Exception as e:
                self.log(f"[{self.category}] Genel hata (Error-Based): {type(e).__name__}", "WARNING")
        
        return False
    
    @staticmethod
    def _calculate_correlation(x: List[float], y: List[float]) -> float:
        if len(x) != len(y) or len(x) < 2: return 0.0
        n = len(x); mean_x = sum(x) / n; mean_y = sum(y) / n; sum_xy = sum([(x[i] - mean_x) * (y[i] - mean_y) for i in range(n)])
        sum_x2 = sum([(x[i] - mean_x) ** 2 for i in range(n)]); sum_y2 = sum([(y[i] - mean_y) ** 2 for i in range(n)])
        denominator = math.sqrt(sum_x2 * sum_y2)
        return sum_xy / denominator if denominator != 0 else 0.0

    async def _run_time_based_multi_round(
        self, base_url: str, param: str, payload: str, session: aiohttp.ClientSession, parsed_url, 
        base_query: Dict[str, List[str]], baseline_threshold_s: float, time_based_allowed: bool, exploit_manager
    ):
        if not time_based_allowed: return
        delays_to_test = [0.0] + self.CONTROL_DELAYS + [self.EXPECTED_SLEEP_DELAY]
        actual_latencies: List[float] = []; expected_sleep_times: List[float] = [] 

        for round_num in range(self.ROUNDS):
            for expected_delay in delays_to_test:
                payload_context = self._infer_param_context("string"); payload_templates = self._select_time_based_payloads_for_context(payload_context)
                payload_template = random.choice(payload_templates)
                if expected_delay == 0.0: payload_to_send = ""
                else: payload_to_send = payload_template.replace("{delay_time}", str(int(expected_delay)))
                    
                duration = await self._single_timed_request(base_url, param, base_query, session, parsed_url, replacement=payload_to_send)
                if duration is None: continue
                actual_latencies.append(duration)
                expected_total_time = (baseline_threshold_s + expected_delay) 
                expected_sleep_times.append(expected_total_time)
        
        if len(actual_latencies) < 6: return
        correlation = self._calculate_correlation(expected_sleep_times, actual_latencies)
        avg_delay_on_max_sleep = statistics.mean([actual_latencies[i] for i, exp_time in enumerate(expected_sleep_times) if exp_time >= baseline_threshold_s + self.EXPECTED_SLEEP_DELAY])
        is_high_correlation = correlation >= self.CORRELATION_THRESHOLD
        is_sufficiently_slow = avg_delay_on_max_sleep >= baseline_threshold_s + (self.EXPECTED_SLEEP_DELAY * 0.8)
        
        if is_high_correlation and is_sufficiently_slow:
            level = "CRITICAL"; score = self._calculate_score_deduction(level)
            poc_params = base_query.copy(); poc_params[param] = [payload_to_send]; poc_qs = urlencode(poc_params, doseq=True); poc_url_parts = list(parsed_url); poc_url_parts[4] = poc_qs
            final_poc_url = urlunparse(poc_url_parts)
            self.add_result(self.category, level, (f"KANITLANMIŞ Time-Based SQLi! Parametre: '{param}'. Korelasyon (Kanıt): {correlation:.2f}. Ort. Gecikme: {avg_delay_on_max_sleep:.2f}s."), score,
                poc_data={"url": final_poc_url, "method": "GET", "attack_vector": f"Time-Based SQLi (Param: {param})", "data": None, "headers": {}})
            
            if hasattr(self, 'neural_engine') and self.neural_engine.is_active: asyncio.create_task(self.neural_engine.analyze_vulnerability({"category": self.category, "message": f"Time-Based SQLi kanıtlandı. Payload: {payload_to_send}", "metrics": f"Correlation: {correlation:.2f}, Avg Delay: {avg_delay_on_max_sleep:.2f}s"}))
            return
        
        self.log(f"[{self.category}] Time-Based Sinyal Zayıf (Param: {param}). Korelasyon: {correlation:.2f}. Avg Delay: {avg_delay_on_max_sleep:.2f}s. Kanıt yetersiz.", "INFO")
        
    async def _send_simple_request(self, base_url: str, param: str, base_query: Dict[str, List[str]], session: aiohttp.ClientSession, parsed_url, replacement: Optional[str]) -> Tuple[str, int]:
        
        # KRİTİK DÜZELTME: base_query'nin değerlerini güvenli bir şekilde kopyala (TypeError'ı önler)
        test_params = {}
        for k, v in base_query.items():
            if isinstance(v, list):
                test_params[k] = v[:] # Güvenli liste kopyalama
            else:
                test_params[k] = [str(v)] # String veya tek değer ise, liste içine al
        
        if replacement is not None: test_params[param] = [replacement] 
        
        query_str = urlencode(test_params, doseq=True); url_parts = list(parsed_url); url_parts[4] = query_str
        test_url = urlunparse(url_parts)
        try:
            async with self._sem: response, _ = await self._throttled_request(session, "GET", test_url, allow_redirects=True)
            if response is None: return "", 0
            text = await response.text()
            return text, response.status
        except Exception: return "", 0

    async def _single_timed_request(self, base_url: str, param: str, base_query: Dict[str, List[str]], session: aiohttp.ClientSession, parsed_url, replacement: str) -> Optional[float]:
        
        # KRİTİK DÜZELTME: base_query'nin değerlerini güvenli bir şekilde kopyala (TypeError'ı önler)
        test_params = {}
        for k, v in base_query.items():
            if isinstance(v, list):
                test_params[k] = v[:] # Güvenli liste kopyalama
            else:
                test_params[k] = [str(v)] # String veya tek değer ise, liste içine al

        test_params[param] = [replacement] 
        
        query_str = urlencode(test_params, doseq=True); url_parts = list(parsed_url); url_parts[4] = query_str
        test_url = urlunparse(url_parts)
        try:
            start = time()
            async with self._sem: response, _ = await self._throttled_request(session, "GET", test_url) 
            if response is None: return None
            await response.text()
            end = time()
            return end - start
        except Exception: return None
            
    def _calculate_score_deduction(self, level: str) -> float:
        weight = self.engine_instance.MODULE_WEIGHTS.get(self.category, 0.0)
        if level == "CRITICAL": return weight
        elif level == "HIGH": return weight * 0.7
        else: return weight * 0.3