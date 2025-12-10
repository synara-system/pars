# path: core/scanners/json_api_scanner.py

import aiohttp
import aiohttp.client_exceptions
import asyncio
import json
from typing import Callable, List, Dict, Any, Optional, Set
from urllib.parse import urlparse, parse_qs, urlencode, urljoin

from core.scanners.base_scanner import BaseScanner
from core.payload_generator import PayloadGenerator


class JSONAPIScanner(BaseScanner):
    """
    POST/PUT gövdeleri için JSON formatında payload'lar oluşturarak
    XSS / SQLi benzeri zafiyetleri test eder.

    ÖNEMLİ GÜNCELLEME:
    - Baseline (kontrol) isteği başarısız veya HTML dönerse → JSON API taraması tamamen atlanır.
    - Fuzzing isteklerindeki timeout'lar log spam yapmaz, sessizce geçilir.
    - V3.0 Path Fuzzing: Parametre bulunamazsa yaygın API yollarını dener.
    """

    # Varsayılan API endpoint (boş ise hedef URL'ye POST atar)
    DEFAULT_API_ENDPOINT = ""

    # Yanıt uzunluğu farkı eşiği
    RESPONSE_DIFF_THRESHOLD = 100
    
    # V3.0: Yaygın API endpoint yolları (API Path Fuzzing için)
    COMMON_API_PATHS = [
        "/v1/login", "/v1/auth", "/v1/user/me", "/v1/data", "/v2/users",
        "/api/login", "/api/v1/user", "/api/v2/data/public", "/auth/token",
        "/v3/status", "/user/profile", "/guest/login", "/api/stats", "/api/events"
    ]


    @property
    def name(self):
        return "JSON/REST API Zafiyet Keşfi"

    @property
    def category(self):
        return "JSON_API"

    def __init__(self, logger, results_callback, request_callback: Callable[[], None]):
        super().__init__(logger, results_callback, request_callback)
        self.payload_generator = PayloadGenerator(logger)

    async def scan(self, url: str, session: aiohttp.ClientSession, completed_callback: Callable[[], None]):
        """
        JSON API tarama mantığını uygular (Asenkron).
        """
        try:
            # 1) Payload listelerini hazırla
            base_xss_payloads = self.payload_generator.generate_xss_payloads()
            base_sqli_payloads = self.payload_generator.generate_sqli_payloads()
            all_payloads = list(set(base_xss_payloads + base_sqli_payloads))

            # Keşif modüllerinden gelen tüm API yolları veya parametreleri
            # KRİTİK DÜZELTME: Gelen veriyi Set tipine dönüştürüyoruz.
            discovered_items: Set[str] = set(getattr(self, "discovered_params", set()))

            # ----------------------------------------------------
            # V5.1 KRİTİK DEĞİŞİKLİK: Hedeflenecek Yolları Belirle
            # ----------------------------------------------------
            target_endpoints: List[str] = []
            
            # 1. Statik Path Fuzzing: Parametre bulunamazsa yedek olarak kullanılır (Path Fuzzing listesi)
            if not discovered_items or all(not item.startswith('/') for item in discovered_items):
                 self.log(f"[{self.category}] JS/Pre-Scan'den dinamik yol gelmedi. Statik Path Fuzzing ({len(self.COMMON_API_PATHS)} yol) başlatılıyor...", "WARNING")
                 target_endpoints.extend(self.COMMON_API_PATHS)
            else:
                 # 2. Dinamik Keşif Yolları: JS_ENDPOINT'ten gelen ve '/' ile başlayan yollar (en kritik veri)
                 self.log(f"[{self.category}] JS Keşfi başarılı. {len(discovered_items)} adet yol/parametre üzerinden fuzzing başlatılıyor.", "INFO")
                 target_endpoints.extend([item for item in discovered_items if item.startswith('/')])
            
            
            if not target_endpoints:
                self.add_result(self.category, "INFO", "INFO: JSON API taraması için uygun API yolu/endpoint'i bulunamadı.", 0)
                completed_callback()
                return

            # ----------------------------------------------------
            # 3. Yürütme: Her API Yolu + Her Parametre için Fuzzing
            # ----------------------------------------------------
            
            tasks: List[asyncio.Task] = []
            
            # Test edilecek DUMMY parametreler (Çünkü sadece yol bulduk, parametre adı bulamadık)
            dummy_params = {"data": "api_test_data", "id": 12345}

            # Her bir endpoint'e Fuzzing uygula
            for endpoint in target_endpoints:
                
                # A) Bu yolda fuzzing yapılması gereken parametreleri belirle
                params_to_fuzz: Set[str] = set()
                
                # Eğer keşfedilenler arasında path olmayan, sadece parametre isimleri varsa, onları kullan
                if not endpoint.startswith('/'):
                    params_to_fuzz.add(endpoint) # PRE_SCAN'in bulduğu parametreler
                else:
                    params_to_fuzz.update(dummy_params.keys()) # Sadece yol bulduysak, dummy parametreleri kullan

                # B) Baseline (kontrol) isteği
                baseline_payload: Dict[str, Any] = {}
                for p_name in params_to_fuzz:
                    baseline_payload[p_name] = self._guess_default_value(p_name)
                
                original_content, original_status_code = await self._fetch_json_api(
                    url, session, payload=baseline_payload, log_on_timeout=True, path_suffix=endpoint
                )

                if original_content is None or original_status_code not in [200, 400]:
                    # Baseline alınamazsa veya 404/403/5xx dönerse bu endpoint'i atla
                    self.log(f"[{self.category}] Yol atlandı: {endpoint} -> Geçersiz Baseline ({original_status_code})", "WARNING")
                    continue

                # Yanıt HTML ise bu endpoint API değildir → atla
                content_start = original_content.strip().lower()
                if content_start.startswith("<html") or content_start.startswith("<!doctype html"):
                    self.log(f"[{self.category}] Yol atlandı: {endpoint} -> HTML yanıtı döndü.", "WARNING")
                    continue
                
                # C) Fuzzing görevlerini oluştur
                for param in params_to_fuzz:
                    for payload in all_payloads:
                        tasks.append(
                            self._test_json_fuzzing(
                                url,
                                param,
                                payload,
                                session,
                                original_content,
                                original_status_code,
                                endpoint # Yeni endpoint'i geçir
                            )
                        )
            
            total_tasks = len(tasks)
            if total_tasks > 0:
                self.log(f"[{self.category}] Toplam {total_tasks} JSON API kombinasyonu keşfedilen yollarda taranacak.", "SUCCESS")
            
                await asyncio.gather(*tasks)

        except Exception as e:
            error_message = f"Kritik Hata: {type(e).__name__} ({str(e)})"
            score_deduction = self._calculate_score_deduction("CRITICAL")
            self.add_result(self.category, "CRITICAL", error_message, score_deduction)
            self.log(f"[{self.category}] {error_message}", "CRITICAL")

        completed_callback()

    def _guess_default_value(self, param_name: str) -> Any:
        """
        Parametre ismine bakarak API'nin kabul edeceği varsayılan değeri tahmin eder.
        """
        param_lower = param_name.lower()

        if any(x in param_lower for x in ["id", "count", "limit", "offset", "age", "year", "status", "price", "quantity"]):
            return 1

        if any(x in param_lower for x in ["is_", "has_", "enable", "visible", "active"]):
            return True

        if "email" in param_lower:
            return "test@example.com"

        if "url" in param_lower or "link" in param_lower or "site" in param_lower:
            return "http://example.com"

        if "date" in param_lower or "time" in param_lower:
            return "2025-01-01"

        return "synara_test_data"

    async def _fetch_json_api(
        self,
        url: str,
        session: aiohttp.ClientSession,
        payload: Dict[str, Any],
        log_on_timeout: bool,
        path_suffix: str = None # Yeni: Dinamik path parametresi
    ):
        """
        URL'ye POST isteği gönderir ve içeriği/durum kodunu döndürür.
        Baseline isteği için timeout loglanır, fuzzing için sessiz geçilir.
        """

        # YENİ: Dinamik path'i kullan
        target_path = path_suffix if path_suffix is not None else self.DEFAULT_API_ENDPOINT
        api_url = urljoin(url, target_path)

        # Dinamik timeout: kalibrasyona göre ama asla 10 saniyenin altına düşmesin, 20'nin üstüne çıkmasın
        base_timeout_s = getattr(self, "calibration_latency_ms", 4000) / 1000.0
        total_timeout_s = max(10.0, min(20.0, base_timeout_s * 5.0))

        try:
            # Jitter / Token-Bucket entegrasyonu (varsa)
            if hasattr(self, '_apply_jitter_and_throttle'):
                await self._apply_jitter_and_throttle()

            self.request_callback()

            async with session.post(
                api_url,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=total_timeout_s),
            ) as res:
                content = await res.text()
                return content, res.status

        except asyncio.TimeoutError:
            if log_on_timeout:
                self.log(
                    f"[{self.category}] API Timeout: {total_timeout_s:.1f}s sınırı aşıldı.",
                    "WARNING",
                )
            return None, None

        except aiohttp.client_exceptions.ClientConnectorError:
            if log_on_timeout:
                self.log(
                    f"[{self.category}] API İstek Hatası: ClientConnectorError (Bağlantı kurulamadı)",
                    "WARNING",
                )
            return None, None

        except Exception as e:
            if log_on_timeout:
                self.log(
                    f"[{self.category}] API İstek Hatası: {type(e).__name__}",
                    "WARNING",
                )
            return None, None

    async def _test_json_fuzzing(
        self,
        url: str,
        param: str,
        payload: str,
        session: aiohttp.ClientSession,
        original_content: str,
        original_status_code: int,
        target_endpoint: str # Yeni endpoint parametresi
    ):
        """
        Verilen parametreye payload enjekte ederek API'yi test eder.
        Fuzzing çağrılarında timeout'lar loglanmaz, sadece sessizce atlanır.
        """

        test_payload_body: Dict[str, Any] = {}

        for p in self.discovered_params:
            if p == param:
                test_payload_body[p] = payload
            else:
                test_payload_body[p] = self._guess_default_value(p)

        test_content, test_status_code = await self._fetch_json_api(
            url,
            session,
            payload=test_payload_body,
            log_on_timeout=False,  # Fuzzing timeout'ları spam yapmasın
            path_suffix=target_endpoint # Yeni endpoint'i geçir
        )

        if test_content is None:
            return

        # 500 → Doğrudan kritik backend hatası
        if test_status_code == 500:
            score_deduction = self._calculate_score_deduction("CRITICAL")
            self.add_result(
                self.category,
                "CRITICAL",
                f"KRİTİK: JSON Fuzzing hatası! Parametre '{param}' payload'ı sunucu tarafında 500 hatası tetikledi. Payload: {payload[:20]}...",
                score_deduction,
            )
            return

        len_diff = abs(len(test_content) - len(original_content))

        if len_diff > self.RESPONSE_DIFF_THRESHOLD and original_status_code == test_status_code:
            score_deduction = self._calculate_score_deduction("WARNING")
            self.add_result(
                self.category,
                "WARNING",
                f"RİSK: JSON Zafiyet Şüphesi! Parametre '{param}' ile yanıt içeriği değişti (Fark: {len_diff} byte). Payload: {payload[:20]}...",
                score_deduction,
            )
            return