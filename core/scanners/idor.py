# path: core/scanners/idor.py

import aiohttp
import aiohttp.client_exceptions
import asyncio
import re
import hashlib  # SimHash için eklendi
import math  # Entropy için eklendi
import json
from typing import Callable, Tuple, Optional, Dict, Union, Set, List
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

from core.scanners.base_scanner import BaseScanner


class IDORScanner(BaseScanner):
    """
    [AR-GE v7.2 - GHOST PARAMETER HUNTER]
    URL Query Parametrelerinde Insecure Direct Object Reference (IDOR) zafiyetini tarar.
    
    İCAT EDİLEN ÖZELLİKLER:
    - Ghost Parameter Injection: URL'de görünmese bile yaygın IDOR parametrelerini (user_id, account_id...)
      her isteğe enjekte ederek "gizli" zafiyetleri arar.
    - Reflection Analysis: Enjekte edilen ID'nin yanıt içinde geçip geçmediğini (Reflection) kontrol eder.
    - Full Coverage: Sadece sayısal değil, tüm parametreleri test kapsamına alır.
    - Gelişmiş Çok Katmanlı Doğrulama (SimHash + Dice + Entropy).
    """

    # Sayısal ID'leri yakalamak için RegEx
    ID_PATTERN = re.compile(r"(\d+)")

    # IDOR tespiti için minimum içerik boyutu veya içerik değişim eşiği
    CONTENT_DIFF_THRESHOLD = 50 

    # Hassas anahtar kelimeler
    SENSITIVE_KEYWORDS = [
        "email", "profile", "address", "user_id", "secret", "private", "balance",
        "e-posta", "eposta", "tc kimlik", "tckn", "tcno", "telefon", "adres",
        "şifre", "password", "hesap", "account", "sipariş", "order", "fatura",
        "ödeme", "kart", "iban", "bakiye", "kredi", "borç", "kargo", "delivery",
        "admin", "root", "token", "key", "auth", "session", "invoice"
    ]
    
    # Yaygın IDOR Parametreleri (Blind Injection için - Ghost Parameters)
    COMMON_IDOR_PARAMS = [
        "id", "user_id", "userid", "account_id", "account", "number", "order_id", 
        "invoice_id", "profile_id", "uid", "customer_id", "client_id", "member_id"
    ]

    # --- WAF/FIREWALL TESPİT SABİTLERİ ---
    WAF_STATUS_CODES = [403, 429, 302]
    WAF_HEADERS = [
        "Server", "X-WAF", "X-Sucuri-ID", "CF-RAY", "X-Cache", 
        "Google-Proxy-Tracking", "X-Cache-Status", "X-CDN", 
        "X-Firewall-Detection", "X-Content-Encoded-By", "X-Request-ID", 
        "Cdn-Cache-Status"
    ]
    WAF_CONTENT_KEYWORDS = ["unusual traffic", "captcha", "security check", "access denied", "blocked"]

    @property
    def name(self):
        return "IDOR Zafiyeti Tarayıcı"

    @property
    def category(self):
        return "IDOR"

    async def scan(
        self,
        url: str,
        session: aiohttp.ClientSession,
        completed_callback: Callable[[], None],
    ):
        """
        IDOR tarama mantığını uygular (Asenkron).
        """
        try:
            if not hasattr(self, 'payload_generator'):
                self.log(f"[{self.category}] Payload Generator objesi bulunamadı. Tarama atlandı.", "CRITICAL")
                completed_callback()
                return
            
            # 1. URL'yi parçalara ayır ve mevcut parametreleri topla
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            
            # Parametre listesini hazırla
            all_target_params: Set[str] = set(query_params.keys())
            
            # Keşfedilen parametreleri ekle
            discovered_params: Set[str] = getattr(self, "discovered_params", set())
            for param_name in discovered_params:
                if param_name not in all_target_params:
                    query_params[param_name] = ["1"] # Varsayılan değer
                    all_target_params.add(param_name)

            # --- GHOST PARAMETER INJECTION (YENİ İCAT) ---
            # Mevcut parametreler olsa bile, yaygın IDOR parametrelerini de test listesine ekle.
            # Böylece geliştirici parametreyi gizlemiş olsa bile (örn: POST bekleyen bir ID'yi GET ile denemek gibi) yakalayabiliriz.
            injected_param_count = 0
            for common_param in self.COMMON_IDOR_PARAMS:
                if common_param not in all_target_params:
                    # Bu parametreleri varsayılan olarak "1000" gibi bir değerle ekle
                    query_params[common_param] = ["1000"]
                    all_target_params.add(common_param)
                    injected_param_count += 1
            
            if injected_param_count > 0:
                self.log(f"[{self.category}] Ghost Parameter Hunter: {injected_param_count} adet gizli parametre enjekte edildi.", "INFO")
            
            # Base URL oluştur (Tüm parametreler dahil)
            base_url_parts = list(parsed_url)
            base_url_parts[4] = urlencode(query_params, doseq=True)
            base_url = urlunparse(base_url_parts)

            # 2. ORİJİNAL İSTEK (Kontrol)
            original_content, original_status_code, original_protection = await self._fetch_url(
                base_url, session, is_control=True
            )

            if original_content is None:
                self.add_result(self.category, "INFO", "Orijinal yanıt alınamadığı için IDOR taraması atlandı.", 0)
                completed_callback()
                return

            if original_protection:
                self.log(f"[{self.category}] Koruma Tespiti: {original_protection}. Sonuçlar filtrelenecek.", "WARNING")

            tasks: List[asyncio.Task] = []
            
            try:
                test_ids: List[int] = self.payload_generator.generate_idor_test_ids()
            except AttributeError:
                test_ids = [1, 0, 100, 101, 999, 1000, 2024] # Fallback

            # 3. FUZZING
            for param in all_target_params:
                original_value = query_params.get(param, [""])[0]
                
                # Sayısal ID var mı kontrol et
                id_match = self.ID_PATTERN.search(original_value)
                original_id_str = id_match.group(1) if id_match else original_value
                
                # Çok uzun değerleri (token vb.) atla, ama ghost injection için eklenenleri (kısa) tut
                if len(original_value) > 20 and param not in self.COMMON_IDOR_PARAMS: 
                    continue

                for test_id in test_ids:
                    # Değişim Mantığı
                    if id_match:
                        try:
                            if int(original_id_str) == test_id: continue
                        except: pass
                        new_value = original_value.replace(original_id_str, str(test_id), 1)
                    else:
                        new_value = str(test_id)

                    if new_value == original_value: continue

                    tasks.append(
                        self._test_idor_payload(
                            base_url, param, original_value, new_value, session,
                            parsed_url, query_params, original_content, original_status_code
                        )
                    )

            total_tasks = len(tasks)
            if total_tasks > 0:
                self.log(f"[{self.category}] {total_tasks} IDOR kombinasyonu test ediliyor...", "INFO")
                await asyncio.gather(*tasks)
            else:
                self.log(f"[{self.category}] Test edilecek uygun IDOR senaryosu oluşmadı.", "INFO")

        except Exception as e:
            error_message = f"Kritik Hata: {type(e).__name__} ({str(e)})"
            self.add_result(self.category, "CRITICAL", error_message, 0)
            self.log(f"[{self.category}] {error_message}", "CRITICAL")

        completed_callback()

    # -------------------------------------------------------------------------
    # WAF / Firewall / Anti-Bot Tespiti
    # -------------------------------------------------------------------------
    def _detect_protection_response(
        self,
        status_code: int,
        headers: Dict[str, str],
        content: str,
    ) -> Optional[str]:
        if status_code in self.WAF_STATUS_CODES:
            if status_code == 403: return "WAF/Firewall (403 Forbidden)"
            elif status_code == 429: return "Rate Limit (429 Too Many Requests)"
            elif status_code == 302 and any(k.lower() in content.lower() for k in ["captcha", "security check"]):
                return "Captcha/Anti-Bot (302 Redirect)"

        header_keys = [h.lower() for h in headers.keys()]
        for waf_header in self.WAF_HEADERS:
            if waf_header.lower() in header_keys:
                return f"Koruma Başlığı Tespit Edildi ({waf_header})"

        content_lower = content.lower()
        for keyword in self.WAF_CONTENT_KEYWORDS:
            if keyword in content_lower:
                return f"Koruma İçeriği Tespit Edildi ('{keyword}')"

        return None

    async def _fetch_url(
        self,
        url: str,
        session: aiohttp.ClientSession,
        is_control: bool,
    ) -> Tuple[Optional[str], Optional[int], Optional[str]]:
        try:
            self.request_callback()
            async with getattr(self, "module_semaphore", asyncio.Semaphore(5)):
                async with session.get(
                    url,
                    allow_redirects=True,
                    timeout=aiohttp.ClientTimeout(total=8),
                ) as res:
                    content = await res.text()
                    protection_status = self._detect_protection_response(res.status, res.headers, content)
                    return content, res.status, protection_status

        except Exception:
            return None, None, None

    # -------------------------------------------------------------------------
    # FULL SIMILARITY ENGINE (SimHash + Dice + Entropy Shift)
    # -------------------------------------------------------------------------
    def _tokenize(self, text: str) -> List[str]:
        if not text: return []
        return re.findall(r"[A-Za-z0-9_@\.-]+", text.lower())

    def _simhash(self, tokens: List[str], bit_size: int = 64) -> int:
        if not tokens: return 0
        v = [0] * bit_size
        for token in tokens:
            h = int(hashlib.md5(token.encode("utf-8")).hexdigest(), 16)
            for i in range(bit_size):
                bit = (h >> i) & 1
                v[i] += 1 if bit else -1
        fingerprint = 0
        for i in range(bit_size):
            if v[i] > 0: fingerprint |= 1 << i
        return fingerprint

    def _simhash_similarity(self, tokens_a: List[str], tokens_b: List[str], bit_size: int = 64) -> float:
        if not tokens_a or not tokens_b: return 0.0
        h1 = self._simhash(tokens_a, bit_size)
        h2 = self._simhash(tokens_b, bit_size)
        x = h1 ^ h2
        dist = bin(x).count("1")
        return 1.0 - (dist / float(bit_size))

    def _dice_coefficient(self, tokens_a: List[str], tokens_b: List[str]) -> float:
        if not tokens_a or not tokens_b: return 0.0
        set_a = set(tokens_a)
        set_b = set(tokens_b)
        if not set_a or not set_b: return 0.0
        overlap = len(set_a & set_b)
        total = len(set_a) + len(set_b)
        if total == 0: return 0.0
        return (2.0 * overlap) / float(total)

    def _shannon_entropy(self, text: str) -> float:
        if not text: return 0.0
        length = len(text)
        freq: Dict[str, int] = {}
        for ch in text: freq[ch] = freq.get(ch, 0) + 1
        entropy = 0.0
        for count in freq.values():
            p = count / float(length)
            entropy -= p * math.log2(p)
        return entropy

    def _compute_similarity_metrics(self, original: str, test: str) -> Dict[str, float]:
        tokens_orig = self._tokenize(original)
        tokens_test = self._tokenize(test)
        len_diff = abs(len(test) - len(original))
        simhash_sim = self._simhash_similarity(tokens_orig, tokens_test)
        dice_sim = self._dice_coefficient(tokens_orig, tokens_test)
        ent_orig = self._shannon_entropy(original)
        ent_test = self._shannon_entropy(test)
        entropy_shift = abs(ent_orig - ent_test)
        entropy_norm = max(0.0, min(1.0, entropy_shift / 4.0))
        
        combined_similarity = (simhash_sim * 0.45 + dice_sim * 0.35 + (1.0 - entropy_norm) * 0.20)
        diff_score = 1.0 - combined_similarity
        
        return {
            "len_diff": float(len_diff),
            "simhash_similarity": float(simhash_sim),
            "dice_similarity": float(dice_sim),
            "entropy_shift": float(entropy_shift),
            "combined_similarity": float(combined_similarity),
            "diff_score": float(diff_score),
        }

    def _analyze_idor_result(
        self,
        test_content: str,
        original_content: str,
        injected_id: str, # YENİ: Reflection kontrolü için ID'yi alıyoruz
        metrics: Optional[Dict[str, float]] = None,
    ) -> Tuple[bool, str]:
        if not original_content or not test_content: return False, ""
        if metrics is None: metrics = self._compute_similarity_metrics(original_content, test_content)

        diff_score = metrics.get("diff_score", 0.0)
        is_json = test_content.strip().startswith("{") and test_content.strip().endswith("}")
        test_content_lower = test_content.lower()
        sensitive_hit = any(keyword in test_content_lower for keyword in self.SENSITIVE_KEYWORDS)
        
        # YENİ: Reflection Check (Enjekte edilen ID dönen cevapta var mı?)
        # Bu, sunucunun parametreyi okuduğunu ve belki de hata mesajında döndürdüğünü gösterir.
        is_reflected = injected_id in test_content

        if diff_score < 0.02: return False, "" # Aynı içerik
        if diff_score > 0.90: return False, "" # Muhtemelen 404/Error sayfası

        if sensitive_hit: return True, "CRITICAL"
        if is_json and diff_score > 0.05: return True, "HIGH"
        
        # Reflection varsa ve fark varsa, bu bir işarettir
        if is_reflected and diff_score > 0.05: return True, "HIGH"
        
        if diff_score > 0.10: return True, "WARNING"

        return False, ""

    # -------------------------------------------------------------------------
    # IDOR Payload Testi
    # -------------------------------------------------------------------------
    async def _test_idor_payload(
        self,
        base_url: str,
        param: str,
        original_value: str,
        new_value: str,
        session: aiohttp.ClientSession,
        parsed_url,
        query_params,
        original_content: str,
        original_status_code: int,
    ):
        # Test URL'sini oluştur
        test_params = query_params.copy()
        test_params[param] = [new_value]
        test_query = urlencode(test_params, doseq=True)
        test_url_parts = list(parsed_url)
        test_url_parts[4] = test_query
        test_url = urlunparse(test_url_parts)

        test_content, test_status_code, test_protection = await self._fetch_url(
            test_url, session, is_control=False
        )

        if test_content is None: return
        if test_protection: return 

        if original_status_code == 200 and test_status_code in [401, 403, 404, 500]:
            return

        metrics = self._compute_similarity_metrics(original_content, test_content)
        len_diff = metrics["len_diff"]
        diff_score = metrics["diff_score"]

        # YENİ: injected_id (new_value) parametresini de gönderiyoruz
        is_idor, severity = self._analyze_idor_result(test_content, original_content, new_value, metrics=metrics)

        if is_idor:
            score_deduction = self._calculate_score_deduction(severity)
            msg_prefix = "IDOR TESPİTİ" if severity == "CRITICAL" else "IDOR ŞÜPHESİ"
            
            extra_info = ""
            if param in self.COMMON_IDOR_PARAMS and not original_value:
                extra_info = " [GHOST PARAMETER]"

            self.add_result(
                self.category,
                severity,
                (
                    f"{msg_prefix}{extra_info}: Parametre '{param}', "
                    f"Test ID: {new_value}. "
                    f"İçerik farkı: {int(len_diff)} byte. "
                    f"Fark Skoru: {diff_score:.2f}"
                ),
                score_deduction,
            )