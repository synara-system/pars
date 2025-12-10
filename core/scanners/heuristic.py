# path: core/scanners/heuristic.py

import aiohttp
import aiohttp.client_exceptions
from typing import Callable, Dict, List
import re
import math

from core.scanners.base_scanner import BaseScanner


class HeuristicScanner(BaseScanner):
    """
    [AR-GE v3.2 - CRITICAL FIX]
    Gelişmiş Heuristic Analiz Motoru. Zafiyet Motorları için kritik meta veri sağlar:
    1. Reflection Context Detection (SCRIPT_UNQUOTED gibi tehlike seviyesi)
    2. Modern Framework (React/Vue) Fingerprinting
    3. Entropy-Based Secret Leakage Detection
    
    V3.2: Yazım hataları ve Entropy/Reflection filtre mantık hataları düzeltildi.
    """

    REFLECTION_TEST_TOKEN = "SynaraHeuristicToken1A2B3C"

    def __init__(self, logger, results_callback, request_callback: Callable[[], None]):
        # KRİTİK HATA DÜZELTMESİ: super().__init__ çağrımında parantezler eklendi.
        super().__init__(logger, results_callback, request_callback)

        # Tüm gelişmiş reflection + content diff bilgilerini XSS modülüne aktaracağız.
        self.reflection_info: Dict[str, any] = {
            "is_reflected": False,
            "context": None,
            "similarity": None,
        }

    @property
    def name(self): # HATA 1 DÜZELTİLDİ: name property'sinin yazım hatası giderildi.
        return "Heuristic Analiz Motoru (Gelişmiş Zeka)"

    @property
    def category(self):
        return "HEURISTIC"

    async def scan(self, url: str, session: aiohttp.ClientSession, completed_callback: Callable[[], None]):
        try:
            # --- 1. NORMAL İSTEK ---
            self.request_callback()
            async with session.get(url, allow_redirects=True) as res_normal:
                base_status = res_normal.status
                base_content = await res_normal.text()
                base_headers = res_normal.headers

                await self._check_status_code(base_status)
                self._check_body_content(base_content)
                self._check_headers_info(base_headers)

            # --- 2. REFLECTION TEST + CONTEXT EXTRACTOR ---
            await self._run_advanced_reflection(url, base_content, session)

        except Exception as e:
            score = self._calculate_score_deduction("CRITICAL")
            self.add_result(self.category, "CRITICAL", f"Kritik Heuristic Hatası: {type(e).__name__} ({str(e)})", score)

        completed_callback()

    # ----------------------------------------------------------------------
    #  HTML & FRAMEWORK CHECKER
    # ----------------------------------------------------------------------
    def _check_body_content(self, content: str):
        c = content.lower()

        if "index of /" in c:
            self.add_result(self.category, "CRITICAL", "KRİTİK: Directory Listing aktif!", 5)

        error_patterns = [
            r"warning: .*?\.php on line",
            r"mysql_fetch_array",
            r"sql syntax.*?near",
            r"in your sql statement"
        ]
        for p in error_patterns:
            if re.search(p, c):
                self.add_result(self.category, "WARNING", "RİSK: PHP/SQL hata mesajı ifşası.", 2)

        if "<!-- password" in c or "<!-- admin" in c:
            self.add_result(self.category, "INFO", "BİLGİ: HTML yorumlarında hassas bilgi olabilir.", 0)
        
        # YENİ: FRAMEWORK FINGERPRINTING çağrılır
        self._check_framework_fingerprints(c)

    def _check_framework_fingerprints(self, content_lower: str):
        """
        [YENİ] HTML içeriğinden modern framework izlerini (Front-end) tespit eder.
        """
        fingerprints = {
            "Next.js/React": [r"_next/static/", r"data-reactroot"],
            "Nuxt.js/Vue": [r"_nuxt/", r"data-v-", r"id=\"__nuxt\""],
            "Angular": [r"ng-app", r"ng-binding"],
            "Jinja2 (SSTI)": [r"{{", r"}}"],
            "ASP.NET": [r"__VIEWSTATE", r"aspx"],
        }

        found_framework = None
        for framework, patterns in fingerprints.items():
            for pattern in patterns:
                if re.search(pattern, content_lower):
                    found_framework = framework
                    # Sadece ilk bulguyu raporla ve bu framework'ü belirle
                    break
            if found_framework:
                break
        
        if found_framework:
             self.add_result(self.category, "INFO", f"Teknoloji İpucu: {found_framework} parmak izi bulundu.", 0)
        else:
             self.add_result(self.category, "INFO", "Sunucu yazılımı: Standart HTML/Backend Framework.", 0)


    # ----------------------------------------------------------------------
    #  ADVANCED REFLECTION ENGINE (V8.0)
    # ----------------------------------------------------------------------
    async def _run_advanced_reflection(self, url: str, base_content: str, session: aiohttp.ClientSession):

        test_url = f"{url}?synara_test={self.REFLECTION_TEST_TOKEN}"

        try:
            # _throttled_request BaseScanner'da varsayılıyor
            res, _ = await self._throttled_request(
                session,
                "GET",
                test_url,
                allow_redirects=True,
                timeout=aiohttp.ClientTimeout(total=7)
            )

            if res is None:
                return

            test_content = await res.text()

        except Exception:
            self.log("[HEURISTIC] Reflection test isteği başarısız.", "WARNING")
            return

        # -------------------------------------------------------
        # 1. TOKEN YANSIDI MI?
        # -------------------------------------------------------
        if self.REFLECTION_TEST_TOKEN in test_content:
            self.reflection_info["is_reflected"] = True
        else:
            self.reflection_info["is_reflected"] = False
            self.add_result(self.category, "SUCCESS", "GÜVENLİ: Heuristic yansıma kontrolü temiz.", 0)
            return

        # -------------------------------------------------------
        # 2. Reflection Context Detection (Bağlamsal Tehdit Seviyesi)
        # -------------------------------------------------------
        context = self._detect_reflection_context(test_content)
        self.reflection_info["context"] = context

        if context == "SCRIPT_UNQUOTED":
            level = "CRITICAL"
            msg = "KRİTİK: Token SCRIPT tag içinde tırnaksız yansıyor → DOM XSS/RCE olasılığı ÇOK YÜKSEK!"
        elif context == "ATTRIBUTE":
            level = "HIGH"
            msg = "YÜKSEK RİSK: Token HTML attribute içinde yansıyor → Olay işleyici (event handler) enjeksiyonu mümkün."
        elif context == "HTML_TAG":
            level = "WARNING"
            msg = "UYARI: Token bir HTML etiketi içinde yansıyor (örn: <div>TOKEN</div>) → Kolay XSS atlatma."
        else: # BODY_PLAIN
            level = "INFO"
            msg = "Token gövde içinde düz metin olarak yansıyor."

        self.add_result(self.category, level, msg, self._calculate_score_deduction(level))

        # -------------------------------------------------------
        # 3. İçerik Benzerlik Analizi (Levenshtein Similarity)
        # -------------------------------------------------------
        sim = self._calculate_similarity(base_content, test_content)
        self.reflection_info["similarity"] = sim

        if sim < 0.25:
            self.add_result(
                self.category,
                "CRITICAL",
                f"KRİTİK: Parametre manipülasyonu içerik akışını %75'ten fazla değiştiriyor. (Sim={sim:.2f})",
                self._calculate_score_deduction("CRITICAL"),
            )
        elif sim < 0.6:
            self.add_result(
                self.category,
                "WARNING",
                f"UYARI: İçerik farkı yüksek (%40+ değişim). Parametre içerik yapısını etkiliyor. (Sim={sim:.2f})",
                self._calculate_score_deduction("WARNING"),
            )
        # -------------------------------------------------------
        # 4. Entropy-Based Secret Leakage Detection (FP-GUARD EKLENDİ)
        # -------------------------------------------------------
        leakage = self._detect_entropy_leakage(test_content)
        if leakage:
            level = "CRITICAL"
            self.add_result(
                self.category,
                level,
                f"KRİTİK: Yanıt gövdesinde potansiyel secret/token benzeri yüksek entropy değerli veri bulundu → {leakage[:60]}...",
                self._calculate_score_deduction(level)
            )

    # ----------------------------------------------------------------------
    #  REFLECTION CONTEXT DETECTOR (YENİ VE GÜÇLENDİRİLMİŞ)
    # ----------------------------------------------------------------------
    def _detect_reflection_context(self, content: str):
        token = re.escape(self.REFLECTION_TEST_TOKEN)

        # RİSK 1: SCRIPT_UNQUOTED (KRİTİK TEHLİKE)
        # Token, script tag'in içinde, tırnak işaretleri olmadan yansıyor.
        # KRİTİK DÜZELTME: Bu regex sadece tırnaksız yansımayı yakalamalıdır.
        # <script>var a=TOKEN;</script> gibi.
        if re.search(rf"<script[^>]*>[^\"']*?{token}[^\"']*?<\/script>", content, re.IGNORECASE):
            return "SCRIPT_UNQUOTED"

        # RİSK 2: ATTRIBUTE (YÜKSEK RİSK)
        # Token, bir HTML niteliği (attribute) içinde yansıyor.
        if re.search(rf'\w+="[^"]*{token}[^"]*"', content, re.IGNORECASE) or \
           re.search(rf"\w+='[^']*{token}[^']*'", content, re.IGNORECASE):
            return "ATTRIBUTE"

        # RİSK 3: HTML TAG (WARNING)
        # Token bir HTML etiketi içinde yansıyor (örn: <div>TOKEN</div>)
        if re.search(rf"<[^>]+>{token}<[^>]+>", content, re.IGNORECASE):
             return "HTML_TAG"
             
        # RİSK 4: DÜZ METİN (BODY_PLAIN)
        return "BODY_PLAIN"


    # ----------------------------------------------------------------------
    #  LEVENSHTEIN DISTANCE (LIGHTWEIGHT)
    # ----------------------------------------------------------------------
    def _calculate_similarity(self, a: str, b: str) -> float:
        """
        0 → tamamen farklı, 1 → tamamen aynı.
        """
        if not a or not b:
            return 0.0

        la, lb = len(a), len(b)
        if abs(la - lb) > 2000:
            # İçerik çok farklıysa CPU harcamaya gerek yok
            return 0.0

        # DP tabanlı Levenshtein (optimize)
        dp = list(range(lb + 1))

        for i in range(1, la + 1):
            prev = dp[:]
            dp[0] = i
            for j in range(1, lb + 1):
                cost = 0 if a[i - 1] == b[j - 1] else 1
                dp[j] = min(prev[j] + 1, dp[j - 1] + 1, prev[j - 1] + cost)

        distance = dp[-1]
        max_len = max(la, lb)

        return 1 - (distance / max_len)

    # ----------------------------------------------------------------------
    #  HIGH ENTROPY SECRET LEAKAGE DETECTOR
    # ----------------------------------------------------------------------
    def _detect_entropy_leakage(self, content: str):
        """
        [FP-GUARD] Yüksek entropili sızıntıları tespit ederken, yaygın Base64 bloklarını filtreler.
        """
        
        # Token arama, base64 karakter seti ve minimum 50 karakter uzunluğu (FP düşürmek için artırıldı)
        possible_secrets = re.findall(r"[A-Za-z0-9+/=]{50,}", content)

        for token_candidate in possible_secrets:
            ent = self._entropy(token_candidate)

            # Yüksek Entropi Eşiği (3.8)
            if ent > 3.8: 
                # HATA 2 DÜZELTİLDİ: Base64 bitiş kontrolü OR ile yapıldı.
                is_b64_ending = token_candidate.endswith("=") or token_candidate.endswith("==")
                
                # Basit bir kontrol için token'ın kendisinde arayalım.
                is_crit_word = any(kw in token_candidate.lower() for kw in ["key", "token", "secret", "auth", "jwt"])

                # HATA 3 DÜZELTİLDİ: Mantık ters çevrildi. 
                # Eğer B64 bitişli İSE ve kritik kelime YOK İSE, büyük ihtimalle FP'dir (atla).
                if is_b64_ending and not is_crit_word:
                    self.log(f"[HEURISTIC-FP] Yüksek Entropi FP atlandı: B64 sonlanıyor ve kritik kelime yok. Ent: {ent:.2f}", "INFO")
                    continue
                
                # Yüksek entropi ve ya B64 değil, ya da kritik kelime içeriyor -> Raporla
                return token_candidate

        return None

    def _entropy(self, s: str):
        freqs = {}
        for c in s:
            freqs[c] = freqs.get(c, 0) + 1

        length = len(s)
        return -sum((count / length) * math.log2(count / length) for count in freqs.values())

    # ----------------------------------------------------------------------
    #  BASIC EXISTING CHECKS (OLD ENGINE)
    # ----------------------------------------------------------------------
    async def _check_status_code(self, status: int):
        if status == 401:
            self.add_result(self.category, "WARNING", "UYARI: 401 Unauthorized yanıtı alındı.", 1)
        elif status == 403:
            self.add_result(self.category, "WARNING", "UYARI: 403 Forbidden – Bypass denenebilir.", 2)
        elif status == 500:
            self.add_result(self.category, "CRITICAL", "KRİTİK: 500 Internal Server Error!", 5)
        # Kapsam dışı olduğu için 200/300 durumları raporlanmaz

    def _check_headers_info(self, headers: dict):
        if "Server" in headers:
            self.add_result(self.category, "INFO", f"Sunucu: {headers['Server']}", 0)

        if headers.get("Access-Control-Allow-Origin") == "*":
            self.add_result(self.category, "WARNING", "UYARI: CORS '*' → geniş erişim riski.", 1)