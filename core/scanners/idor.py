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
    [AR-GE v7.0 - FAZ 36 OPTİMİZASYON]
    URL Query Parametrelerinde Insecure Direct Object Reference (IDOR) zafiyetini tarar.
    Gelişmiş Çok Katmanlı Doğrulama (SimHash + Dice Similarity + Entropy Shift + Hassas Kelime Filtresi)
    ile güvenilir ve düşük false-positive oranlı IDOR tespiti sağlar.
    
    FAZ 36: ID listesi PayloadGenerator'dan çekilerek merkezi hale getirildi.
    """

    # Sayısal ID'leri yakalamak için RegEx
    ID_PATTERN = re.compile(r"(\d+)")

    # [ESKİ PAYLOAD KALDIRILDI] TEST_IDS listesi artık PayloadGenerator'dan çekilecektir.
    # TEST_IDS = [1, 2, 10, 100, 9999]

    # IDOR tespiti için minimum içerik boyutu veya içerik değişim eşiği
    CONTENT_DIFF_THRESHOLD = 50 # Düşürüldü

    # Hassas anahtar kelimeler – TÜRKÇE + İNGİLİZCE (FAZ 24 GÜNCELLEMESİ)
    SENSITIVE_KEYWORDS = [
        "email", "profile", "address", "user_id", "secret", "private", "balance",
        "e-posta", "eposta", "tc kimlik", "tckn", "tcno", "telefon", "adres",
        "şifre", "password", "hesap", "account", "sipariş", "order", "fatura",
        "ödeme", "kart", "iban", "bakiye", "kredi", "borç", "kargo", "delivery",
        "admin", "root", "token", "key", "auth", "session", "invoice"
    ]

    # --- WAF/FIREWALL TESPİT SABİTLERİ ---
    WAF_STATUS_CODES = [403, 429, 302]  # 403 Forbidden, 429 Too Many Requests, 302/Redirection (Captcha)
    WAF_HEADERS = [
        "Server",
        "X-WAF",
        "X-Sucuri-ID",
        "CF-RAY",
        "X-Cache",
        "Google-Proxy-Tracking",  # Cloudflare ve Google başlıkları
        "X-Cache-Status",
        "X-CDN",
        "X-Firewall-Detection",
        "X-Content-Encoded-By",
        "X-Request-ID",  # Generic Request IDs
        "Cdn-Cache-Status",
    ]
    WAF_CONTENT_KEYWORDS = ["unusual traffic", "captcha", "security check", "access denied", "blocked"]
    # -------------------------------------------

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
            # KRİTİK KONTROL: PayloadGenerator'ın varlığını kontrol et
            if not hasattr(self, 'payload_generator'):
                self.log(f"[{self.category}] Payload Generator objesi bulunamadı. Tarama atlandı.", "CRITICAL")
                completed_callback()
                return
            
            # 1. URL'yi parçalara ayır ve keşif parametrelerini topla
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)

            # V7.0 ENTEGRASYON: Tüm girdi noktalarını (URL + Keşfedilenler) birleştir
            discovered_params: Set[str] = getattr(self, "discovered_params", set())

            # Keşfedilen parametreleri, mevcut query_params'a ekle (varsayılan bir değerle)
            all_target_params: Set[str] = set(query_params.keys())

            for param_name in discovered_params:
                if param_name not in all_target_params:
                    # Keşfedilen parametreye varsayılan sayısal ID atanır
                    query_params[param_name] = ["1"]
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

            # Test edilecek base URL'yi oluştur
            base_url_parts = list(parsed_url)
            base_url_parts[4] = urlencode(query_params, doseq=True)
            base_url = urlunparse(base_url_parts)

            # 2. ORİJİNAL İSTEK (Kontrol)
            original_content, original_status_code, original_protection = await self._fetch_url(
                base_url, session, is_control=True
            )

            if original_content is None:
                self.add_result(
                    self.category,
                    "INFO",
                    "INFO: Orijinal yanıt alınamadığı için IDOR taraması atlandı.",
                    0,
                )
                completed_callback()
                return

            if original_protection:
                self.log(
                    f"[{self.category}] Orijinal Kontrol Yanıtında Koruma Tespiti: "
                    f"{original_protection}. IDOR sonuçları FP'ye karşı filtrelenecek.",
                    "WARNING",
                )

            tasks: List[asyncio.Task] = []
            
            # --- FAZ 36 KRİTİK GÜNCELLEME: ID Payload'larını Generator'dan çek ---
            try:
                test_ids: List[int] = self.payload_generator.generate_idor_test_ids()
            except AttributeError:
                self.log(f"[{self.category}] KRİTİK: PayloadGenerator.generate_idor_test_ids() bulunamadı. Payload üretilemedi.", "CRITICAL")
                completed_callback()
                return

            # 3. FUZZING: Her parametreyi TEST_IDS ile test et.
            for param in all_target_params:
                original_value = query_params.get(param, [""])[0]

                # Sadece sayısal değerler içeriyorsa test et
                id_match = self.ID_PATTERN.search(original_value)
                if not id_match:
                    continue

                original_id_str = id_match.group(1)
                try:
                    original_id = int(original_id_str)
                except ValueError:
                    continue

                for test_id in test_ids: # TEST_IDS yerine test_ids kullanıldı
                    if test_id == original_id:
                        continue  # Kendini test etme

                    # Yeni ID değerini orijinal parametreye yerleştir
                    new_value = original_value.replace(original_id_str, str(test_id), 1)

                    tasks.append(
                        self._test_idor_payload(
                            base_url,
                            param,
                            original_value,
                            new_value,
                            session,
                            parsed_url,
                            query_params,
                            original_content,
                            original_status_code,
                        )
                    )

            total_tasks = len(tasks)
            self.log(
                f"[{self.category}] Toplam {total_tasks} farklı IDOR kombinasyonu taranacak "
                f"(Gelişmiş Çok Katmanlı Doğrulama).",
                "INFO",
            )

            if tasks:
                await asyncio.gather(*tasks)

        except Exception as e:
            error_message = f"Kritik Hata: {type(e).__name__} ({str(e)})"
            score_deduction = self._calculate_score_deduction("CRITICAL")
            self.add_result(self.category, "CRITICAL", error_message, score_deduction)
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
        """
        WAF/Firewall/Anti-Bot tarafından korunan bir yanıtı tespit eder.
        """
        # 1. Durum Kodu Kontrolü
        if status_code in self.WAF_STATUS_CODES:
            if status_code == 403:
                return "WAF/Firewall (403 Forbidden)"
            elif status_code == 429:
                return "Rate Limit (429 Too Many Requests)"
            elif status_code == 302 and any(
                k.lower() in content.lower() for k in ["captcha", "security check"]
            ):
                return "Captcha/Anti-Bot (302 Redirect)"

        # 2. Başlık Kontrolü
        header_keys = [h.lower() for h in headers.keys()]
        for waf_header in self.WAF_HEADERS:
            if waf_header.lower() in header_keys:
                return f"Koruma Başlığı Tespit Edildi ({waf_header})"

        # 3. İçerik Kontrolü
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
        """
        URL'yi çeker ve içeriği/durum kodunu/koruma durumunu döndürür.
        """
        protection_status = None
        try:
            # İSTEK SAYACI: HTTP isteği yapmadan önce sayacı artır.
            self.request_callback()

            # Modülün kendi semaforunu kullanarak concurrency limitine uy
            async with getattr(self, "module_semaphore", asyncio.Semaphore(self.PER_MODULE_LIMIT)):
                async with session.get(
                    url,
                    allow_redirects=True,
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as res:
                    content = await res.text()
                    protection_status = self._detect_protection_response(res.status, res.headers, content)
                    return content, res.status, protection_status

        except aiohttp.client_exceptions.ClientConnectorError:
            self.log(f"[{self.category}] Bağlantı Hatası: {url}", "WARNING")
            return None, None, None
        except Exception:
            return None, None, None

    # -------------------------------------------------------------------------
    # FULL SIMILARITY ENGINE (SimHash + Dice + Entropy Shift)
    # -------------------------------------------------------------------------
    def _tokenize(self, text: str) -> List[str]:
        """
        Basit, güvenli ve hızlı tokenizer.
        Harf, rakam, '_' ve '.' içeren kelimeleri çeker. (Case-insensitive)
        """
        if not text:
            return []
        # KRİTİK DÜZELTME: @ ve . de kelime içinde kalmalı (email/domain için)
        return re.findall(r"[A-Za-z0-9_@\.-]+", text.lower())

    def _simhash(self, tokens: List[str], bit_size: int = 64) -> int:
        """
        SimHash fingerprint hesaplar.
        64-bit fingerprint, büyük body'lerde bile çok hızlı karşılaştırma sağlar.
        """
        if not tokens:
            return 0

        v = [0] * bit_size
        for token in tokens:
            # Stabil hash için md5 kullanıyoruz
            h = int(hashlib.md5(token.encode("utf-8")).hexdigest(), 16)
            for i in range(bit_size):
                bit = (h >> i) & 1
                v[i] += 1 if bit else -1

        fingerprint = 0
        for i in range(bit_size):
            if v[i] > 0:
                fingerprint |= 1 << i
        return fingerprint

    def _simhash_similarity(self, tokens_a: List[str], tokens_b: List[str], bit_size: int = 64) -> float:
        """
        SimHash tabanlı benzerlik skoru (0.0–1.0).
        1.0 = tamamen aynı, 0.0 = tamamen farklı.
        """
        if not tokens_a or not tokens_b:
            return 0.0

        h1 = self._simhash(tokens_a, bit_size)
        h2 = self._simhash(tokens_b, bit_size)

        x = h1 ^ h2
        # Hamming distance
        dist = bin(x).count("1")
        return 1.0 - (dist / float(bit_size))

    def _dice_coefficient(self, tokens_a: List[str], tokens_b: List[str]) -> float:
        """
        Dice Similarity (0.0–1.0) – set tabanlı hızlı benzerlik.
        """
        if not tokens_a or not tokens_b:
            return 0.0

        set_a = set(tokens_a)
        set_b = set(tokens_b)

        if not set_a or not set_b:
            return 0.0

        overlap = len(set_a & set_b)
        total = len(set_a) + len(set_b)
        if total == 0:
            return 0.0

        return (2.0 * overlap) / float(total)

    def _shannon_entropy(self, text: str) -> float:
        """
        Shannon Entropy (bit/karakter).
        """
        if not text:
            return 0.0

        length = len(text)
        freq: Dict[str, int] = {}
        for ch in text:
            freq[ch] = freq.get(ch, 0) + 1

        entropy = 0.0
        for count in freq.values():
            p = count / float(length)
            entropy -= p * math.log2(p)

        return entropy

    def _compute_similarity_metrics(self, original: str, test: str) -> Dict[str, float]:
        """
        FULL similarity analizini yapar ve bir metrik seti döndürür.
        """
        tokens_orig = self._tokenize(original)
        tokens_test = self._tokenize(test)

        len_diff = abs(len(test) - len(original))

        simhash_sim = self._simhash_similarity(tokens_orig, tokens_test)
        dice_sim = self._dice_coefficient(tokens_orig, tokens_test)

        ent_orig = self._shannon_entropy(original)
        ent_test = self._shannon_entropy(test)
        entropy_shift = abs(ent_orig - ent_test)

        # Entropy shift normalizasyonu (0–1 arası)
        entropy_norm = max(0.0, min(1.0, entropy_shift / 4.0))

        # 0.0–1.0 arası toplam benzerlik skoru
        combined_similarity = (
            simhash_sim * 0.45
            + dice_sim * 0.35
            + (1.0 - entropy_norm) * 0.20
        )

        # Fark skoru: 0.0 = aynı, 1.0 = tamamen farklı
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
        metrics: Optional[Dict[str, float]] = None,
    ) -> Tuple[bool, str]:
        """
        IDOR tespiti için AKILLI ANALİZ V2.0:
        
        Dönüş: (is_idor_suspect, severity_level)
        """
        if not original_content or not test_content:
            return False, ""

        if metrics is None:
            metrics = self._compute_similarity_metrics(original_content, test_content)

        len_diff = metrics.get("len_diff", 0.0)
        diff_score = metrics.get("diff_score", 0.0)

        # 1) JSON Kontrolü: Eğer yanıt JSON ise, yapısal benzerlik daha önemlidir.
        is_json = test_content.strip().startswith("{") and test_content.strip().endswith("}")
        
        # 2) Hassas kelime filtresi (Puan Artırıcı)
        test_content_lower = test_content.lower()
        sensitive_hit = any(keyword in test_content_lower for keyword in self.SENSITIVE_KEYWORDS)

        # --- KARAR MEKANİZMASI ---

        # Senaryo A: Sayfalar ÇOK benziyor (diff < 0.02) -> Muhtemelen IDOR yok (Aynı içerik).
        if diff_score < 0.02: 
            return False, ""

        # Senaryo B: Sayfalar ÇOK farklı (diff > 0.90) -> Muhtemelen Error Page (404 disguised as 200).
        if diff_score > 0.90:
            return False, ""

        # Senaryo C: "SWEET SPOT" (Yapı benzer, içerik farklı) -> IDOR ADAYI
        # diff_score 0.02 ile 0.90 arasında.
        
        # C1: Hassas kelime var -> KESİN IDOR (CRITICAL)
        if sensitive_hit:
            return True, "CRITICAL"
        
        # C2: JSON yanıtı ve belirgin fark var -> YÜKSEK OLASILIK (HIGH)
        # JSON'da kelime yakalamak zordur (key'ler değişmeyebilir), diff'e güveniriz.
        if is_json and diff_score > 0.05:
            return True, "HIGH"

        # C3: HTML yanıtı, belirgin fark var ama hassas kelime yok -> ŞÜPHELİ (WARNING)
        # Sadece farka dayalı uyarı.
        if diff_score > 0.10: # Fark eşiği 0.35'ten 0.10'a düşürüldü.
            return True, "WARNING"

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
        """
        Değiştirilmiş ID ile istek gönderir ve FULL similarity engine ile doğrulamayı uygular.
        """
        # Test URL'sini oluştur
        test_params = query_params.copy()
        test_params[param] = [new_value]

        test_query = urlencode(test_params, doseq=True)
        test_url_parts = list(parsed_url)
        test_url_parts[4] = test_query
        test_url = urlunparse(test_url_parts)

        # Test isteğini gönder
        test_content, test_status_code, test_protection = await self._fetch_url(
            test_url, session, is_control=False
        )

        if test_content is None:
            return

        # Koruma yanıtı ise IDOR sayma, sadece logla
        if test_protection:
            self.log(
                f"[{self.category}] DİKKAT: IDOR testi sırasında koruma yanıtı "
                f"({test_protection}) alındı. Bu test koruma tarafından engellenmiş olabilir.",
                "WARNING",
            )
            return

        # Durum kodu bazlı erken çıkış (Sadece bariz hataları ele)
        if original_status_code == 200 and test_status_code in [401, 403, 404, 500]:
            return

        # FULL similarity metrikleri
        metrics = self._compute_similarity_metrics(original_content, test_content)
        len_diff = metrics["len_diff"]
        diff_score = metrics["diff_score"]

        # YENİ: Akıllı Analiz
        is_idor, severity = self._analyze_idor_result(test_content, original_content, metrics=metrics)

        if is_idor:
            score_deduction = self._calculate_score_deduction(severity)
            
            msg_prefix = "IDOR TESPİTİ" if severity == "CRITICAL" else "IDOR ŞÜPHESİ"
            
            self.add_result(
                self.category,
                severity,
                (
                    f"{msg_prefix}: Parametre '{param}', "
                    f"ID Değişimi: {original_value} -> {new_value}. "
                    f"İçerik farkı: {int(len_diff)} byte. "
                    f"Fark Skoru: {diff_score:.2f} (0=Aynı, 1=Farklı)"
                ),
                score_deduction,
            )