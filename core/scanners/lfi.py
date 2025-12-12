# path: core/scanners/lfi.py

import aiohttp
import aiohttp.client_exceptions
import asyncio
import math
import random
import re
import base64 # KRİTİK EKLENTİ: PHP Wrapper (Base64) decode için
from typing import Callable, Dict, List, Tuple
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

from core.scanners.base_scanner import BaseScanner


class LFIScanner(BaseScanner):
    """
    [AR-GE v2.2 - FAZ 36 OPTİMİZASYON]
    Yeni Nesil Local File Inclusion / Path Traversal Tarayıcı
    --------------------------------------------------------
    V2.2: Payload üretimi PayloadGenerator'a (AI/Simülasyon destekli) devredildi.
    FP oranını düşüren sinyal güçlendirme (Heuristic Score + Signature) korunuyor.
    """

    # --- ESKİ STATİK PAYLOAD VE PATH LİSTELERİ SİLİNDİ (FAZ 36 OPTİMİZASYON) ---
    # Payload ve SENSITIVE_FILES artık self.payload_generator üzerinden çekiliyor.

    # Hedef dosyalar ve içerik imzaları (signature) (Sadece Signature Kontrolü İçin Sınıf Seviyesinde Tutuldu)
    SENSITIVE_FILES: Dict[str, List[str]] = {
        # Linux (Yüksek Güvenilirlik İmza)
        "/etc/passwd": ["root:x:0:0", "daemon:x:", "/bin/bash"],
        "/etc/shadow": ["root:", ":$"],
        "/etc/hosts": ["127.0.0.1", "localhost"],
        "/proc/self/environ": ["USER=", "PATH="],
        # Log Poisoning Hedefleri (Düşük Güvenilirlikli İmza - Ek Kontrol Gerektirir)
        "/var/log/apache2/access.log": ["GET /", "HTTP/1.1"],
        "/var/log/nginx/access.log": ["GET /", "HTTP/1.1"],
        "/var/log/auth.log": ["session opened"],
        "/var/log/messages": ["kernel:", "error"],
        # Windows
        "C:\\Windows\\win.ini": ["[fonts]", "[extensions]", "[mci extensions]"],
        "C:\\boot.ini": ["[boot loader]", "[operating systems]"],
    }
    # ---------------------------------------------------------------------------

    # Genel hatalar / WAF / CDN sayfaları → LFI sayma
    BLOCKING_KEYWORDS = [
        "cloudflare",
        "nginx",
        "error 400",
        "400 bad request",
        "403 forbidden",
        "404 not found",
        "the requested url was not found",
        "access denied",
        "request blocked",
        "invalid url",
        "bad request",
    ]

    # LFI hata mesajları (file system error leakage)
    ERROR_LEAK_KEYWORDS = [
        "failed to open stream",
        "no such file or directory",
        "include_path=",
        "warning: include",
        "warning: require",
        "file_get_contents(",
    ]

    # Magic bytes (binary / doküman imzaları)
    MAGIC_BYTES = {
        b"%PDF-": "PDF dokümanı",
        b"\x7fELF": "ELF binary",
        b"PK\x03\x04": "ZIP / DOCX / JAR arşivi",
        b"\xFF\xD8\xFF": "JPEG görüntü",
        b"GIF89a": "GIF görüntü",
        b"ID3": "MP3 Ses",
        b"<?php": "PHP Kodu (RCE Kanıtı)", 
    }

    # Eşzamanlılık limiti (PLAYTIKA UYUMU İÇİN AZALTILDI)
    CONCURRENCY_LIMIT = 5 

    # İstek bazlı hard timeout
    LFI_TIMEOUT = 15

    def __init__(self, logger, results_callback, request_callback: Callable[[], None]):
        super().__init__(logger, results_callback, request_callback)

        # Heuristic için baseline metrikleri
        self.baseline_len: int = 0
        self.baseline_entropy: float = 0.0
        self.baseline_status: int = 0

    @property
    def name(self):
        return "Local File Inclusion / Path Traversal Tarayıcı"

    @property
    def category(self):
        return "LFI"

    # ------------------------------------------------------------------
    # ANA GİRİŞ NOKTASI
    # ------------------------------------------------------------------
    async def scan(
        self,
        url: str,
        session: aiohttp.ClientSession,
        completed_callback: Callable[[], None],
    ):
        try:
            # KRİTİK KONTROL: PayloadGenerator'ın varlığını kontrol et
            if not hasattr(self, 'payload_generator'):
                 self.log(f"[{self.category}] Payload Generator objesi bulunamadı. Tarama atlandı.", "CRITICAL")
                 completed_callback()
                 return
                 
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)

            # Pre-Scan ile bulunmuş parametreler
            discovered_params = getattr(self, "discovered_params", set())
            all_params = set(query_params.keys()) | set(discovered_params)

            # URL'de olmayan ama keşfedilen parametrelere default değer
            for p in discovered_params:
                if p not in query_params:
                    query_params[p] = ["SYNARA_LFI_TEST"]
                    all_params.add(p)

            if not all_params:
                self.add_result(
                    self.category,
                    "INFO",
                    "INFO: LFI/Path Traversal testi için sorgu parametresi bulunamadı.",
                    0,
                )
                completed_callback()
                return

            # Baseline yanıtını al (entropy + length referansı)
            await self._init_baseline(url, session)

            # --- FAZ 36 KRİTİK GÜNCELLEME: Payload Generator'dan Saldırı Yollarını Çek ---
            # Bu, (target_file, payload) tuple'larının Listesini döndürmelidir.
            try:
                # generate_lfi_attack_paths metodu PayloadGenerator'da tanımlanmalıdır.
                file_payloads: List[Tuple[str, str]] = self.payload_generator.generate_lfi_attack_paths()
            except AttributeError:
                 # Hata durumunda (eğer generator henüz güncellenmediyse) boş liste döndür
                 self.log(f"[{self.category}] KRİTİK: PayloadGenerator.generate_lfi_attack_paths() bulunamadı. Payload üretilemedi.", "CRITICAL")
                 completed_callback()
                 return
                 
            semaphore = asyncio.Semaphore(self.CONCURRENCY_LIMIT)
            tasks = []

            base_query = query_params

            param_list = list(all_params)
            
            # Parametre ve Payload'ları birleştirerek görevleri oluştur
            for param in param_list:
                for target_file, payload in file_payloads:
                    # data:// payload'ını sadece data_uri_test ile test et (SADECE BİR KEZ)
                    if payload.startswith("data://") and target_file != "DATA_URI_TEST":
                        continue
                    
                    tasks.append(
                        self._test_single_payload(
                            base_url=url,
                            param=param,
                            target_file=target_file,
                            payload=payload,
                            session=session,
                            parsed=parsed_url,
                            base_query=base_query,
                            semaphore=semaphore,
                        )
                    )

            total_tests = len(tasks)
            self.log(
                f"[{self.category}] Toplam {total_tests} farklı LFI kombinasyonu eş zamanlı taranacak "
                f"(Limit: {self.CONCURRENCY_LIMIT}).",
                "INFO",
            )

            if tasks:
                await asyncio.gather(*tasks)

        except Exception as e:
            msg = f"Kritik Hata: {type(e).__name__} ({e})"
            score = self._calculate_score_deduction("CRITICAL")
            self.add_result(self.category, "CRITICAL", msg, score)
            self.log(f"[{self.category}] {msg}", "CRITICAL")

        completed_callback()

    # ------------------------------------------------------------------
    # Baseline yanıtı (entropy + length) — Heuristic referans
    # ------------------------------------------------------------------
    async def _init_baseline(self, url: str, session: aiohttp.ClientSession):
        """
        Orijinal URL’den tek bir yanıt çekilir ve
        entropy + uzunluk, LFI fark analizinde referans alınır.
        """
        try:
            # Jitter uygula
            if hasattr(self, '_apply_jitter_and_throttle'):
                await self._apply_jitter_and_throttle() 
            await asyncio.sleep(random.uniform(0.05, 0.2))
            
            self.request_callback()

            async with session.get(
                url,
                allow_redirects=True,
                timeout=aiohttp.ClientTimeout(total=self.LFI_TIMEOUT),
            ) as res:
                raw = await res.read()
                self.baseline_len = len(raw)
                self.baseline_status = res.status
                self.baseline_entropy = self._shannon_entropy_bytes(raw)

        except Exception as e:
            self.log(
                f"[{self.category}] Baseline alınamadı, heuristic kısıtlı çalışacak: "
                f"{type(e).__name__} ({e})",
                "WARNING",
            )
            # Baseline sıfır kalır, sadece direkt signature'lara güvenilir.

    # ------------------------------------------------------------------
    # TEK LFI PAYLOAD TESTİ
    # ------------------------------------------------------------------
    async def _test_single_payload(
        self,
        base_url: str,
        param: str,
        target_file: str,
        payload: str,
        session: aiohttp.ClientSession,
        parsed,
        base_query,
        semaphore: asyncio.Semaphore,
    ):
        async with semaphore:
            test_query = {k: list(v) for k, v in base_query.items()}
            test_query[param] = [payload]

            new_parts = list(parsed)
            new_parts[4] = urlencode(test_query, doseq=True)
            test_url = urlunparse(new_parts)

            try:
                # Küçük jitter — WAF & rate-limit dostu
                if hasattr(self, '_apply_jitter_and_throttle'):
                    await self._apply_jitter_and_throttle() 
                await asyncio.sleep(random.uniform(0.1, 0.4))
                self.request_callback()

                async with session.get(
                    test_url,
                    allow_redirects=True,
                    timeout=aiohttp.ClientTimeout(total=self.LFI_TIMEOUT),
                ) as res:
                    status = res.status
                    raw = await res.read()
                    body_len = len(raw)
                    text = raw.decode(errors="ignore")
                    lower = text.lower()

                    if status >= 500:
                        return

                    # WAF / CDN Sayfaları Filtresi (FP Guard)
                    for bad in self.BLOCKING_KEYWORDS:
                        if bad in lower:
                            return

                    # --- 1) Hata mesajı üzerinden LFI leak (directory disclosure vs.) ---
                    for err in self.ERROR_LEAK_KEYWORDS:
                        if err in lower:
                            level = "WARNING"
                            score = self._calculate_score_deduction(level) // 2
                            self.add_result(
                                self.category,
                                level,
                                f"LFI HATA MESAJI: Dosya/dizin hatası ifşa edildi. "
                                f"Param: '{param}', Payload: '{payload}'",
                                score,
                            )
                            return

                    # --- 2) Signature / Wrapper Kontrolü (Sinyal Güçlendirme) ---
                    
                    # A) PHP Wrapper (Base64) Kontrolü
                    is_b64_wrapper = "php://filter" in payload and "base64" in payload.lower()
                    
                    if is_b64_wrapper:
                        # Base64 decode gürültüsünü engellemek için yerel try/except
                        try:
                            # Base64 veri bloğunu bul (en az 50 karakter)
                            b64_match = re.search(r"([a-zA-Z0-9+/]{50,}={0,2})", text)
                            if b64_match:
                                decoded_content = base64.b64decode(b64_match.group(0).encode()).decode(errors='ignore')
                                
                                # Kritik Signature kontrolü (Yüksek güvenilirlikli dosyalar)
                                high_confidence_sig_hit = any(sig.lower() in decoded_content.lower() 
                                                                for target in ["/etc/passwd", "/etc/shadow"]
                                                                for sig in self.SENSITIVE_FILES.get(target, []))
                                
                                if high_confidence_sig_hit:
                                    level = "CRITICAL"
                                    score = self._calculate_score_deduction(level)
                                    self.add_result(
                                        self.category, level,
                                        f"KRİTİK: PHP Wrapper (Base64) ile dosya okundu! Param: '{param}', Hedef: 'High Confidence File'",
                                        score,
                                    )
                                    return
                        except base64.binascii.Error:
                            # KRİTİK: Incorrect padding hatasını sessizce yakala
                            pass 
                        except Exception as e:
                            # Diğer decode hatalarını sessizce yakala
                            pass

                    # B) Normal Signature Kontrolü (YENİ GÜVENİLİRLİK MANTIĞI)
                    signatures = self.SENSITIVE_FILES.get(target_file, [])
                    
                    if signatures:
                        # Eğer çok kritik bir imza eşleşirse (root:x:0:0), direkt raporla
                        is_critical_match = any(sig.lower() in lower and len(sig) > 10 for sig in signatures)
                        
                        if is_critical_match:
                            level = "CRITICAL"
                            score = self._calculate_score_deduction(level)
                            self.add_result(
                                self.category, level,
                                f"KRİTİK: LFI / Path Traversal tespit edildi! Param: '{param}', Hedef Dosya: '{target_file}'",
                                score,
                            )
                            return
                        
                    # --- 3) Heuristic ML-benzeri skor (FP-Guard Eşiği) ---
                    if not self.baseline_len or not self.baseline_entropy:
                        return

                    suspicion_score, magic_label = self._score_lfi_suspicion(
                        raw, body_len
                    )

                    # Güçlü LFI şüphesi (Şüphe Skoru 3.5 ve üzeri olmalı)
                    if suspicion_score >= 3.5:
                        level = "WARNING"
                        score = self._calculate_score_deduction(level)
                        extra = f" (İmza: {magic_label})" if magic_label else ""
                        self.add_result(
                            self.category,
                            level,
                            f"LFI ŞÜPHESİ: Yanıt içeriği baseline'dan ciddi ölçüde farklı. Param: '{param}' (Skor={suspicion_score:.1f}){extra}",
                            score,
                        )

            except (asyncio.TimeoutError, aiohttp.client_exceptions.ClientConnectorError):
                return
            except Exception as e:
                self.log(
                    f"[{self.category}] LFI Test Hatası ({param} → {payload}): "
                    f"{type(e).__name__} ({e})",
                    "WARNING",
                )

    # ------------------------------------------------------------------
    # Heuristic: Entropy + Magic Byte ile LFI Şüphe Skoru
    # ------------------------------------------------------------------
    def _score_lfi_suspicion(self, raw: bytes, body_len: int) -> Tuple[float, str]:
        """
        Baseline ile karşılaştırmalı entropy + boyut farkı + magic byte sinyalleri
        üzerinden ML-benzeri bir şüphe skoru üretir.
        """
        if body_len == 0:
            return 0.0, ""

        entropy = self._shannon_entropy_bytes(raw)
        magic_label = self._detect_magic_bytes(raw)

        score = 0.0

        # 1. Boyut farkı katkısı (Shrinkage en önemlisi)
        if self.baseline_len > 0:
            length_diff_ratio = abs(body_len - self.baseline_len) / float(self.baseline_len)
            
            # Ciddi küçülme (Örn: Log file yerine küçük bir metin dosyası çekme)
            if (body_len < self.baseline_len) and (length_diff_ratio > 0.4):
                score += 2.0
            # Ciddi büyüme (Örn: Binary dosya çekme)
            if (body_len > self.baseline_len) and (length_diff_ratio > 1.0):
                score += 1.0

        # 2. Entropy farkı katkısı
        if self.baseline_entropy > 0.0:
            ratio = entropy / self.baseline_entropy
            # Binary çıktı veya rastgele data → Yüksek Entropi (Ratio > 1.3)
            if ratio > 1.3:
                score += 1.0
            # Text dosyası çıktısı → Düşük Entropi (Ratio < 0.7)
            elif ratio < 0.7:
                score += 0.5


        # 3. Magic bytes tespiti ekstra sinyal
        if magic_label:
            score += 1.0

        return score, magic_label

    # ------------------------------------------------------------------
    # Shannon Entropy (bytes bazlı)
    # ------------------------------------------------------------------
    @staticmethod
    def _shannon_entropy_bytes(data: bytes) -> float:
        if not data:
            return 0.0

        freq = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1

        entropy = 0.0
        length = float(len(data))

        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)

        return entropy

    # ------------------------------------------------------------------
    # Magic Byte Sniffing
    # ------------------------------------------------------------------
    def _detect_magic_bytes(self, raw: bytes) -> str:
        """
        Dosya başındaki magic byte imzalarına göre kabaca
        dosya tipini tahmin eder (PDF, ZIP, ELF, JPEG vs.).
        """
        head = raw[:8] if len(raw) >= 8 else raw
        for sig, label in self.MAGIC_BYTES.items():
            if head.startswith(sig):
                return label
        return ""