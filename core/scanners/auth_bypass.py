# path: core/scanners/auth_bypass.py

import aiohttp
import asyncio
from typing import Callable, List, Dict, Tuple
from .base_scanner import BaseScanner
from urllib.parse import urljoin, urlparse
from difflib import SequenceMatcher # YENİ: Benzerlik analizi için

class AuthBypassScanner(BaseScanner):
    """
    Yönetim panelleri ve hassas dizinler için yetki atlatma (Auth Bypass) ve
    görünmez erişim noktası (Ghost Key) taraması yapar.
    
    V21.0 UPDATE: Cloudflare/Next.js Soft 404'lerini ayıklamak için geliştirilmiş
    Difflib Benzerlik Analizi ve WAF İmzası kontrolü eklendi (FP-Guard).
    """

    # KRİTİK DÜZELTME: Sınıf seviyesinde TIMEOUT tanımı eklendi
    TIMEOUT = 12

    def __init__(self, logger, results_callback, request_callback: Callable[[], None]):
        super().__init__(logger, results_callback, request_callback)
        self.max_depth = 2
        
        # WAF ve Hata Sayfası İmzaları (False Positive Önleme)
        self.waf_signatures = [
            "Attention Required! | Cloudflare",
            "Access denied",
            "Error 1020",
            "Ray ID:",
            "DDoS protection by Cloudflare",
            "403 Forbidden",
            "404 Not Found",
            "An error occurred while processing your request",
            "WAF",
            "Security Check",
            "Human Verification",
            "Challenge",
            "banned",
            "blocked",
            "rejected"
        ]

        # Potansiyel Yönetim Yolları
        self.admin_paths = [
            "/admin", "/administrator", "/dashboard", "/login", "/wp-admin",
            "/cpanel", "/config", "/api/admin", "/user/admin", "/root",
            "/system", "/auth", "/panel", "/controlpanel", "/secure"
        ]

        # Bypass Teknikleri (Payloads)
        self.bypass_payloads = [
            "//",               # Çift slash (Normalization hatası)
            "/%2e/",            # URL Encoded dot
            "/%2e%2e/",         # Double dot encoded
            "/.",               # Dot suffix
            "..;/",             # Tomcat path traversal
            "/./",              # Current dir
            "?",                # Query trick
            "%20",              # Space trick
            "%09",              # Tab trick
            "/.git",            # Git exposure (Bazen bypass sağlar)
            "/static/..%2f",    # Static files üzerinden traversal
            ";/admin"           # Semicolon injection
        ]
        
        # Baseline (Referans) verisi
        self.baseline_content = ""
        self.baseline_status = 0
        self.baseline_size = 0

    @property
    def name(self):
        return "Auth Bypass & Ghost Key Scanner"

    @property
    def category(self):
        return "AUTH_BYPASS"

    def _is_waf_page(self, content: str, status: int) -> bool:
        """
        Yanıtın bir WAF engelleme sayfası olup olmadığını kontrol eder.
        """
        # Status kodu kontrolü (403/406/429 kesin WAF işaretidir)
        if status in [403, 406, 429]:
            return True
            
        content_lower = content.lower()
        for sig in self.waf_signatures:
            if sig.lower() in content_lower:
                return True
        return False

    def _calculate_similarity(self, content1: str, content2: str) -> float:
        """
        İki HTML içeriği arasındaki benzerlik oranını (0.0 - 1.0) döndürür.
        """
        # Performans için sadece ilk 2000 karakteri karşılaştır
        s = SequenceMatcher(None, content1[:2000], content2[:2000])
        return s.ratio()

    async def scan(self, url: str, session: aiohttp.ClientSession, completed_callback: Callable[[], None]):
        """
        Asenkron tarama mantığı.
        """
        self.log(f"[{self.category}] Hedef üzerinde yetkilendirme kontrolleri test ediliyor...", "INFO")
        
        # 1. BASELINE AL (Referans Noktası)
        # Kök dizine veya rastgele bir olmayan yola istek atarak sunucunun "Erişim Yok" tepkisini öğren.
        try:
            # Rastgele, olmayan bir yola istek atarak 404/403 baseline'ını al
            baseline_url = urljoin(url, "/non_existent_path_for_baseline_" + str(self.request_callback.__hash__()))
            
            # self.TIMEOUT kullanıldı
            response, latency = await self._throttled_request(session, "GET", baseline_url, timeout=self.TIMEOUT)
            
            if response:
                self.baseline_content = await response.text()
                self.baseline_status = response.status
                self.baseline_size = len(self.baseline_content)
                self.log(f"[{self.category}] Baseline Alındı. Status: {self.baseline_status}, Boyut: {self.baseline_size} byte", "INFO")
            else:
                self.log(f"[{self.category}] Baseline alınamadı. Tarama iptal.", "WARNING")
                completed_callback()
                return
        except Exception as e:
            self.log(f"[{self.category}] Baseline hatası: {e}", "ERROR")
            completed_callback()
            return

        # 2. KRİTİK YOL ANALİZİ
        tasks = []
        semaphore = getattr(self, 'module_semaphore', asyncio.Semaphore(5))

        for path in self.admin_paths:
            full_url = urljoin(url, path)
            tasks.append(self._check_bypass(session, full_url, semaphore))

        await asyncio.gather(*tasks)
        
        completed_callback()

    async def _check_bypass(self, session: aiohttp.ClientSession, target_url: str, semaphore: asyncio.Semaphore):
        """
        Tek bir hedef yol için bypass tekniklerini dener.
        """
        async with semaphore:
            # STOP KONTROLÜ
            if hasattr(self, 'engine_instance') and self.engine_instance.stop_requested:
                return

            for payload in self.bypass_payloads:
                # Payload'ı URL'e enjekte et
                if target_url.endswith("/"):
                    test_url = target_url[:-1] + payload
                else:
                    test_url = target_url + payload

                try:
                    # self.TIMEOUT kullanıldı
                    response, latency = await self._throttled_request(session, "GET", test_url, timeout=self.TIMEOUT) 
                    if not response:
                        continue

                    content = await response.text()
                    status = response.status
                    size = len(content)

                    # --- AKILLI DOĞRULAMA (FALSE POSITIVE KILLER) ---

                    # 1. WAF Kontrolü: Yanıt bir engelleme sayfasıysa direkt atla
                    if self._is_waf_page(content, status):
                        continue

                    # 2. Baseline Kontrolü: Benzerlik %85'in üzerindeyse içerik baseline ile aynı kabul edilir.
                    similarity = self._calculate_similarity(content, self.baseline_content)
                    
                    # KRİTİK FP GUARD (Next.js/Vercel Soft 404 Filtresi):
                    # Eğer Status 200 VEYA 404 ise (Soft 404 sinyali) VE içerik boyutu
                    # baseline boyutuna çok yakınsa (%5 sapma içinde) VE benzerlik çok yüksekse, FP olarak ele.
                    if status in [200, 404] and abs(size - self.baseline_size) / max(self.baseline_size, 1) < 0.05:
                        if similarity > 0.85: # Baseline'a çok benziyor
                            self.log(f"[{self.category}] FP ATLANDI: Soft 404 (Next.js/Baseline Similarity: {similarity:.2f}). Test URL: {test_url}", "INFO")
                            continue


                    # 3. Gerçek BYPASS (Yüksek Güvenilirlik):
                    # Test status 200 ve similarity çok düşük (yani tamamen farklı bir sayfa yüklendi) 
                    # VEYA Test status 200 ve Baseline 403/401 idi.
                    is_real_bypass = False
                    
                    if status == 200 and self.baseline_status in [403, 401]:
                        # Yetki Gerekli Sayfadan Başarılı Yanıt Alındı
                        is_real_bypass = True
                        bypass_confidence = "CRITICAL"
                    
                    elif status == 200 and similarity < 0.70:
                        # Baseline 404 bile olsa, 200 döndü ve içerik yeni -> Gizli dosya/dizin ifşası
                        is_real_bypass = True
                        bypass_confidence = "HIGH"

                    elif status in [301, 302]:
                        # Yetkilendirilmiş bir alana yönlendirme (örn: /login -> /dashboard)
                        location = response.headers.get("Location", "").lower()
                        if "dashboard" in location or "panel" in location or ("admin" in location and "login" not in location):
                            is_real_bypass = True
                            bypass_confidence = "HIGH"
                            
                    
                    if is_real_bypass:
                        msg = f"BYPASS ŞÜPHESİ ({bypass_confidence}): {test_url} [Status: {status}, Size: {size}, Sim: {similarity:.2f}]"
                        level = "WARNING"
                        
                        if bypass_confidence == "CRITICAL" or bypass_confidence == "HIGH":
                            level = "HIGH"
                            
                            # İçerik Kontrolü ile kesinleştir (Admin kelimesi vb.)
                            if "admin" in content.lower() or "dashboard" in content.lower() or "cpanel" in content.lower():
                                level = "CRITICAL"
                                msg = f"KRİTİK YETKİ ATLAMA: {test_url} [Admin Paneli İfşası Tespiti]"
                                
                        # Eğer kesin BYPASS (Status 200/201/302 ve LOW Similarity) ise CRITICAL'e yükseltme
                        if status == 200 and similarity < 0.5:
                             level = "CRITICAL"
                             msg = f"KRİTİK YETKİ ATLAMA: {test_url} [İçerik Tamamen Farklı ({similarity:.2f} Sim)]"


                        self.add_result(self.category, level, msg, self._calculate_score_deduction(level))
                        self.log(f"[{self.category}] {msg}", "SUCCESS")

                except Exception as e:
                    self.log(f"[{self.category}] İstek Hatası: {type(e).__name__}", "WARNING")