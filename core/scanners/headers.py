# path: core/scanners/headers.py

import aiohttp # Asenkron HTTP istekleri için eklendi
import aiohttp.client_exceptions
from typing import Callable # Completed callback'in tipini belirtmek için eklendi
import re # Set-Cookie ayrıştırması için eklendi

from core.scanners.base_scanner import BaseScanner

class HeadersScanner(BaseScanner):
    """
    HTTP Yanıt Başlıklarını (Headers) tarar ve temel güvenlik protokollerini
    (HSTS, CSP, X-Powered-By ifşası, Oturum Güvenliği, CORS vb.) kontrol eder.
    V19.1: Proaktif Güvenlik Analizi (Headers Hardening) ile güçlendirildi.
    """
    
    # YENİ: request_callback argümanını alacak şekilde __init__ güncellendi
    def __init__(self, logger, results_callback, request_callback: Callable[[], None]):
        super().__init__(logger, results_callback, request_callback)
    
    @property
    def name(self):
        return "HTTP Başlık Analizi ve Güvenlik Denetimi"

    @property
    def category(self):
        return "HEADERS"
        
    async def scan(self, url: str, session: aiohttp.ClientSession, completed_callback: Callable[[], None]):
        """
        Headers tarama mantığını uygular (Asenkron).
        completed_callback, BaseScanner'dan gelen yeni argümandır.
        """
        try:
            # İSTEK SAYACI: HTTP isteği yapmadan önce sayacı artır.
            self.request_callback()
            
            # aiohttp ile asenkron GET isteği
            async with session.get(url, allow_redirects=True) as res:
                
                # Sadece başlıkları alıyoruz
                headers = res.headers 

                # 1. X-Powered-By Kontrolü (Bilgi İfşası)
                self._check_powered_by(headers)

                # 2. Content-Security-Policy (XSS Koruması) Kontrolü
                self._check_csp(headers)
                    
                # 3. Strict-Transport-Security (HSTS/HTTPS Zorlama) Kontrolü
                self._check_hsts(headers)
                
                # 4. X-Frame-Options Kontrolü (Clickjacking Koruması)
                self._check_xfo(headers)

                # 5. Oturum Güvenliği Kontrolü (HttpOnly / Secure)
                # NOT: Bu kritik bir bulgudur ve KAPSAM DIŞI DEĞİLDİR.
                self._check_session_security(headers)

                # 6. YENİ (V19.1): CORS Analizi
                self._check_cors(headers)

                # 7. YENİ (V19.1): Önbellek Zehirlenmesi Kontrolü
                self._check_cache_poisoning(headers)

                # 8. YENİ (V19.1): Modern Güvenlik Başlıkları
                self._check_modern_security_headers(headers)

        except aiohttp.client_exceptions.ClientConnectorError as re:
             # Ağ hatası, DNS hatası veya bağlantı zaman aşımı
             score_deduction = self._calculate_score_deduction("CRITICAL")
             self.add_result(self.category, "CRITICAL", f"Sunucuya erişilemedi/Bağlantı Hatası: {type(re).__name__}", score_deduction)
        
        except aiohttp.ClientError as ce:
             # aiohttp tarafından atılan diğer tüm istemci hataları (Timeout, ResponseError vb.)
             score_deduction = self._calculate_score_deduction("CRITICAL")
             self.add_result(self.category, "CRITICAL", f"aiohttp İstemci Hatası: {type(ce).__name__}", score_deduction)
             
        except Exception as e:
             # Beklenmeyen diğer hatalar (Örn: Log kaydınızdaki AttributeError)
             score_deduction = self._calculate_score_deduction("CRITICAL")
             self.add_result(self.category, "CRITICAL", f"Kritik Hata: {type(e).__name__} ({str(e)})", score_deduction)

        # İşlem tamamlandığında motoru bilgilendir.
        completed_callback()

    # --- Sınıf İçinde Olması Gereken Yardımcı Metotlar ---
    
    def _check_session_security(self, headers: dict):
        """
        Set-Cookie başlıklarını kontrol eder ve HttpOnly / Secure bayraklarının eksikliğini raporlar.
        Playtika Notu: Oturum Güvenliği Kapsam Dışı Değil (BBH Kuralı 1. Seviye için geçerli).
        """
        cookie_headers = headers.getall('Set-Cookie', []) 
        
        if not cookie_headers:
            self.add_result(self.category, "INFO", "BİLGİ: Yanıtta Set-Cookie başlığı bulunamadı (Oturum çerezleri ayarlanmıyor olabilir).", 0)
            return

        all_cookies_secure = True
        # Oturum güvenliği kritiktir, SRP puanını koru (WARNING/2)
        score_deduction = self._calculate_score_deduction("WARNING") // 2 
        
        for cookie_header in cookie_headers:
            cookie_name_match = re.search(r'^\s*([^=;]+)=', cookie_header)
            cookie_name = cookie_name_match.group(1).strip() if cookie_name_match else "Bilinmeyen Çerez"

            is_http_only = "httponly" in cookie_header.lower()
            is_secure = "secure" in cookie_header.lower()
            
            # Playtika Notu: Eksik HttpOnly veya Secure bayrakları hariç tutulmuş.
            # Ancak biz bu bilgiyi loglayacağız (INFO seviyesinde SRP: 0.0)
            
            if not is_http_only:
                all_cookies_secure = False
                self.add_result(self.category, "INFO", f"[BBH Filtresi] UYARI: Çerez '{cookie_name}'de HttpOnly bayrağı eksik (Kapsam Dışı/INFO).", 0)

            if not is_secure:
                all_cookies_secure = False
                self.add_result(self.category, "INFO", f"[BBH Filtresi] UYARI: Çerez '{cookie_name}'de Secure bayrağı eksik (Kapsam Dışı/INFO).", 0)
                
            if is_http_only and is_secure:
                self.log(f"[{self.category}] Çerez '{cookie_name}' güvenli ayarlanmış (HttpOnly, Secure).", "INFO")
        
        if all_cookies_secure:
             self.add_result(self.category, "SUCCESS", "GÜVENLİ: Tüm oturum çerezleri güvenli bayraklarla ayarlanmış.", 0)

    def _check_powered_by(self, headers):
        """
        X-Powered-By Kontrolü. Playtika kapsamında Banner Tanımlama sorunları kapsam dışıdır.
        SRP Düşüşü SIFIRLANIR.
        """
        if 'X-Powered-By' in headers:
            technology = headers['X-Powered-By']
            # SRP DÜŞÜŞÜ SIFIRLANDI
            self.add_result(self.category, "INFO", f"[BBH Filtresi] RİSK: 'X-Powered-By' ifşası tespit edildi! ({technology}) (Kapsam Dışı/INFO)", 0)
        else:
            self.add_result(self.category, "SUCCESS", "GÜVENLİ: Teknoloji bilgisi (X-Powered-By) gizlenmiş.", 0)

    def _check_csp(self, headers):
        """
        Content-Security-Policy Kontrolü. Playtika kapsamında CSP eksikliği kapsam dışıdır.
        SRP Düşüşü SIFIRLANIR.
        """
        if 'Content-Security-Policy' not in headers:
            # SRP DÜŞÜŞÜ SIFIRLANDI
            self.add_result(self.category, "INFO", "[BBH Filtresi] UYARI: Content-Security-Policy (CSP) bulunamadı (Kapsam Dışı/INFO).", 0)
        else:
            self.add_result(self.category, "SUCCESS", "GÜVENLİ: CSP politikası aktif.", 0)
            
    def _check_hsts(self, headers):
        """
        Strict-Transport-Security (HSTS) Kontrolü. Playtika kapsamında HSTS eksikliği kapsam dışıdır.
        SRP Düşüşü SIFIRLANIR.
        """
        if 'Strict-Transport-Security' not in headers:
            # SRP DÜŞÜŞÜ SIFIRLANDI
            self.add_result(self.category, "INFO", "[BBH Filtresi] UYARI: HSTS (HTTPS Zorlama) başlığı eksik (Kapsam Dışı/INFO).", 0)
        else:
            self.add_result(self.category, "SUCCESS", "GÜVENLİ: HSTS aktif.", 0)

    def _check_xfo(self, headers):
        """
        X-Frame-Options Kontrolü. Playtika kapsamında diğer güvenlik başlıkları kapsam dışıdır.
        SRP Düşüşü SIFIRLANIR.
        """
        if 'X-Frame-Options' not in headers:
            # SRP DÜŞÜŞÜ SIFIRLANDI
            self.add_result(self.category, "INFO", "[BBH Filtresi] UYARI: X-Frame-Options başlığı eksik (Kapsam Dışı/INFO).", 0)
        else:
            self.add_result(self.category, "SUCCESS", "GÜVENLİ: X-Frame-Options aktif.", 0)

    # --- YENİ (V19.1) METOTLAR ---

    def _check_cors(self, headers):
        """
        CORS yapılandırmasını analiz eder. Sadece kritik misconfiguration'ları raporla.
        """
        acao = headers.get('Access-Control-Allow-Origin', '')
        acac = headers.get('Access-Control-Allow-Credentials', 'false').lower()

        if acao == '*':
            if acac == 'true':
                # Bu kritik bir güvenlik açığıdır (CORS Misconfiguration) - Kapsam Dışı Değil
                score = self._calculate_score_deduction("CRITICAL")
                self.add_result(self.category, "CRITICAL", "KRİTİK: CORS 'Access-Control-Allow-Origin: *' ve 'Credentials: true' birlikte kullanılmış!", score)
            else:
                # Wildcard tek başına BBH'de genellikle kapsam dışı/düşüktür. INFO olarak düşürelim.
                self.add_result(self.category, "INFO", "[BBH Filtresi] RİSK: CORS 'Access-Control-Allow-Origin: *' (Wildcard) kullanımı (INFO).", 0)
        elif acao == 'null':
            # Null origin bypass riski. INFO olarak düşürelim.
            self.add_result(self.category, "INFO", "[BBH Filtresi] RİSK: CORS 'Access-Control-Allow-Origin: null' kullanımı (INFO).", 0)
        elif acao:
            self.add_result(self.category, "INFO", f"BİLGİ: CORS Origin kısıtlaması aktif: {acao}", 0)

    def _check_cache_poisoning(self, headers):
        """
        Önbellek zehirlenmesi riskini (Vary başlığı eksikliği) kontrol eder.
        """
        # Dinamik içerik sunan sayfalarda Vary başlığı önemlidir.
        cache_control = headers.get('Cache-Control', '').lower()
        vary = headers.get('Vary', '')

        if 'public' in cache_control and not vary:
             # Cache Poisoning potansiyeli INFO olarak kalır.
             self.add_result(self.category, "INFO", "BİLGİ: 'Vary' başlığı eksik. Cache Poisoning potansiyeli olabilir (Cache-Control: public).", 0)

    def _check_modern_security_headers(self, headers):
        """
        Modern güvenlik başlıklarını (Permissions, Referrer, Content-Type) kontrol eder.
        Playtika kapsamında 'X-Content-Type-Options' ve 'X-XSS-Protection' eksikliği kapsam dışıdır.
        SRP Düşüşü SIFIRLANIR.
        """
        # 1. X-Content-Type-Options
        if 'X-Content-Type-Options' not in headers or headers['X-Content-Type-Options'].lower() != 'nosniff':
            # SRP DÜŞÜŞÜ SIFIRLANDI
            self.add_result(self.category, "INFO", "[BBH Filtresi] BİLGİ: 'X-Content-Type-Options: nosniff' eksik (Kapsam Dışı/INFO).", 0)

        # 2. Referrer-Policy
        if 'Referrer-Policy' not in headers:
            self.add_result(self.category, "INFO", "BİLGİ: 'Referrer-Policy' başlığı eksik. Kullanıcı gizliliği için ayarlanmalı.", 0)
        
        # 3. Permissions-Policy (Eski Feature-Policy)
        if 'Permissions-Policy' not in headers and 'Feature-Policy' not in headers:
             self.add_result(self.category, "INFO", "BİLGİ: 'Permissions-Policy' başlığı eksik. Kamera/Mikrofon gibi özellikler kısıtlanmamış.", 0)