# path: core/scanners/waf_detector.py

import aiohttp
import asyncio
import re
from typing import Callable, Dict, List, Optional, Tuple
from core.scanners.base_scanner import BaseScanner
from core.payload_generator import PayloadGenerator

class WAFDetector(BaseScanner):
    """
    [AR-GE v2.0 - GHOST BREAKER]
    Hedef sistemin önünde duran dijital surları (WAF/CDN/IPS) tespit eder.
    Pasif İmza Analizi + Aktif Provokasyon + Evasion Stratejisi belirler.
    """
    
    # --------------------------------------------------------------------------
    # GENİŞLETİLMİŞ WAF İMZA VERİTABANI (50+ İmza)
    # --------------------------------------------------------------------------
    WAF_SIGNATURES = {
        "Cloudflare": {
            "headers": {"Server": "cloudflare", "CF-RAY": "", "cf-cache-status": ""},
            "cookies": ["__cfduid", "cf_clearance"]
        },
        "AWS WAF": {
            "headers": {"X-Amz-Cf-Id": "", "Server": "Awselb", "Server": "AmazonS3"},
            "cookies": ["aws-waf-token"]
        },
        "Akamai": {
            "headers": {"Server": "AkamaiGHost", "X-Akamai-Transformed": ""},
        },
        "Imperva Incapsula": {
            "headers": {"X-Iinfo": "", "X-CDN": "Incapsula"},
            "cookies": ["incap_ses", "visid_incap"]
        },
        "ModSecurity": {
            "headers": {"Server": "ModSecurity", "Server": "NOYB"},
            "body": ["Not Acceptable", "406 Not Acceptable", "ModSecurity Action"]
        },
        "Sucuri": {
            "headers": {"Server": "Sucuri/Cloudproxy", "X-Sucuri-ID": ""},
            "cookies": ["sucuri_cloudproxy"]
        },
        "F5 BIG-IP ASM": {
            "headers": {"X-Cnection": "close"},
            "cookies": ["TS[0-9a-f]{8}"] # Regex cookie
        },
        "Citrix NetScaler": {
            "headers": {"Via": "NS-CACHE", "X-Cnection": ""},
            "cookies": ["ns_af"]
        },
        "Barracuda WAF": {
            "headers": {"Server": "BarracudaServer"},
            "cookies": ["barra_counter_session"]
        },
        "Microsoft Azure WAF": {
            "headers": {"Server": "Microsoft-IIS", "X-Ms-Forbidden-Ip": ""}
        },
        "Google Cloud Armor": {
            "headers": {"Via": "1.1 google"}
        },
        "StackPath": {
            "headers": {"Server": "StackPath", "X-Sp-Url": ""}
        },
        "Fastly": {
            "headers": {"Server": "Fastly", "X-Fastly-Request-ID": ""}
        },
        "Reblaze": {
            "headers": {"Server": "Reblaze Secure Web Gateway"},
            "cookies": ["rbzid"]
        },
        "FortiWeb": {
            "cookies": ["FORTIWAFSID"]
        },
        "Palo Alto": {
            "headers": {"Server": "Palo Alto"}
        }
    }
    
    # WAF'ı kışkırtmak için kullanılan, backend'e zarar vermeyen ama WAF'ı tetikleyen payloadlar
    PROVOCATION_PAYLOADS = [
        # SQLi Benzeri
        "' OR 1=1 --", 
        "UNION SELECT 1,2,3--",
        # XSS Benzeri
        "<script>alert('Synara')</script>",
        "javascript:alert(1)",
        # LFI Benzeri
        "../../../../etc/passwd",
        "/boot.ini",
        # Command Injection Benzeri
        "; cat /etc/passwd",
        "|| whoami"
    ]

    # WAF Engelleme Sayfalarında geçen yaygın kelimeler
    BLOCK_KEYWORDS = [
        "captcha", "challenge", "security check", "access denied", "forbidden",
        "block", "firewall", "virus", "malicious", "protect", "incapsula",
        "cloudflare", "sucuri", "mod_security", "waf"
    ]

    @property
    def name(self):
        return "WAF (Güvenlik Duvarı) Tespiti"

    @property
    def category(self):
        return "WAF_DETECT"
        
    def __init__(self, logger, results_callback, request_callback: Callable[[], None]):
        super().__init__(logger, results_callback, request_callback)

    async def scan(self, url: str, session: aiohttp.ClientSession, completed_callback: Callable[[], None]):
        """
        WAF tespit mantığını uygular.
        1. Pasif İmza Analizi (Headers/Cookies)
        2. Aktif Provokasyon (Payload Gönderimi)
        3. Evasion Stratejisi Belirleme
        """
        self.log(f"[{self.category}] WAF (Güvenlik Duvarı) analizi başlatılıyor...", "INFO")
        
        waf_detected = False
        detected_waf_name = "Bilinmeyen WAF"
        detection_method = "Pasif Analiz"
        
        try:
            # --- 1. PASİF ANALİZ (NORMAL İSTEK) ---
            # Motorun rate limitine takılmamak için bekleyerek istek at
            if hasattr(self, '_apply_jitter_and_throttle'):
                await self._apply_jitter_and_throttle()
            self.request_callback()
            
            async with session.get(url, allow_redirects=True, timeout=10) as res:
                content = await res.text()
                headers = res.headers
                cookies = res.cookies
                
                # İmzaları Kontrol Et
                waf_detected, detected_waf_name = self._check_signatures(headers, cookies, content)

            # --- 2. AKTİF ANALİZ (PROVOKASYON) ---
            # Pasif analizde bulunamadıysa veya emin olmak için
            if not waf_detected:
                self.log(f"[{self.category}] Pasif imza bulunamadı. Aktif provokasyon başlatılıyor...", "INFO")
                
                # Sadece 2-3 payload ile hızlıca dene (çok gürültü yapma)
                for payload in self.PROVOCATION_PAYLOADS[:3]:
                    # Parametresiz URL'ye sahte bir query ekle
                    target = f"{url}?synara_waf_check={payload}"
                    
                    if hasattr(self, '_apply_jitter_and_throttle'):
                        await self._apply_jitter_and_throttle()
                    self.request_callback()
                    
                    try:
                        async with session.get(target, allow_redirects=False, timeout=5) as res:
                            # 403, 406 veya 501 genellikle WAF tepkisidir
                            # Bazı WAF'lar 200 döner ama içerikte "Captcha" gösterir
                            resp_content = await res.text()
                            
                            is_blocked_status = res.status in [403, 406, 501, 999]
                            is_blocked_content = any(k in resp_content.lower() for k in self.BLOCK_KEYWORDS)
                            
                            if is_blocked_status or is_blocked_content:
                                waf_detected = True
                                detected_waf_name = f"Generic WAF (Tepki: {res.status})"
                                detection_method = f"Aktif Provokasyon ({payload})"
                                
                                # Belki aktif tepkide bir imza yakalarız (örn: Cloudflare 403 sayfasında footer)
                                active_sig_check, active_waf_name = self._check_signatures(res.headers, res.cookies, resp_content)
                                if active_sig_check:
                                    detected_waf_name = active_waf_name
                                
                                break
                    except Exception:
                        continue # Time out yerse bir sonrakini dene

            # --- 3. SONUÇ RAPORLAMA VE STRATEJİ ---
            if waf_detected:
                msg = f"GÜVENLİK DUVARI TESPİT EDİLDİ: {detected_waf_name} | Yöntem: {detection_method}"
                
                # SRP Puanı Düşürme (WAF varsa işimiz zorlaşır, uyarı ver)
                # Not: WAF olması doğrudan bir zafiyet değildir, sadece engeldir. Puanı 0.0 tutuyoruz.
                self.add_result(self.category, "WARNING", msg, 0.0)
                self.log(f"[{self.category}] {msg}", "WARNING")
                
                # Evasion Modunu Aktifleştir
                PayloadGenerator.set_evasion_mode(True)
                
                # Strateji Önerisi
                strategy = self._get_evasion_strategy(detected_waf_name)
                self.log(f"[{self.category}] [STRATEJİ] {strategy}", "SUCCESS")
                
            else:
                self.add_result(self.category, "INFO", "Herhangi bir WAF koruması tespit edilemedi.", 0.0)
                self.log(f"[{self.category}] Yol temiz. WAF tespit edilmedi.", "INFO")
                PayloadGenerator.set_evasion_mode(False) 

        except Exception as e:
            self.log(f"[{self.category}] WAF Analiz Hatası: {str(e)}", "WARNING")
            
        completed_callback()

    def _check_signatures(self, headers, cookies, content) -> Tuple[bool, str]:
        """
        Verilen yanıt verilerini imza veritabanı ile karşılaştırır.
        """
        content_lower = content.lower() if content else ""
        
        for waf_name, signatures in self.WAF_SIGNATURES.items():
            # 1. Header Kontrolü
            for h_key, h_val in signatures.get("headers", {}).items():
                # Case-insensitive header arama
                header_match = False
                for k, v in headers.items():
                    if k.lower() == h_key.lower():
                        if h_val == "" or h_val.lower() in v.lower():
                            header_match = True
                            break
                if header_match:
                    return True, waf_name
            
            # 2. Cookie Kontrolü
            if "cookies" in signatures:
                for c_key in signatures["cookies"]:
                    # Regex desteği
                    if any(re.search(c_key, cookie.key) for cookie in cookies.values()):
                        return True, waf_name
                        
            # 3. Body Kontrolü (Varsa)
            if "body" in signatures:
                for b_text in signatures["body"]:
                    if b_text.lower() in content_lower:
                        return True, waf_name
                        
        return False, "Bilinmeyen"

    def _get_evasion_strategy(self, waf_name: str) -> str:
        """
        Tespit edilen WAF'a özel atlatma (evasion) stratejisi önerir.
        """
        waf_name = waf_name.lower()
        if "cloudflare" in waf_name:
            return "Cloudflare Tespiti: IP rotasyonu kullanın. Orijinal IP (Origin Server) keşfi yapın. Rate-limit agresiftir, yavaş tarama yapın."
        elif "modsecurity" in waf_name:
            return "ModSecurity Tespiti: Büyük/Küçük harf karıştırma (SeLeCt) ve SQLi için yorum satırı hileleri (/*!50000*/) kullanın."
        elif "aws" in waf_name:
            return "AWS WAF Tespiti: Genellikle kurallı (rule-based). JSON body encoding veya HTTP method değiştirme deneyin."
        elif "akamai" in waf_name:
            return "Akamai Tespiti: Çok gelişmiş. Manuel analiz ve business logic hatalarına odaklanın."
        elif "incapsula" in waf_name or "imperva" in waf_name:
            return "Imperva Tespiti: Bot koruması güçlüdür. User-Agent ve Header sırasını gerçek tarayıcı gibi yapın."
        else:
            return "Genel WAF Stratejisi: PayloadGenerator 'Evasion Mode'a geçti. Encoding, Null Byte ve Case Variation teknikleri uygulanacak."