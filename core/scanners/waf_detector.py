# path: core/scanners/waf_detector.py

import aiohttp
import asyncio
import re
from typing import Callable, Dict, List, Optional, Tuple
from core.scanners.base_scanner import BaseScanner
from core.payload_generator import PayloadGenerator

class WAFDetector(BaseScanner):
    """
    [AR-GE v2.1 - GHOST BREAKER & CONFIDENCE ENGINE]
    Hedef sistemin önünde duran dijital surları (WAF/CDN/IPS) tespit eder.
    
    YENİLİKLER (v2.1):
    - Confidence Scoring: Düşük güvenilirlikli WAF tespitlerinde (Generic) sistemi frenlemez.
    - False Positive Killer: 200 OK yanıtlarında "block" kelimesi geçmesi artık WAF sayılmaz.
    - Aggressive Bypass: Belirsiz durumlarda Evasion Mode yerine saldırı modunda kalır.
    """
    
    # --------------------------------------------------------------------------
    # GENİŞLETİLMİŞ WAF İMZA VERİTABANI
    # --------------------------------------------------------------------------
    WAF_SIGNATURES = {
        "Cloudflare": {
            "headers": {"Server": "cloudflare", "CF-RAY": "", "cf-cache-status": ""},
            "cookies": ["__cfduid", "cf_clearance"],
            "score": 10  # Kesin İmza
        },
        "AWS WAF": {
            "headers": {"X-Amz-Cf-Id": "", "Server": "Awselb", "Server": "AmazonS3"},
            "cookies": ["aws-waf-token"],
            "score": 9
        },
        "Akamai": {
            "headers": {"Server": "AkamaiGHost", "X-Akamai-Transformed": ""},
            "score": 9
        },
        "Imperva Incapsula": {
            "headers": {"X-Iinfo": "", "X-CDN": "Incapsula"},
            "cookies": ["incap_ses", "visid_incap"],
            "score": 10
        },
        "ModSecurity": {
            "headers": {"Server": "ModSecurity", "Server": "NOYB"},
            "body": ["Not Acceptable", "406 Not Acceptable", "ModSecurity Action"],
            "score": 8
        },
        "Sucuri": {
            "headers": {"Server": "Sucuri/Cloudproxy", "X-Sucuri-ID": ""},
            "cookies": ["sucuri_cloudproxy"],
            "score": 10
        },
        "F5 BIG-IP ASM": {
            "headers": {"X-Cnection": "close"},
            "cookies": ["TS[0-9a-f]{8}"], # Regex cookie
            "score": 9
        },
        "Citrix NetScaler": {
            "headers": {"Via": "NS-CACHE", "X-Cnection": ""},
            "cookies": ["ns_af"],
            "score": 9
        },
        "Barracuda WAF": {
            "headers": {"Server": "BarracudaServer"},
            "cookies": ["barra_counter_session"],
            "score": 9
        },
        "Microsoft Azure WAF": {
            "headers": {"Server": "Microsoft-IIS", "X-Ms-Forbidden-Ip": ""},
            "score": 8
        },
        "Google Cloud Armor": {
            "headers": {"Via": "1.1 google"},
            "score": 8
        },
        "StackPath": {
            "headers": {"Server": "StackPath", "X-Sp-Url": ""},
            "score": 9
        },
        "Fastly": {
            "headers": {"Server": "Fastly", "X-Fastly-Request-ID": ""},
            "score": 8
        },
        "Reblaze": {
            "headers": {"Server": "Reblaze Secure Web Gateway"},
            "cookies": ["rbzid"],
            "score": 10
        },
        "FortiWeb": {
            "cookies": ["FORTIWAFSID"],
            "score": 10
        },
        "Palo Alto": {
            "headers": {"Server": "Palo Alto"},
            "score": 9
        }
    }
    
    # WAF'ı kışkırtmak için kullanılan payloadlar
    PROVOCATION_PAYLOADS = [
        "' OR 1=1 --", 
        "<script>alert(1)</script>",
        "../../../../etc/passwd",
        "; cat /etc/passwd"
    ]

    # Bu kelimeler SADECE hata kodu (403, 406 vb.) alındığında aranır.
    # 200 OK dönen sayfalarda aranmaz (FP Önleme).
    BLOCK_KEYWORDS = [
        "captcha", "challenge", "security check", "access denied", 
        "firewall", "virus", "malicious", "protect", "incapsula",
        "cloudflare", "sucuri", "mod_security"
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
        """
        self.log(f"[{self.category}] WAF (Güvenlik Duvarı) analizi başlatılıyor...", "INFO")
        
        waf_detected = False
        detected_waf_name = "Bilinmeyen WAF"
        detection_confidence = 0 # 0-10 arası güven puanı
        
        try:
            # --- 1. PASİF ANALİZ (NORMAL İSTEK) ---
            if hasattr(self, '_apply_jitter_and_throttle'):
                await self._apply_jitter_and_throttle()
            self.request_callback()
            
            async with session.get(url, allow_redirects=True, timeout=10) as res:
                content = await res.text()
                headers = res.headers
                cookies = res.cookies
                
                # İmzaları Kontrol Et
                hit, name, score = self._check_signatures(headers, cookies, content)
                if hit:
                    waf_detected = True
                    detected_waf_name = name
                    detection_confidence = score

            # --- 2. AKTİF ANALİZ (PROVOKASYON) ---
            # Eğer pasif analizde güçlü bir WAF (Puan > 8) bulunmadıysa kışkırt
            if detection_confidence < 8:
                self.log(f"[{self.category}] Kesin imza bulunamadı (Güven: {detection_confidence}/10). Aktif provokasyon başlatılıyor...", "INFO")
                
                for payload in self.PROVOCATION_PAYLOADS:
                    target = f"{url}?synara_waf_check={payload}"
                    
                    if hasattr(self, '_apply_jitter_and_throttle'):
                        await self._apply_jitter_and_throttle()
                    self.request_callback()
                    
                    try:
                        async with session.get(target, allow_redirects=False, timeout=5) as res:
                            resp_content = await res.text()
                            
                            # KRİTİK DEĞİŞİKLİK: 200 OK dönen yanıtları WAF sayma (Legacy Siteler için)
                            # Testfire.net gibi siteler saldırıya 200 OK dönebilir ama bu WAF değildir.
                            if res.status == 200:
                                continue 

                            # 403, 406, 501, 999 gibi belirgin bloklama kodları
                            is_blocked_status = res.status in [403, 406, 501, 999]
                            is_blocked_content = any(k in resp_content.lower() for k in self.BLOCK_KEYWORDS)
                            
                            if is_blocked_status:
                                # Status kodu bloklandığını gösteriyor ama içerik de önemli
                                confidence_boost = 5
                                if is_blocked_content:
                                    confidence_boost += 3 # İçerikte "Forbidden" vs geçiyorsa güven artar
                                
                                # Daha önce bulunmadıysa veya bu daha güçlüyse güncelle
                                if confidence_boost > detection_confidence:
                                    waf_detected = True
                                    detected_waf_name = f"Generic WAF (Tepki: {res.status})"
                                    detection_confidence = confidence_boost
                                    
                                # Belki aktif tepkide bir imza yakalarız
                                hit, name, score = self._check_signatures(res.headers, res.cookies, resp_content)
                                if hit and score > detection_confidence:
                                    detected_waf_name = name
                                    detection_confidence = score
                                
                                break # Bir kere bloklandık mı yeterli
                    except Exception:
                        continue 

            # --- 3. SONUÇ VE KARAR MEKANİZMASI ---
            
            # EŞİK DEĞERİ: 6'nın altındaki tespitleri "False Positive" riski nedeniyle yoksay (Aggressive Mode)
            CONFIDENCE_THRESHOLD = 6
            
            if waf_detected and detection_confidence >= CONFIDENCE_THRESHOLD:
                msg = f"GÜVENLİK DUVARI TESPİT EDİLDİ: {detected_waf_name} | Güven: {detection_confidence}/10"
                self.add_result(self.category, "WARNING", msg, 0.0)
                self.log(f"[{self.category}] {msg}", "WARNING")
                
                # Evasion Modunu SADECE güvenilir tespitlerde aç
                PayloadGenerator.set_evasion_mode(True)
                strategy = self._get_evasion_strategy(detected_waf_name)
                self.log(f"[{self.category}] [STRATEJİ] {strategy}", "SUCCESS")
                
            elif waf_detected and detection_confidence < CONFIDENCE_THRESHOLD:
                # WAF var gibi ama emin değiliz -> Saldırıya devam et!
                msg = f"Zayıf WAF Sinyali ({detected_waf_name}, Güven: {detection_confidence}/10). Evasion Modu KAPALI tutuluyor (Aggressive)."
                self.log(f"[{self.category}] {msg}", "INFO")
                PayloadGenerator.set_evasion_mode(False)
                
            else:
                self.add_result(self.category, "INFO", "Herhangi bir WAF koruması tespit edilemedi.", 0.0)
                self.log(f"[{self.category}] Yol temiz. WAF tespit edilmedi. Tam güç saldırı modu aktif.", "INFO")
                PayloadGenerator.set_evasion_mode(False) 

        except Exception as e:
            self.log(f"[{self.category}] WAF Analiz Hatası: {str(e)}", "WARNING")
            
        completed_callback()

    def _check_signatures(self, headers, cookies, content) -> Tuple[bool, str, int]:
        """
        Verilen yanıt verilerini imza veritabanı ile karşılaştırır.
        Dönüş: (BulunduMu, Wafİsmi, Puan)
        """
        content_lower = content.lower() if content else ""
        
        best_match = (False, "Bilinmeyen", 0)
        
        for waf_name, data in self.WAF_SIGNATURES.items():
            score = data.get("score", 5)
            
            # 1. Header Kontrolü
            for h_key, h_val in data.get("headers", {}).items():
                header_match = False
                for k, v in headers.items():
                    if k.lower() == h_key.lower():
                        if h_val == "" or h_val.lower() in v.lower():
                            header_match = True
                            break
                if header_match:
                    return True, waf_name, score
            
            # 2. Cookie Kontrolü
            if "cookies" in data:
                for c_key in data["cookies"]:
                    if any(re.search(c_key, cookie.key) for cookie in cookies.values()):
                        return True, waf_name, score
                        
            # 3. Body Kontrolü
            if "body" in data:
                for b_text in data["body"]:
                    if b_text.lower() in content_lower:
                        return True, waf_name, score
                        
        return best_match

    def _get_evasion_strategy(self, waf_name: str) -> str:
        waf_name = waf_name.lower()
        if "cloudflare" in waf_name:
            return "Cloudflare: IP rotasyonu ve yavaş tarama kullanın."
        elif "modsecurity" in waf_name:
            return "ModSecurity: Case variation (SeLeCt) teknikleri uygulayın."
        elif "aws" in waf_name:
            return "AWS WAF: JSON body encoding deneyin."
        else:
            return "Genel WAF: Payload encoding ve null byte teknikleri uygulanacak."