# path: core/scanners/pre_scan.py

import aiohttp
import aiohttp.client_exceptions
import asyncio
import re
import json
from typing import Callable, Set, Any, Dict
from urllib.parse import parse_qs 

from core.scanners.base_scanner import BaseScanner


class PreScanner(BaseScanner):
    """
    Deep Vision v3.8 – Hibrit Parametre Keşfi
    
    YENİLİKLER (v3.8):
    - Ultra Agresif Query Hunter: HTML'deki herhangi bir nitelik (attribute) değerinde 
      gizlenmiş sorgu parametrelerini (id, cat vb.) en basit ve en agresif desenle keşfeder.
    """

    # Modern JS/HTML attribute regex'i (React props, Angular directives vb. için)
    PARAM_PATTERN = re.compile(
        r'(?:name|id|ng-model|v-model)=["\']?([a-zA-Z0-9_\-]+)["\']?|'     # HTML attr
        r'["\']?([a-zA-Z0-9_\-]+)["\']?\s*:',                              # JS/JSON key
        re.IGNORECASE
    )
    
    # Ultra Agresif Query Hunter Regex: HTML içinde '?QUERY_STRING"' desenini arar.
    QUERY_URL_PATTERN = re.compile(r'\?([^"\']+)["\']', re.IGNORECASE)


    # Anahtar kelime grupları
    SECURITY_HINT = {"token", "session", "auth", "key", "secret", "uid", "user", "pass", "pwd", "login"}
    STRUCTURAL_HINT = {"id", "file", "path", "page", "index", "view", "cat", "category"} 
    BEHAVIORAL_HINT = {"search", "query", "filter", "sort", "event", "submit", "btn", "q"} 

    # Gürültü Filtresi (Static Noise + TR Guard)
    STATIC_NOISE = {
        "class", "style", "type", "value", "placeholder", "href", "src",
        "width", "height", "rel", "media", "charset", "name", "id",
        "margin", "padding", "color", "display", "background",
        "z-index", "opacity", "vertical-align", "margin-bottom",
        "margin-top", "margin-right", "margin-left",
        "padding-bottom", "padding-right", "padding-left", "padding-top",
        "border", "font", "grid", "flex", "gap", "float", "source",
        "font-size", "them", "following", "hacking", "https", "http",
        "warning", "error", "message", "description", "position", "selection",
        "box-shadow", "text-shadow", "transform-style", "backdrop-filter",
        "focus-visible", "disabled", "theme-color",
        
        # Next.js/Vercel/React/CSS/SVG Gürültüsü
        "viewport", "twitter", "og", "left", "transform", "transition",
        "outline-color", "outline-width", "outline-style", "aspect-ratio",
        "border-radius", "filter", "mask", "paint", "clip", "fill",
        "__next_data__", "props", "pageprops", "buildid", "nextexport", 
        "autoexport", "isfallback", "scriptloader", "prefers-color-scheme",
        "dark", "light", "md", "sm", "lg", "xl", "r1tcm", 
        "apple-mobile-web-app-capable", "apple-mobile-web-app-status-bar-style",
        "apple-mobile-web-app-title", "next-size-adjust", "group-hover",
        "div", "span", "label", "form", "input", "body", "html", "head", "meta",
        
        # RainbowKit / CSS Variables Prefix'leri
        "rs", "rk", "paint0", "mask0", "filter1", "radix-", "-trigger-radix-",
        "-content-radix-", "-webkit-backdrop-filter",

        # TÜRKÇE KELİMELER / UI METİNLERİ (False Positive Filtresi)
        "varız", "satın", "tıkayın", "disiplini", "katkısı", "sinyal", 
        "analiz", "altyapısı", "payı", "veresiye", "hakkımızda", "iletişim", 
        "giriş", "kayıt", "sepet", "ara", "menü", "kapat", "devam", "iptal", 
        "onayla", "gönder", "yardım", "sss", "blog", "kariyer", "referanslar", 
        "fiyatlar", "özellikler", "indir", "yükle", "yakalayın", "parlayın",
        "stagemind", "healthcore", "eduminds", "mestegflow", "hizmetler",
        "kurumsal", "bize", "ulaşın", "detaylı", "bilgi", "alın", "şimdi"
    }

    MAX_RETRIES = 3

    @property
    def name(self):
        return "Gelişmiş Parametre Keşfi (Deep Vision v3.8)"

    @property
    def category(self):
        return "PRE_SCAN"

    def __init__(self, logger, results_callback, request_callback: Callable[[], None],
                 discovery_callback: Callable[[str], None]):
        super().__init__(logger, results_callback, request_callback)
        self.discovery_callback = discovery_callback

    # ----------------------------------------------------------------------
    # PARAMETRE SINIFLANDIRICI
    # ----------------------------------------------------------------------
    def _classify_param(self, p: str) -> str:
        p = p.lower()

        if any(k in p for k in self.SECURITY_HINT):
            return "SECURITY-SENSITIVE"

        if any(k in p for k in self.STRUCTURAL_HINT):
            return "STRUCTURAL"

        if any(k in p for k in self.BEHAVIORAL_HINT):
            return "BEHAVIORAL"

        return "LOW"

    # ----------------------------------------------------------------------
    # MUTABILITY CHECK
    # ----------------------------------------------------------------------
    def _is_mutable(self, p: str) -> bool:
        if not self._is_valid_param(p):
            return False 

        p = p.lower()
        if len(p) <= 2 and p not in self.SECURITY_HINT:
            return False

        return True

    # ----------------------------------------------------------------------
    # PARAMETRE VALİDASYON
    # ----------------------------------------------------------------------
    def _is_valid_param(self, p: str) -> bool:
        if not p:
            return False
            
        if not p.isascii():
            return False

        p_lower = p.lower()

        # Kritik kısa parametrelerin uzunluk filtresine takılmasını önle
        if len(p) < 2 or len(p) > 50:
            if p_lower not in ["id", "uid", "key", "q", "p", "cat", "view"]:
                return False

        if p_lower in self.STATIC_NOISE:
            return False
            
        if p.startswith(('--', 'rs-', 'rk-', 'clip', 'mask', 'filter', 'paint', 'radix-', '-')): 
            return False
            
        if len(p) <= 3 and re.match(r"^[a-zA-Z]{1}\d+$", p_lower):
            return False
        
        # Agresif Alfanumerik Filtrenin gevşetilmesi
        if 3 <= len(p) <= 5 and re.match(r"^[a-z0-9]+$", p_lower) and not any(k in p_lower for k in self.SECURITY_HINT | self.STRUCTURAL_HINT | self.BEHAVIORAL_HINT):
            return False

        if " " in p:
            return False

        return True

    # ----------------------------------------------------------------------
    # ANA TARAYICI
    # ----------------------------------------------------------------------
    async def scan(self, url: str, session: aiohttp.ClientSession, completed_callback: Callable[[], None]):
        self.log(f"[{self.category}] Deep Vision v3.8 analizi başlatıldı...", "INFO")

        discovered: Dict[str, Dict[str, str]] = {}

        for attempt in range(self.MAX_RETRIES):
            try:
                self.request_callback()

                async with session.get(url, allow_redirects=True) as res:
                    content_type = res.headers.get("Content-Type", "").lower()
                    text = await res.text()

                    # 1. HTML FORM ANALİZİ (Legacy Hunter)
                    self._extract_html_forms(text, discovered)
                    
                    # 2. URL SORGUSU ANALİZİ (Query Hunter)
                    self._extract_url_queries(text, discovered) 

                    # 3. JSON ANALİZİ (Modern Apps)
                    if "application/json" in content_type or "__NEXT_DATA__" in text:
                        try:
                            if "__NEXT_DATA__" in text:
                                json_match = re.search(r'__NEXT_DATA__" type="application/json">({.*?})</script>', text)
                                if json_match:
                                    json_data = json.loads(json_match.group(1))
                                    self._extract_json(json_data, discovered)
                            else:
                                if "application/json" in content_type:
                                    json_data = await res.json()
                                    self._extract_json(json_data, discovered)
                        except Exception:
                            pass

                    # 4. GENEL REGEX ANALİZİ (Fallback)
                    for m in self.PARAM_PATTERN.finditer(text):
                        p = m.group(1) or m.group(2)
                        if self._is_valid_param(p):
                            if p not in discovered:
                                discovered[p] = {
                                    "level": self._classify_param(p),
                                    "source": "HTML/JS-REGEX",
                                    "mutable": "YES" if self._is_mutable(p) else "NO"
                                }

                    # SONUÇLARI KAYDET
                    if discovered:
                        mutable_params = {p for p, info in discovered.items() if info["mutable"] == "YES"}
                        
                        for param in mutable_params:
                            self.discovery_callback(param)

                        preview = ", ".join(
                            [f"{p}({discovered[p]['level']})" for p in list(mutable_params)[:6]]
                        )
                        
                        total_count = len(mutable_params)
                        self.add_result(self.category, "SUCCESS",
                                       f"SRP Düşüş: 0.0 │ {total_count} parametre bulundu. Örn: {preview}", 0)
                    else:
                        self.add_result(self.category, "INFO", "SRP Düşüş: 0.0 │ Yeni parametre bulunamadı.", 0)

                    break

            except aiohttp.client_exceptions.ClientConnectorError as e:
                self.log(f"[{self.category}] Erişim hatası (Connection Error): {type(e).__name__}", "CRITICAL")
                if attempt == self.MAX_RETRIES - 1:
                    self.add_result(self.category, "CRITICAL", f"Erişim hatası: {type(e).__name__}", 5)
            except Exception as e:
                if attempt == self.MAX_RETRIES - 1:
                    self.add_result(self.category, "CRITICAL", f"Beklenmedik Hata: {type(e).__name__}", 5)

                await asyncio.sleep(1)

        completed_callback()

    # ----------------------------------------------------------------------
    # URL Query Extractor (Query Hunter)
    # ----------------------------------------------------------------------
    def _extract_url_queries(self, content: str, discovered: Dict[str, Dict[str, str]]):
        """
        HTML içeriğindeki linklerden, form action'lardan ve diğer niteliklerden sorgu parametrelerini (ör. ?id=1) çıkarır.
        """
        for m in self.QUERY_URL_PATTERN.finditer(content):
            # m.group(1) sorgu dizesini yakalar, örn: id=1&cat=fashion
            query_string = m.group(1) 
            
            try:
                # parse_qs fonksiyonu, sorgu dizesini ayrıştırır.
                parsed_query = parse_qs(query_string, keep_blank_values=True)
            except Exception:
                continue

            for p in parsed_query:
                if self._is_valid_param(p):
                    if p not in discovered:
                        discovered[p] = {
                            "level": self._classify_param(p),
                            "source": "HTML-QUERY-STRING",
                            "mutable": "YES"
                        }

    # ----------------------------------------------------------------------
    # HTML Form Extractor (Legacy Hunter)
    # ----------------------------------------------------------------------
    def _extract_html_forms(self, content: str, discovered: Dict[str, Dict[str, str]]):
        """
        HTML içeriğindeki <input>, <textarea>, <select> elemanlarının 'name' niteliklerini toplar.
        """
        # Input pattern: <input ... name="X" ...>
        input_matches = re.finditer(r'<input[^>]+name=["\']([^"\']+)["\']', content, re.IGNORECASE)
        for m in input_matches:
            name = m.group(1)
            if self._is_valid_param(name) and not name.startswith("__"): # ASP.NET __VIEWSTATE hariç
                discovered[name] = {
                    "level": self._classify_param(name),
                    "source": "HTML-FORM-INPUT",
                    "mutable": "YES"
                }

        # Textarea pattern
        textarea_matches = re.finditer(r'<textarea[^>]+name=["\']([^"\']+)["\']', content, re.IGNORECASE)
        for m in textarea_matches:
            name = m.group(1)
            if self._is_valid_param(name):
                discovered[name] = {
                    "level": self._classify_param(name),
                    "source": "HTML-FORM-TEXTAREA",
                    "mutable": "YES"
                }
        
        # Select pattern
        select_matches = re.finditer(r'<select[^>]+name=["\']([^"\']+)["\']', content, re.IGNORECASE)
        for m in select_matches:
            name = m.group(1)
            if self._is_valid_param(name):
                discovered[name] = {
                    "level": self._classify_param(name),
                    "source": "HTML-FORM-SELECT",
                    "mutable": "YES"
                }

    # ----------------------------------------------------------------------
    # JSON Key Extractor
    # ----------------------------------------------------------------------
    def _extract_json(self, data: Any, target: Dict[str, Dict[str, str]]):
        if isinstance(data, dict):
            for k, v in data.items():
                if self._is_valid_param(k):
                    target[k] = {
                        "level": self._classify_param(k),
                        "source": "JSON",
                        "mutable": "YES" if self._is_mutable(k) else "NO"
                    }
                self._extract_json(v, target)

        elif isinstance(data, list):
            for item in data:
                self._extract_json(item, target)