# path: core/scanners/pre_scan.py

import aiohttp
import aiohttp.client_exceptions
import asyncio
import re
import json
from typing import Callable, Set, Any, Dict

from core.scanners.base_scanner import BaseScanner


class PreScanner(BaseScanner):
    """
    Deep Vision v3.2 – Parametre Keşfi (Pro Optimize + Susturucu v1.1)
    - Parametre kaynağı tespiti (HTML / JS / JSON)
    - Semantic Noise Filter (CSS & HTML otomatik gürültü temizleme)
    - Parametre sınıflandırma: STRUCTURAL / BEHAVIORAL / SECURITY-SENSITIVE / LOW
    - Mutability Analyzer: Parametre değiştirilebilir mi?
    - TR-GUARD: Türkçe ve ASCII olmayan kelimeleri filtreleme.
    """

    PARAM_PATTERN = re.compile(
        r'(?:name|id|ng-model|v-model)=["\']?([a-zA-Z0-9_\-]+)["\']?|'     # HTML attr
        r'["\']?([a-zA-Z0-9_\-]+)["\']?\s*:',                              # JS/JSON key
        re.IGNORECASE
    )

    # Anahtar kelime grupları
    SECURITY_HINT = {"token", "session", "auth", "key", "secret", "uid", "user"}
    STRUCTURAL_HINT = {"id", "file", "path", "page", "index"}
    BEHAVIORAL_HINT = {"search", "query", "filter", "sort", "event"}

    # KRİTİK GÜNCELLEME: Next.js/Vercel/CSS/SVG gürültüsünü filtreleyen genişletilmiş set
    # v1.1 EKLENTİSİ: Türkçe UI kelimeleri eklendi.
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
        
        # RainbowKit / CSS Variables Prefix'leri
        "rs", "rk", "paint0", "mask0", "filter1", "radix-", "-trigger-radix-",
        "-content-radix-", "-webkit-backdrop-filter",

        # [v1.1] TÜRKÇE KELİMELER / UI METİNLERİ (False Positive Filtresi)
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
        return "Gelişmiş Parametre Keşfi (Deep Vision v3.2)"

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
    # MUTABILITY CHECK (Parametre gerçekten değiştirilebilir mi?)
    # ----------------------------------------------------------------------
    def _is_mutable(self, p: str) -> bool:
        """
        Değiştirilebilir parametreler:
        - GET parametresi olma ihtimali yüksek olan kelimeler
        - Form input isimleri
        """
        # KRİTİK: Mutability check'ten önce FP'leri elemeliyiz.
        if not self._is_valid_param(p):
            return False 

        p = p.lower()

        # Çok küçük isimler risklidir
        if len(p) <= 2 and p not in self.SECURITY_HINT:
            return False

        # Güvenlik/structural parametreler genelde değiştirilebilir
        if any(k in p for k in self.SECURITY_HINT | self.STRUCTURAL_HINT):
            return True

        return True  # diğerleri için varsayılan: evet

    # ----------------------------------------------------------------------
    # PARAMETRE VALİDASYON (YENİ FP FİLTRESİ v1.1)
    # ----------------------------------------------------------------------
    def _is_valid_param(self, p: str) -> bool:
        if not p:
            return False
            
        # 1. [YENİ] ASCII Kontrolü (Türkçe karakter filtresi)
        # Parametre anahtarları teknik olarak %-encoded olabilir ancak
        # raw string içinde 'ş','ğ','ı' gibi karakterler varsa bu %99.9 UI metnidir.
        if not p.isascii():
            return False

        p_lower = p.lower()

        # 2. Uzunluk Kontrolü (Çok kısa veya çok uzunsa atla)
        if len(p) < 2 or len(p) > 50:
             # İzin verilen kısa güvenlik anahtarlarını kontrol et (örn: q=search)
             if p_lower not in ["id", "uid", "key", "q"]:
                 return False

        # 3. Statik Gürültü Kontrolü (Türkçe kelimeler dahil)
        if p_lower in self.STATIC_NOISE:
            return False
            
        # 4. CSS Değişkeni/SVG ID ve Framework Prefix Kontrolü
        if p.startswith(('--', 'rs-', 'rk-', 'clip', 'mask', 'filter', 'paint', 'radix-', '-')): 
             return False
             
        # 5. Anlamsız Kısa Tekrarlayan Key'ler (n4f, n20, n3c)
        if len(p) <= 3 and re.match(r"^[a-zA-Z]{1}\d+$", p_lower):
            return False
            
        # 6. Harf-Rakam karışımı ve Anlamsız (Random id'ler) filtresi
        # Eğer parametre adı 3-5 karakter uzunluğunda VE sadece harf-rakam karışımı ise 
        # VE içinde bilinen bir ipucu (id, key vb.) yoksa atla.
        if 3 <= len(p) <= 5 and re.match(r"^[a-z0-9]+$", p_lower) and not any(k in p_lower for k in self.SECURITY_HINT | self.STRUCTURAL_HINT):
             return False

        # 7. Boşluk Kontrolü (Parametre anahtarlarında boşluk olmaz)
        if " " in p:
            return False

        return True


    # ----------------------------------------------------------------------
    # ANA TARAYICI
    # ----------------------------------------------------------------------
    async def scan(self, url: str, session: aiohttp.ClientSession, completed_callback: Callable[[], None]):
        self.log(f"[{self.category}] Deep Vision v3.2 parametre analizi başlatıldı...", "INFO")

        discovered: Dict[str, Dict[str, str]] = {}  # {param: {level, source, mutable}}

        for attempt in range(self.MAX_RETRIES):
            try:
                self.request_callback()

                async with session.get(url, allow_redirects=True) as res:
                    content_type = res.headers.get("Content-Type", "").lower()
                    text = await res.text()

                    # ----------------------------------------------------
                    # JSON ANALİZİ (Next.js __NEXT_DATA__ gibi)
                    # ----------------------------------------------------
                    if "application/json" in content_type or "__NEXT_DATA__" in text:
                        try:
                            # Eğer HTML içinde __NEXT_DATA__ varsa onu parse et
                            if "__NEXT_DATA__" in text:
                                json_match = re.search(r'__NEXT_DATA__" type="application/json">({.*?})</script>', text)
                                if json_match:
                                    json_data = json.loads(json_match.group(1))
                                else:
                                    json_data = await res.json()
                            else:
                                json_data = await res.json()
                                
                            self._extract_json(json_data, discovered)
                        except Exception:
                            pass

                    # ----------------------------------------------------
                    # HTML/JS Regex analizi
                    # ----------------------------------------------------
                    for m in self.PARAM_PATTERN.finditer(text):
                        p = m.group(1) or m.group(2)

                        if not self._is_valid_param(p): # FP Kalkanı burada çalışır
                            continue

                        discovered[p] = {
                            "level": self._classify_param(p),
                            "source": "HTML/JS",
                            "mutable": "YES" if self._is_mutable(p) else "NO"
                        }

                    # ----------------------------------------------------
                    # SONUÇ
                    # ----------------------------------------------------
                    if discovered:
                        # Mutation kontrolünden geçenleri Engine'e gönder
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