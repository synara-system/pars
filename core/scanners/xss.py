# path: core/scanners/xss.py

import asyncio
import aiohttp
import aiohttp.client_exceptions # Timeout hatası için kullanılıyor
import re
from typing import Callable, List, Dict, Any, Optional, Set
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
import random
from time import time # KRİTİK DÜZELTME: time() için eklendi

from core.scanners.base_scanner import BaseScanner
from core.payload_generator import PayloadGenerator # Faz 29
from core.dynamic_scanner import DynamicScanner # Headless browser
from core.data_simulator import DataSimulator # Random string generation için

class XSSScanner(BaseScanner):
    """
    [FAZ 3/29/35] Cross-Site Scripting (XSS) Tarayıcısı.
    
    Yöntemler:
    - Yansıtılmış (Reflected) XSS
    - DOM XSS (DynamicScanner gerektirir)
    """
    
    PER_MODULE_LIMIT = 10
    
    # Normalde yanıtta bulunmaması gereken benzersiz payload
    CONTROL_PAYLOAD = "Synara_False_Positive_Control_123456789"

    # Maksimum paralel görev
    CONCURRENCY_LIMIT = 15

    # Varsayılan Timeout (Engine tarafından ezilecek, yoksa güvenli değer 10s)
    REQUEST_TIMEOUT = 10 

    # GET/POST için payload sınırları (ARTIRILDI - OFFENSIVE MODE)
    MAX_GET_PAYLOADS = 20
    MAX_POST_PAYLOADS = 10

    # Circuit Breaker Ayarları
    MAX_CONSECUTIVE_TIMEOUTS = 5 
    
    # YENİ FAZ: Engine'den gelen Heuristic Context bilgisi için placeholder
    reflection_context_type: Optional[str]

    def __init__(
        self,
        logger,
        results_callback,
        request_callback: Callable[[], None],
        dynamic_scanner_instance=None,
    ):
        super().__init__(logger, results_callback, request_callback)
        # self.payload_generator = PayloadGenerator(logger) # Bu artık Engine'den enjekte ediliyor
        self.dynamic_scanner = dynamic_scanner_instance
        
        # Sigorta ve Görev Takibi
        self.consecutive_timeouts = 0
        self.circuit_open = False
        self.active_coroutines: List[Any] = [] 
        self.running_tasks: List[asyncio.Task] = [] 
        
        # Enjekte edilecekler
        self.payload_generator: Optional[PayloadGenerator] = None
        self.reflection_context_type: Optional[str] = None


    @property
    def name(self):
        return "Cross-Site Scripting (XSS) Tarayıcı (Circuit Breaker)"

    @property
    def category(self):
        return "XSS"

    # -------------------------------------------------------
    # ANA GİRİŞ: SCAN
    # -------------------------------------------------------
    async def scan(
        self,
        url: str,
        session: aiohttp.ClientSession,
        completed_callback: Callable[[], None],
    ):
        if self.payload_generator is None:
            self.log(f"[{self.category}] Payload Generator enjekte edilmedi. Tarama atlanıyor.", "CRITICAL")
            completed_callback()
            return
            
        try:
            # 0) Dinamik Timeout Ayarı
            calibration_ms = getattr(self, "calibration_latency_ms", 4000)
            self.REQUEST_TIMEOUT = max(5.0, min(20.0, (calibration_ms / 1000.0) * 10.0))
            
            # Sigortayı ve listeleri sıfırla
            self.consecutive_timeouts = 0
            self.circuit_open = False
            self.active_coroutines = []
            self.running_tasks = []

            # 1) False Positive Risk Kontrolü (AGRESİF MOD)
            fp_risk = await self._check_false_positive(url, session)
            if fp_risk:
                self.add_result(
                    self.category,
                    "INFO",
                    "BİLGİ: Kontrol payload'u yanıta yansıdı. XSS taraması devam edecek ancak sonuçlar manuel doğrulanmalı.",
                    0,
                )
                self.log(f"[{self.category}] FP Kalkanı uyarı verdi ama tarama devam ettiriliyor (Aggressive Mode).", "WARNING")

            # 2) Payload setini hazırla (FAZ 29/35: Asenkron çekim)
            context_aware_payloads = await self.payload_generator.generate_context_aware_xss_payloads(
                self.reflection_context_type # Engine'den enjekte edilen context'i kullan
            )
            base_payloads = await self.payload_generator.generate_xss_payloads()
            all_payloads = list({*base_payloads, *context_aware_payloads})

            get_payloads = self._select_core_payloads(all_payloads, self.MAX_GET_PAYLOADS)
            post_payloads = self._select_core_payloads(all_payloads, self.MAX_POST_PAYLOADS)

            # 3) Parametreleri topla
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            discovered_params = getattr(self, "discovered_params", set())
            all_target_params = set(query_params.keys()) | set(discovered_params)

            for p in discovered_params:
                if p not in query_params:
                    query_params[p] = [self.CONTROL_PAYLOAD]
                    all_target_params.add(p)

            semaphore = asyncio.Semaphore(self.CONCURRENCY_LIMIT)
            
            # 4) GET Tasks Oluştur
            if all_target_params:
                self.active_coroutines.extend(self._build_get_xss_tasks(
                    url, parsed, query_params, all_target_params, get_payloads, session, semaphore
                ))

            # 5) POST Tasks Oluştur
            post_forms = await self._discover_post_forms(url, session)
            if post_forms:
                self.active_coroutines.extend(self._build_post_xss_tasks(
                    post_forms, post_payloads, session, semaphore
                ))

            total_tasks = len(self.active_coroutines)
            self.log(
                f"[{self.category}] Toplam {total_tasks} farklı XSS kombinasyonu eş zamanlı taranacak "
                f"(Limit: {self.CONCURRENCY_LIMIT}). Timeout: {self.REQUEST_TIMEOUT:.1f}s",
                "INFO",
            )

            if self.active_coroutines:
                # Görevleri Task objelerine çevirip referanslarını tutuyoruz
                self.running_tasks = [asyncio.create_task(coro) for coro in self.active_coroutines]
                
                try:
                    await asyncio.gather(*self.running_tasks)
                except asyncio.CancelledError:
                    self.log(f"[{self.category}] Tarama görevleri iptal edildi (Circuit Breaker).", "WARNING")
                except Exception:
                    pass

        except Exception as e:
            msg = f"Kritik Hata: {type(e).__name__} ({str(e)})"
            self.add_result(
                self.category,
                "CRITICAL",
                msg,
                self._calculate_score_deduction("CRITICAL"),
            )
            self.log(f"[{self.category}] {msg}", "CRITICAL")

        completed_callback()

    # -------------------------------------------------------
    # YARDIMCI METOTLAR
    # -------------------------------------------------------
    def _select_core_payloads(self, payloads: List[str], limit: int) -> List[str]:
        # Payloadları önceliklendir
        high_impact = []
        rest = []
        for p in payloads:
            lower = p.lower()
            if any(k in lower for k in ["<script", "onerror", "onload", "<svg", "img src"]):
                high_impact.append(p)
            else:
                rest.append(p)
        ordered = high_impact + rest
        return ordered[:limit]
    
    # Sigorta Kontrolü ve GÖREV İPTALİ
    def _check_circuit_breaker(self):
        if self.circuit_open: 
            return True

        if self.consecutive_timeouts >= self.MAX_CONSECUTIVE_TIMEOUTS:
            self.circuit_open = True
            self.log(f"[{self.category}] SİGORTA ATTI (Circuit Open): {self.MAX_CONSECUTIVE_TIMEOUTS} kez üst üste Timeout alındı. Modül durduruluyor.", "WARNING")
            self.add_result(self.category, "WARNING", "XSS Taraması erken durduruldu (Rate Limit / Blackhole Tespiti).", 0)
            
            # --- ZOMBİ GÖREVLERİ ÖLDÜR ---
            for task in self.running_tasks:
                if not task.done():
                    task.cancel()
            
            return True
            
        return False

    # -------------------------------------------------------
    # FALSE POSITIVE KONTROLÜ
    # -------------------------------------------------------
    async def _check_false_positive(
        self, url: str, session: aiohttp.ClientSession
    ) -> bool:
        try:
            parsed = urlparse(url)
            query = parse_qs(parsed.query)
            if not query:
                return False

            first_param = list(query.keys())[0]
            test_query = query.copy()
            test_query[first_param] = [self.CONTROL_PAYLOAD]

            new_parts = list(parsed)
            new_parts[4] = urlencode(test_query, doseq=True)
            control_url = urlunparse(new_parts)

            self.request_callback()
            async with session.get(
                control_url,
                allow_redirects=True,
                timeout=aiohttp.ClientTimeout(total=5),
            ) as res:
                text = await res.text()
                if self.CONTROL_PAYLOAD in text:
                    return True

        except Exception:
            pass
        return False

    # -------------------------------------------------------
    # GET XSS TASK OLUŞTURUCU
    # -------------------------------------------------------
    def _build_get_xss_tasks(
        self,
        base_url: str,
        parsed,
        query_params: Dict[str, List[str]],
        all_target_params: set,
        payloads: List[str],
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore,
    ):
        tasks = []
        for param in all_target_params:
            for payload in payloads:
                test_params = query_params.copy()
                test_params[param] = [payload]

                test_query = urlencode(test_params, doseq=True)
                new_parts = list(parsed)
                new_parts[4] = test_query
                test_url = urlunparse(new_parts)

                tasks.append(
                    self._check_reflection_get(
                        test_url, param, payload, session, semaphore
                    )
                )
        return tasks

    # -------------------------------------------------------
    # POST FORM KEŞFİ
    # -------------------------------------------------------
    async def _discover_post_forms(
        self, url: str, session: aiohttp.ClientSession
    ) -> List[Dict[str, Any]]:
        forms: List[Dict[str, Any]] = []

        try:
            await asyncio.sleep(random.uniform(0.05, 0.2))
            self.request_callback()
            async with session.get(
                url,
                allow_redirects=True,
                timeout=aiohttp.ClientTimeout(total=self.REQUEST_TIMEOUT),
            ) as res:
                html = await res.text()

        except Exception:
            return forms

        lower_html = html.lower()
        form_pattern = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL)
        action_pattern = re.compile(r'action=["\']?([^"\'>\s]+)', re.IGNORECASE)
        method_pattern = re.compile(r'method=["\']?(post|get)', re.IGNORECASE)
        input_pattern = re.compile(r'<input\b([^>]*)>', re.IGNORECASE | re.DOTALL)
        textarea_pattern = re.compile(r'<textarea\b([^>]*)>', re.IGNORECASE | re.DOTALL)
        name_pattern = re.compile(r'name=["\']?([^"\'>\s]+)', re.IGNORECASE)
        type_pattern = re.compile(r'type=["\']?([^"\'>\s]+)', re.IGNORECASE)

        parsed_base = urlparse(url)

        for form_match in form_pattern.finditer(lower_html):
            form_attrs = form_match.group(1) or ""
            form_body = form_match.group(2) or ""

            method = "get"
            m = method_pattern.search(form_attrs)
            if m: method = m.group(1).lower()
            if method != "post": continue

            action_url = url
            a = action_pattern.search(form_attrs)
            if a:
                raw_action = a.group(1)
                if raw_action.startswith("http://") or raw_action.startswith("https://"):
                    action_url = raw_action
                else:
                    base_parts = list(parsed_base)
                    if raw_action.startswith("/"):
                        base_parts[2] = raw_action
                    else:
                        base_dir = parsed_base.path.rsplit("/", 1)[0]
                        if not base_dir.endswith("/"): base_dir += "/"
                        base_parts[2] = base_dir + raw_action
                    action_url = urlunparse(base_parts)

            field_names = set()
            for inp in input_pattern.finditer(form_body):
                attrs = inp.group(1) or ""
                n = name_pattern.search(attrs)
                if not n: continue
                name = n.group(1)
                t = type_pattern.search(attrs)
                ftype = t.group(1).lower() if t else "text"
                if ftype in ["text", "search", "email", "password", "url", "hidden"]:
                    field_names.add(name)

            for ta in textarea_pattern.finditer(form_body):
                attrs = ta.group(1) or ""
                n = name_pattern.search(attrs)
                if not n: continue
                name = n.group(1)
                field_names.add(name)

            if not field_names: continue

            forms.append({"action": action_url, "fields": list(field_names)})

        if forms:
            self.log(f"[{self.category}] POST form keşfi: {len(forms)} form bulundu.", "INFO")
        return forms

    # -------------------------------------------------------
    # POST XSS TASK OLUŞTURUCU
    # -------------------------------------------------------
    def _build_post_xss_tasks(
        self,
        forms: List[Dict[str, Any]],
        payloads: List[str],
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore,
    ):
        tasks = []
        for form in forms:
            for payload in payloads:
                tasks.append(
                    self._test_post_xss(
                        form_action=form["action"],
                        field_names=form["fields"],
                        payload=payload,
                        session=session,
                        semaphore=semaphore,
                    )
                )
        return tasks

    # -------------------------------------------------------
    # GET XSS TESTİ
    # -------------------------------------------------------
    async def _check_reflection_get(
        self,
        test_url: str,
        param: str,
        payload: str,
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore,
    ):
        # Görev başlamadan önce sigorta kontrolü
        if self.circuit_open: return

        async with semaphore:
            # Sırada beklerken sigorta atmış olabilir, tekrar kontrol et
            if self.circuit_open: return
            
            try:
                await asyncio.sleep(random.uniform(0.1, 0.3)) # Hızlandırıldı
                self.request_callback()

                async with session.get(
                    test_url,
                    allow_redirects=True,
                    timeout=aiohttp.ClientTimeout(total=self.REQUEST_TIMEOUT),
                ) as res:
                    text = await res.text()
                    
                    # Başarılı (sağlıklı) yanıtta sayacı sıfırla
                    if res.status == 200:
                        self.consecutive_timeouts = 0

                    if payload in text:
                        
                        original_level = "CRITICAL" if "<script" in payload.lower() or "on" in payload.lower() else "HIGH"
                        
                        # BBH Filtresi ve Heuristic Context'e göre ciddiyet düşürme
                        if self.reflection_context_type == "SCRIPT":
                            final_level = "HIGH" # DOM XSS Potansiyeli
                        elif original_level == "CRITICAL":
                            final_level = "WARNING" # Reflected XSS -> Orta Risk
                        else:
                            final_level = "INFO" # Düşük Risk
                        
                        score = self._calculate_score_deduction(final_level)
                        
                        self.add_result(
                            self.category,
                            final_level,
                            f"Reflected XSS tespit edildi! [BBH Filtresi: {original_level} -> {final_level}]. Parametre: '{param}'. "
                            f"Kullanılan Payload: {payload}",
                            score,
                            poc_data={
                                "url": test_url,
                                "method": "GET",
                                "attack_vector": f"Reflected XSS (Param: {param})",
                                "data": None,
                                "headers": {}
                            }
                        )
                        # Yapay Zeka Konsültasyonu (Güvenli Asenkron Çağrı)
                        if hasattr(self, 'neural_engine') and self.neural_engine.is_active:
                            asyncio.create_task(self.neural_engine.analyze_vulnerability({
                                "category": self.category,
                                "message": f"Reflected XSS kanıtlandı. Payload: {payload[:50]}...",
                                "context": self.reflection_context_type
                            }))

                        if self.reflection_context_type == "SCRIPT":
                            await self._maybe_run_dom_analysis(test_url, payload)

            except asyncio.TimeoutError:
                if self.circuit_open: return

                self.consecutive_timeouts += 1
                if self._check_circuit_breaker():
                    return

                self.log(f"[{self.category}] GET XSS Timeout ({self.REQUEST_TIMEOUT:.1f}s). Sayaç: {self.consecutive_timeouts}/{self.MAX_CONSECUTIVE_TIMEOUTS}", "WARNING")
                
            except asyncio.CancelledError:
                raise # Hatayı yukarı fırlat ki gather yakalasın
            except aiohttp.client_exceptions.ClientConnectorError:
                self.log(f"[{self.category}] Bağlantı Hatası alındı.", "WARNING")
            except Exception:
                pass # Diğer hataları sessizce geç

    # -------------------------------------------------------
    # POST XSS TESTİ
    # -------------------------------------------------------
    async def _test_post_xss(
        self,
        form_action: str,
        field_names: List[str],
        payload: str,
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore,
    ):
        if self.circuit_open: return

        async with semaphore:
            if self.circuit_open: return
            
            try:
                await asyncio.sleep(random.uniform(0.1, 0.5))
                self.request_callback()

                data = {name: payload for name in field_names}

                async with session.post(
                    form_action,
                    data=data,
                    allow_redirects=True,
                    timeout=aiohttp.ClientTimeout(total=self.REQUEST_TIMEOUT),
                ) as res:
                    text = await res.text()
                    
                    if res.status == 200:
                        self.consecutive_timeouts = 0

                    if payload in text:
                        
                        original_level = "CRITICAL"
                        
                        if self.reflection_context_type == "SCRIPT":
                            final_level = "HIGH" # DOM XSS Potansiyeli
                        else:
                            final_level = "WARNING" # Orta Riski temsil eder
                            
                        score = self._calculate_score_deduction(final_level)

                        post_body_str = urlencode(data)

                        self.add_result(
                            self.category,
                            final_level,
                            f"KRİTİK: POST tabanlı XSS tespit edildi! [BBH Filtresi: {original_level} -> {final_level}]. "
                            f"Form: {form_action}, Alanlar: {', '.join(field_names)}, "
                            f"Payload: {payload}",
                            score,
                            poc_data={
                                "url": form_action,
                                "method": "POST",
                                "attack_vector": f"POST XSS (Fields: {', '.join(field_names)})",
                                "data": post_body_str, 
                                "headers": {"Content-Type": "application/x-www-form-urlencoded"}
                            }
                        )
                        # Yapay Zeka Konsültasyonu (Güvenli Asenkron Çağrı)
                        if hasattr(self, 'neural_engine') and self.neural_engine.is_active:
                            asyncio.create_task(self.neural_engine.analyze_vulnerability({
                                "category": self.category,
                                "message": f"POST XSS kanıtlandı. Payload: {payload[:50]}...",
                                "context": f"Form: {form_action}"
                            }))

                        if self.reflection_context_type == "SCRIPT":
                            await self._maybe_run_dom_analysis(form_action, payload)

            except asyncio.TimeoutError:
                if self.circuit_open: return

                self.consecutive_timeouts += 1
                if self._check_circuit_breaker():
                    return

                self.log(f"[{self.category}] POST XSS Timeout. Sayaç: {self.consecutive_timeouts}/{self.MAX_CONSECUTIVE_TIMEOUTS}", "WARNING")
            
            except asyncio.CancelledError:
                raise
            except aiohttp.client_exceptions.ClientConnectorError:
                self.log(f"[{self.category}] Bağlantı Hatası alındı.", "WARNING")
            except Exception:
                pass

    # -------------------------------------------------------
    # OPSİYONEL: DOM XSS ANALİZİ
    # -------------------------------------------------------
    async def _maybe_run_dom_analysis(self, url: str, payload: str):
        if not self.dynamic_scanner: return

        try:
            self.log(f"[{self.category}] Dinamik DOM XSS analizi tetiklendi. URL: {url}", "INFO")

            is_dom_vulnerable, final_url = await asyncio.to_thread(
                self.dynamic_scanner.analyze_dom_xss,
                url,
                payload,
            )

            if is_dom_vulnerable:
                score = self._calculate_score_deduction("CRITICAL")
                self.add_result(
                    self.category,
                    "CRITICAL",
                    f"KRİTİK: DOM XSS Tespiti! Payload tarayıcıda DOM manipülasyonunu tetikledi. "
                    f"URL: {final_url}",
                    score,
                )
            else:
                self.log(f"[{self.category}] Dinamik analiz: DOM XSS tespit edilmedi.", "INFO")

        except Exception as e:
            self.log(f"[{self.category}] DİNAMİK ANALİZ HATASI: {type(e).__name__} ({e})", "WARNING")

    def _calculate_score_deduction(self, level: str) -> float:
        """SRP puanını hesaplar (Engine'deki mantığın bir kopyası)."""
        weight = self.engine_instance.MODULE_WEIGHTS.get(self.category, 0.0)
        if level == "CRITICAL":
            return weight
        elif level == "HIGH":
            return weight * 0.7
        else: # WARNING/INFO
            return weight * 0.3