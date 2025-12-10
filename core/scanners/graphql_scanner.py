# path: core/scanners/graphql_scanner.py

import aiohttp
import asyncio
import re
import random
from typing import Callable, List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse

from core.scanners.base_scanner import BaseScanner
from core.payload_generator import PayloadGenerator


class GraphQLScanner(BaseScanner):
    """
    GraphQL Zafiyet Tarayıcı (V1.0)
    -------------------------------
    - Yaygın GraphQL endpoint'lerini keşfeder (/graphql, /api/graphql vb.).
    - Introspection (Şema İfşası) kontrolü yapar.
    - Hata tabanlı bilgi sızıntılarını (Suggestion Leak, Stack Trace) analiz eder.
    - SQLi/NoSQLi payload'ları ile Injection dener.
    """

    # Yaygın GraphQL Endpoint Listesi
    COMMON_ENDPOINTS = [
        "/graphql",
        "/api/graphql",
        "/v1/graphql",
        "/graph",
        "/api/graph",
        "/graphql/api",
        "/graphql/v1",
        "/gql",
    ]

    # GraphQL Hata Desenleri (Bilgi İfşası)
    ERROR_PATTERNS = [
        re.compile(r"Did you mean", re.IGNORECASE),
        re.compile(r"GraphQL syntax error", re.IGNORECASE),
        re.compile(r"Cannot query field", re.IGNORECASE),
        re.compile(r"Field \".*?\" is not defined", re.IGNORECASE),
        re.compile(r"Must provide query string", re.IGNORECASE),
        re.compile(r"Syntax Error: Expected", re.IGNORECASE),
    ]

    def __init__(self, logger, results_callback, request_callback: Callable[[], None]):
        super().__init__(logger, results_callback, request_callback)
        self.payload_generator = PayloadGenerator(logger)
        self.discovered_endpoints = set() # Bulunan endpoint'leri sakla
        
        # Varsayılan limit (Engine tarafından ezilebilir)
        self.PER_MODULE_LIMIT = 5 

    @property
    def name(self):
        return "GraphQL Güvenlik Tarayıcı"

    @property
    def category(self):
        return "GRAPHQL"

    async def scan(self, url: str, session: aiohttp.ClientSession, completed_callback: Callable[[], None]):
        """
        GraphQL tarama mantığını uygular.
        """
        self.log(f"[{self.category}] GraphQL endpoint keşfi başlatılıyor...", "INFO")

        try:
            # 1. Endpoint Keşfi
            tasks = []
            
            # Engine tarafından atanan semaphore'u kullan, yoksa varsayılan oluştur
            concurrency = getattr(self, 'module_semaphore', asyncio.Semaphore(self.PER_MODULE_LIMIT))
            
            # Eğer concurrency bir Semaphore değilse (eski engine sürümleri için fallback)
            if not isinstance(concurrency, asyncio.Semaphore):
                 concurrency = asyncio.Semaphore(5)

            for endpoint in self.COMMON_ENDPOINTS:
                target_url = urljoin(url, endpoint)
                tasks.append(self._check_endpoint(target_url, session, concurrency))
            
            # Ana URL'nin kendisi de GraphQL olabilir
            tasks.append(self._check_endpoint(url, session, concurrency))

            results = await asyncio.gather(*tasks)
            
            # Keşfedilen geçerli endpointleri topla
            valid_endpoints = [res for res in results if res]
            
            if not valid_endpoints:
                self.add_result(self.category, "INFO", "Yaygın GraphQL endpoint'leri bulunamadı.", 0)
                completed_callback()
                return

            self.log(f"[{self.category}] {len(valid_endpoints)} adet potansiyel GraphQL endpoint bulundu.", "SUCCESS")

            # 2. Introspection ve Fuzzing Testleri
            fuzzing_tasks = []
            
            # Payloadları al
            introspection_payloads = self.payload_generator.generate_graphql_introspection_payloads()
            injection_payloads = self.payload_generator.generate_graphql_injection_payloads()
            
            for endpoint_url in valid_endpoints:
                # A) Introspection Kontrolü
                for payload in introspection_payloads:
                    fuzzing_tasks.append(self._test_introspection(endpoint_url, payload, session, concurrency))
                
                # B) Injection / Hata Fuzzing
                for payload in injection_payloads:
                    # Basit query yapısı içine enjekte et
                    # Örn: { query: "1 OR 1=1" } veya parametre manipülasyonu
                    # Şimdilik basitçe raw payload gönderiyoruz, çünkü PayloadGenerator JSON formatında verebilir
                    # veya parametre olarak eklenmesi gerekebilir.
                    # GraphQL genellikle JSON body bekler: {"query": "..."}
                    
                    # Eğer payload JSON formatında değilse sarmala
                    if not payload.strip().startswith("{"):
                         full_payload = f'{{"query": "{{ user(id: \\"{payload}\\") {{ name }} }}"}}'
                    else:
                         full_payload = payload
                         
                    fuzzing_tasks.append(self._test_injection(endpoint_url, full_payload, session, concurrency))

            if fuzzing_tasks:
                self.log(f"[{self.category}] {len(fuzzing_tasks)} adet GraphQL güvenlik testi yürütülüyor...", "INFO")
                await asyncio.gather(*fuzzing_tasks)

        except Exception as e:
            self.log(f"[{self.category}] Kritik Hata: {type(e).__name__} ({e})", "CRITICAL")
            self.add_result(self.category, "CRITICAL", f"GraphQL Tarama Hatası: {str(e)}", 0)

        completed_callback()

    async def _check_endpoint(self, url: str, session: aiohttp.ClientSession, semaphore: asyncio.Semaphore) -> Optional[str]:
        """
        Bir URL'nin GraphQL endpoint'i olup olmadığını kontrol eder.
        """
        async with semaphore:
            try:
                # Jitter / Throttle
                await self._throttled_request(session, "dummy", "dummy") # Sadece delay için, gerçek istek aşağıda

                # Boş bir query göndererek GraphQL olup olmadığını anla
                # GraphQL sunucuları genellikle "Must provide query string" hatası döner
                # veya GET isteğine "GET query missing" der.
                
                # 1. GET İsteği Denemesi
                async with session.get(url, params={"query": "{__typename}"}, timeout=aiohttp.ClientTimeout(total=5)) as res:
                    if res.status == 200:
                         text = await res.text()
                         if "data" in text and "__typename" in text:
                             self.log(f"[{self.category}] GraphQL Endpoint (GET) bulundu: {url}", "SUCCESS")
                             self.add_result(self.category, "INFO", f"GraphQL Endpoint Keşfedildi: {url} (GET Metodu Açık)", 0)
                             return url

                # 2. POST İsteği Denemesi (Boş Body veya __typename)
                headers = {'Content-Type': 'application/json'}
                payload = '{"query": "{__typename}"}'
                
                async with session.post(url, data=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as res:
                    if res.status == 200:
                        text = await res.text()
                        if "data" in text and "__typename" in text:
                            self.log(f"[{self.category}] GraphQL Endpoint (POST) bulundu: {url}", "SUCCESS")
                            self.add_result(self.category, "INFO", f"GraphQL Endpoint Keşfedildi: {url}", 0)
                            return url
                    
                    # Hata mesajından tespit (400 Bad Request dönebilir)
                    if res.status == 400:
                        text = await res.text()
                        for pattern in self.ERROR_PATTERNS:
                            if pattern.search(text):
                                self.log(f"[{self.category}] Olası GraphQL Endpoint (Hata Mesajı): {url}", "INFO")
                                return url

            except Exception:
                pass
            
            return None

    async def _test_introspection(self, url: str, payload: str, session: aiohttp.ClientSession, semaphore: asyncio.Semaphore):
        """
        Introspection sorgusu ile şema ifşasını kontrol eder.
        """
        async with semaphore:
            try:
                await self._throttled_request(session, "dummy", "dummy")
                
                headers = {'Content-Type': 'application/json'}
                
                async with session.post(url, data=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=7)) as res:
                    if res.status == 200:
                        text = await res.text()
                        # Başarılı Introspection işareti
                        if "__schema" in text and "queryType" in text:
                            self.add_result(
                                self.category, 
                                "CRITICAL", 
                                f"KRİTİK: GraphQL Introspection Aktif! Şema yapısı ifşa oluyor. Endpoint: {url}",
                                self._calculate_score_deduction("CRITICAL")
                            )
                            self.log(f"[{self.category}] Introspection BAŞARILI: {url}", "CRITICAL")
                            return

            except Exception as e:
                pass

    async def _test_injection(self, url: str, payload: str, session: aiohttp.ClientSession, semaphore: asyncio.Semaphore):
        """
        SQLi/NoSQLi ve Hata Tabanlı Bilgi İfşası testi.
        """
        async with semaphore:
            try:
                await self._throttled_request(session, "dummy", "dummy")
                headers = {'Content-Type': 'application/json'}
                
                async with session.post(url, data=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=7)) as res:
                    text = await res.text()
                    
                    # 1. SQL Hataları (SQLiScanner pattern'leri kullanılabilir ama burada basit tutalım)
                    sql_errors = ["sql syntax", "mysql_fetch", "pg_query", "ora-", "sqlite_"]
                    if any(err in text.lower() for err in sql_errors):
                         self.add_result(
                            self.category,
                            "CRITICAL",
                            f"KRİTİK: GraphQL üzerinden SQL Hatası döndü (SQLi Potansiyeli). Payload: {payload[:20]}...",
                            self._calculate_score_deduction("CRITICAL")
                        )
                         return

                    # 2. GraphQL Suggestion Leak ("Did you mean...")
                    if "Did you mean" in text:
                        self.add_result(
                            self.category,
                            "WARNING",
                            f"RİSK: GraphQL 'Suggestion' özelliği açık. Alan adlarını tahmin ediyor. Payload: {payload[:20]}...",
                            self._calculate_score_deduction("WARNING")
                        )

            except Exception:
                pass