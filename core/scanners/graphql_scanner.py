# path: core/scanners/graphql_scanner.py

import aiohttp
import asyncio
import re
import json
from typing import Callable, List, Dict, Any, Optional, Set
from urllib.parse import urljoin, urlparse

from core.scanners.base_scanner import BaseScanner
from core.payload_generator import PayloadGenerator


class GraphQLScanner(BaseScanner):
    """
    [FAZ 33 - GRAPHQL HUNTER v2.0 - Asenkron ve AI Destekli]
    GraphQL endpoint'lerini keşfeder ve introspection, injection gibi zafiyetleri test eder.
    Payload Generator ile tam entegre çalışır.
    """

    # Varsayılan limit (Engine tarafından ezilebilir)
    PER_MODULE_LIMIT = 5 

    # Yaygın GraphQL Endpoint Listesi (Genişletilmiş)
    COMMON_ENDPOINTS = [
        "/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql",
        "/graph", "/api/graph", "/graphql/api", "/graphql/v1",
        "/gql", "/query", "/api/query", "/data", "/api/data",
        "/v1/api/graphql", "/v1/graph"
    ]

    # GraphQL Hata Desenleri (Bilgi İfşası)
    ERROR_PATTERNS = [
        re.compile(r"Did you mean", re.IGNORECASE),
        re.compile(r"GraphQL syntax error", re.IGNORECASE),
        re.compile(r"Cannot query field", re.IGNORECASE),
        re.compile(r"Field \".*?\" is not defined", re.IGNORECASE),
        re.compile(r"Must provide query string", re.IGNORECASE),
        re.compile(r"Syntax Error: Expected", re.IGNORECASE),
        re.compile(r"GRAPHQL_VALIDATION_FAILED", re.IGNORECASE),
        re.compile(r"INTERNAL_SERVER_ERROR", re.IGNORECASE),
    ]

    def __init__(self, logger, results_callback, request_callback: Callable[[], None]):
        super().__init__(logger, results_callback, request_callback)
        self.payload_generator = None # Engine tarafından atanacak
        self.discovered_endpoints: Set[str] = set()
        self.module_semaphore = asyncio.Semaphore(self.PER_MODULE_LIMIT)

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

        if self.payload_generator is None:
             self.log(f"[{self.category}] UYARI: Payload Generator yüklenemedi. Standart testler yapılacak.", "WARNING")

        try:
            # 1. Endpoint Keşfi
            tasks = []
            
            # Ana URL'nin kendisi ve yaygın path'ler
            target_urls = set([url])
            for endpoint in self.COMMON_ENDPOINTS:
                target_urls.add(urljoin(url, endpoint))

            for target_url in target_urls:
                tasks.append(self._check_endpoint(target_url, session))

            results = await asyncio.gather(*tasks)
            
            # Keşfedilen geçerli endpointleri topla
            valid_endpoints = [res for res in results if res]
            
            if not valid_endpoints:
                self.log(f"[{self.category}] Yaygın GraphQL endpoint'leri bulunamadı.", "INFO")
                completed_callback()
                return

            # Benzersiz endpointleri sakla
            self.discovered_endpoints.update(valid_endpoints)
            self.log(f"[{self.category}] {len(self.discovered_endpoints)} adet potansiyel GraphQL endpoint bulundu.", "SUCCESS")

            # 2. Introspection ve Fuzzing Testleri
            fuzzing_tasks = []
            
            # Payloadları al (Eğer generator yoksa boş liste döner)
            introspection_payloads = []
            injection_payloads = []

            if self.payload_generator:
                introspection_payloads = self.payload_generator.generate_graphql_introspection_payloads()
                injection_payloads = self.payload_generator.generate_graphql_injection_payloads()
            else:
                 # Fallback payloadlar (Generator yoksa)
                 introspection_payloads = ['{"query": "{__schema{types{name,kind}}}"}']
                 injection_payloads = ['1 OR 1=1']
            
            for endpoint_url in self.discovered_endpoints:
                # A) Introspection Kontrolü
                for payload in introspection_payloads:
                    fuzzing_tasks.append(self._test_introspection(endpoint_url, payload, session))
                
                # B) Injection / Hata Fuzzing
                for payload in injection_payloads:
                    # Payload JSON formatında değilse basit query içine sar
                    if not payload.strip().startswith("{"):
                         full_payload = json.dumps({"query": f"{{ user(id: \"{payload}\") {{ name }} }}"})
                    else:
                         full_payload = payload
                         
                    fuzzing_tasks.append(self._test_injection(endpoint_url, full_payload, session))

            if fuzzing_tasks:
                self.log(f"[{self.category}] {len(fuzzing_tasks)} adet GraphQL güvenlik testi yürütülüyor...", "INFO")
                await asyncio.gather(*fuzzing_tasks)

        except Exception as e:
            self.log(f"[{self.category}] Kritik Hata: {type(e).__name__} ({e})", "CRITICAL")
            self.add_result(self.category, "CRITICAL", f"GraphQL Tarama Hatası: {str(e)}", 0)

        completed_callback()

    async def _check_endpoint(self, url: str, session: aiohttp.ClientSession) -> Optional[str]:
        """
        Bir URL'nin GraphQL endpoint'i olup olmadığını kontrol eder.
        """
        async with self.module_semaphore:
            try:
                self.request_callback()
                # 1. GET İsteği Denemesi
                async with session.get(url, params={"query": "{__typename}"}, timeout=aiohttp.ClientTimeout(total=5)) as res:
                    if res.status == 200:
                         text = await res.text()
                         if "data" in text and "__typename" in text:
                             self.log(f"[{self.category}] GraphQL Endpoint (GET) bulundu: {url}", "SUCCESS")
                             self.add_result(self.category, "INFO", f"GraphQL Endpoint Keşfedildi: {url} (GET Metodu Açık)", 0)
                             return url

                # 2. POST İsteği Denemesi
                headers = {'Content-Type': 'application/json'}
                payload = json.dumps({"query": "{__typename}"})
                
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

    async def _test_introspection(self, url: str, payload: str, session: aiohttp.ClientSession):
        """
        Introspection sorgusu ile şema ifşasını kontrol eder.
        """
        async with self.module_semaphore:
            try:
                self.request_callback()
                headers = {'Content-Type': 'application/json'}
                
                async with session.post(url, data=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=7)) as res:
                    if res.status == 200:
                        text = await res.text()
                        # Başarılı Introspection işareti
                        if "__schema" in text and "queryType" in text:
                            poc_data = {
                                "url": url,
                                "method": "POST",
                                "payload": payload,
                                "response_snippet": text[:200]
                            }
                            
                            self.add_result(
                                self.category, 
                                "CRITICAL", 
                                f"KRİTİK: GraphQL Introspection Aktif! Şema yapısı ifşa oluyor. Endpoint: {url}",
                                self._calculate_score_deduction("CRITICAL"),
                                poc_data=poc_data
                            )
                            self.log(f"[{self.category}] Introspection BAŞARILI: {url}", "CRITICAL")
                            return

            except Exception:
                pass

    async def _test_injection(self, url: str, payload: str, session: aiohttp.ClientSession):
        """
        SQLi/NoSQLi ve Hata Tabanlı Bilgi İfşası testi.
        """
        async with self.module_semaphore:
            try:
                self.request_callback()
                headers = {'Content-Type': 'application/json'}
                
                async with session.post(url, data=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=7)) as res:
                    text = await res.text()
                    
                    # 1. SQL Hataları
                    sql_errors = ["sql syntax", "mysql_fetch", "pg_query", "ora-", "sqlite_"]
                    if any(err in text.lower() for err in sql_errors):
                         self.add_result(
                            self.category,
                            "CRITICAL",
                            f"KRİTİK: GraphQL üzerinden SQL Hatası döndü (SQLi Potansiyeli). Payload: {payload[:50]}...",
                            self._calculate_score_deduction("CRITICAL"),
                            poc_data={"url": url, "payload": payload, "error": text[:100]}
                        )
                         return

                    # 2. GraphQL Suggestion Leak ("Did you mean...")
                    if "Did you mean" in text:
                        self.add_result(
                            self.category,
                            "WARNING",
                            f"RİSK: GraphQL 'Suggestion' özelliği açık. Alan adlarını tahmin ediyor. Payload: {payload[:50]}...",
                            self._calculate_score_deduction("WARNING"),
                             poc_data={"url": url, "payload": payload, "suggestion": text[:100]}
                        )

            except Exception:
                pass
            
    def _calculate_score_deduction(self, level: str) -> float:
        weight = self.engine_instance.MODULE_WEIGHTS.get(self.category, 0.0)
        if level == "CRITICAL": return weight
        elif level == "HIGH": return weight * 0.7
        else: return weight * 0.3