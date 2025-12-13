# path: PARS Pentest Autonomous Recon System/core/engine.py

import datetime
import asyncio
import aiohttp
import time
import threading
import sys
import shutil
import os
import statistics
import re
import json
import math
import random
import concurrent.futures
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
from typing import List, Dict, Any, Optional, Tuple

# Yeni DB Importları
from .database import SessionLocal, init_db
from sqlalchemy.orm import Session as DBSession
from sqlalchemy import select, func # FAZ 27: Modern DB sorgulama için eklendi
from sqlalchemy.orm.exc import NoResultFound # Hata yakalama için eklendi

from .dynamic_scanner import DynamicScanner
from .exploit_manager import ExploitManager
from .dynamic_script_manager import DynamicScriptManager
from .oob_listener import OOBListener
from .proxy_manager import ProxyManager
from .neural_engine import NeuralEngine

from .reporter import SynaraReporter
from .report_manager import ReportManager # ReportManager'ı kullanmak için import
from .payload_generator import PayloadGenerator
from .poc_generator import POCGenerator
from .data_simulator import DataSimulator

from .scanners.headers import HeadersScanner
from .scanners.files import FilesScanner
from .scanners.heuristic import HeuristicScanner
from .scanners.xss import XSSScanner
from .scanners.sqli import SQLiScanner
from .scanners.lfi import LFIScanner
from .scanners.auth_bypass import AuthBypassScanner
from .scanners.idor import IDORScanner
from .scanners.pre_scan import PreScanner
from .scanners.rce_ssrf import RCE_SSRFScanner
from .scanners.json_api_scanner import JSONAPIScanner
from .scanners.port_scanner import PortScanner
from .scanners.waf_detector import WAFDetector
from .scanners.subdomain_scanner import DiscoveryOrchestrator
from .scanners.subdomain_takeover import SubdomainTakeoverScanner
from .scanners.nuclei_scanner import NucleiScanner  # AKTİF EDİLDİ
from .scanners.internal_scanner import InternalScanner
from .scanners.js_finder import JSEndpointScanner
from .scanners.graphql_scanner import GraphQLScanner
from .scanners.cloud_exploit import CloudExploitScanner
from .scanners.react_exploit import ReactExploitScanner
from .scanners.client_logic_analyzer import ClientLogicAnalyzer
from .scanners.http_smuggling_scanner import HTTPSmugglingScanner
from .scanners.business_logic_fuzzer import BusinessLogicFuzzer
from .scanners.osint_scanner import OSINTScanner
from .scanners.leakage_scanner import LeakageScanner
from core.scanners.race_condition import RaceConditionHunter
from core.scanners.llm_prompt_injection import LLMPromptInjectionScanner
from core.scanners.cloud_bucket_leaker import CloudBucketLeakerScanner

# Yeni DB Model Import'u (Post-Scan Analysis için gerekli)
from .models import Vulnerability

# --- CONFIGURATION ---
MAX_GLOBAL_CONCURRENCY = 10
PER_MODULE_LIMIT = 5
NUCLEI_LIMIT = 3
MAX_WORKER_THREADS = 10
MODULE_HARD_TIMEOUT = 90
MIN_TIMEOUT = 2.0
MAX_TIMEOUT = 7.0
MAX_REQUEST_RETRIES = 1
JS_ENDPOINT_PATTERN = r'[A-Za-z0s9_\-]+\.(php|json|js|jsp|aspx)'
FP_DB_PATH = "fp_database.json"
MAX_QPS = 5.0
BURST = 10.0
MAX_THROTTLE_WAIT_TIME = 2.5
AI_QUEUE_QPS = 1.0

# --- PROFILES ---
SCAN_PROFILES = {
    "FULL_SCAN": {
        "description": "Tüm modüller (Hafiften Kapsamlı Fuzzing'e kadar). En yavaş ve en derin tarama.",
        "modules": ['WAF_DETECT', 'SUBDOMAIN', 'SUBDOMAIN_TAKEOVER', 'PRE_SCAN', 'HEADERS', 'FILES', 'PORT_SCAN', 'HEURISTIC', 'AUTH_BYPASS', 'LFI', 'XSS', 'SQLI', 'IDOR', 'RCE_SSRF', 'JSON_API', 'CLOUD_EXPLOIT', 'REACT_EXPLOIT', 'NUCLEI', 'INTERNAL_SCAN', 'JS_ENDPOINT', 'GRAPHQL', 'CLIENT_LOGIC', 'HTTP_SMUGGLING', 'BUSINESS_LOGIC', 'OSINT', 'LEAKAGE', 'RACE_CONDITION', 'LLM_INJECTION', 'CLOUD_BUCKET']
    },
    "BUG_BOUNTY_CORE": {
        "description": "BBH (Bug Bounty Hunter - SADECE KAZANÇ): Yüksek Ödüllü Kritik Zafiyetler ve Gelişmiş Keşif için optimize edilmiştir.",
        "modules": ['WAF_DETECT', 'SUBDOMAIN', 'SUBDOMAIN_TAKEOVER', 'PRE_SCAN', 'JS_ENDPOINT', 'HEADERS', 'FILES', 'HEURISTIC', 'AUTH_BYPASS', 'LFI', 'XSS', 'SQLI', 'IDOR', 'RCE_SSRF', 'REACT_EXPLOIT', 'JSON_API', 'CLOUD_EXPLOIT', 'PORT_SCAN', 'CLIENT_LOGIC', 'HTTP_SMUGGLING', 'BUSINESS_LOGIC', 'OSINT', 'LEAKAGE', 'RACE_CONDITION', 'LLM_INJECTION', 'CLOUD_BUCKET']
    },
    "LIGHT": {
        "description": "Sadece Temel Analiz ve Zeka (Headers, Files, Heuristic). Çok hızlı.",
        "modules": ['WAF_DETECT', 'SUBDOMAIN', 'PRE_SCAN', 'JS_ENDPOINT', 'HEADERS', 'FILES', 'PORT_SCAN', 'HEURISTIC', 'INTERNAL_SCAN', 'CLIENT_LOGIC', 'OSINT', 'LEAKAGE', 'CLOUD_BUCKET']
    },
    "FUZZING_ONLY": {
        "description": "Sadece Fuzzing Modülleri (XSS, SQLi, LFI, RCE).",
        "modules": ['WAF_DETECT', 'PRE_SCAN', 'LFI', 'XSS', 'SQLI', 'IDOR', 'RCE_SSRF', 'REACT_EXPLOIT', 'GRAPHQL', 'RACE_CONDITION', 'LLM_INJECTION']
    },
    "INTERNAL_MISSION": {
        "description": "Sadece Synara'nın çekirdeğini (Codebase, Manifest, Sırlar) analiz eder.",
        "modules": ['INTERNAL_SCAN', 'HEADERS']
    },
    # SaaS Profiles
    "SAAS_USER": {
        "description": "SaaS USER Plan: Temel Keşif ve Bilgi Toplama.",
        "modules": ['WAF_DETECT', 'SUBDOMAIN', 'HEADERS', 'FILES', 'PORT_SCAN', 'OSINT', 'LEAKAGE', 'JS_ENDPOINT']
    },
    "SAAS_PRO": {
        "description": "SaaS PRO Plan: Mantıksal ve Yetki Testleri.",
        "modules": ['WAF_DETECT', 'PRE_SCAN', 'AUTH_BYPASS', 'IDOR', 'JSON_API', 'GRAPHQL', 'CLIENT_LOGIC', 'BUSINESS_LOGIC', 'LLM_INJECTION']
    },
    "SAAS_ENTERPRISE": {
        "description": "SaaS ENTERPRISE Plan: Derin Enjeksiyon, SSRF ve AI Chaining.",
        "modules": ['SQLI', 'XSS', 'LFI', 'RCE_SSRF', 'CLOUD_EXPLOIT', 'HTTP_SMUGGLING', 'RACE_CONDITION', 'NUCLEI', 'REACT_EXPLOIT', 'LLM_INJECTION', 'CLOUD_BUCKET']
    },
    "SAAS_CORE": {
        "description": "SaaS CORE Plan: Tam Saldırı, Auto-POC ve Exploit Önerileri.",
        "modules": ['WAF_DETECT', 'SUBDOMAIN', 'SUBDOMAIN_TAKEOVER', 'PRE_SCAN', 'HEADERS', 'FILES', 'PORT_SCAN', 'HEURISTIC', 'AUTH_BYPASS', 'LFI', 'XSS', 'SQLI', 'IDOR', 'RCE_SSRF', 'JSON_API', 'CLOUD_EXPLOIT', 'REACT_EXPLOIT', 'NUCLEI', 'INTERNAL_SCAN', 'JS_ENDPOINT', 'GRAPHQL', 'CLIENT_LOGIC', 'HTTP_SMUGGLING', 'BUSINESS_LOGIC', 'OSINT', 'LEAKAGE', 'RACE_CONDITION', 'LLM_INJECTION', 'CLOUD_BUCKET']
    }
}


class SynaraScannerEngine:
    """
    Synara'nın ana tarama motoru.
    """
    MODULE_WEIGHTS = {
        "SQLI": 20.0,
        "RCE_SSRF": 18.0,
        "REACT_RCE": 25.0,
        "LFI": 15.0,
        "AUTH_BYPASS": 12.0,
        "XSS": 10.0,
        "IDOR": 8.0,
        "FILES": 6.0,
        "HEADERS": 0.0,
        "HEURISTIC": 3.0,
        "JSON_API": 3.0,
        "GRAPHQL": 12.0,
        "CLOUD_EXPLOIT": 25.0,
        "CLOUD_BUCKET": 20.0,
        "SUBDOMAIN_TAKEOVER": 25.0,
        "HTTP_SMUGGLING": 22.0,
        "CLIENT_LOGIC": 18.0,
        "BUSINESS_LOGIC": 18.0,
        "RACE_CONDITION": 15.0,
        "LLM_INJECTION": 20.0,
        "PORT_SCAN": 5.0,
        "WAF_DETECT": 0.0,
        "SUBDOMAIN": 0.0,
        "NUCLEI": 0.0,
        "CHAINING": 15.0,
        "SYSTEM": 5.0,
        "INTERNAL_SCAN": 20.0,
        "OSINT": 4.0,
        "LEAKAGE": 25.0
    }

    DEFAULT_PROFILE = "BUG_BOUNTY_CORE"

    def __init__(self, logger_callback=None, progress_callback=None, config_profile: str = DEFAULT_PROFILE):
        self.log = logger_callback if logger_callback else self._headless_log
        self.progress_update = progress_callback if progress_callback else self._headless_progress
        
        self.score = 100.0
        # self.results = [] # FAZ 27: DB'ye taşındı, artık burada tutulmuyor.
        self.start_time = None
        self.target_url = ""
        
        # FAZ 27: DB Oturumu ve Rapor Yöneticisi
        self.db: Optional[DBSession] = None 
        self.report_manager: Optional[ReportManager] = None
        
        self.reporter = SynaraReporter(self) # SynaraReporter hala Engine'ı referans almalı.
        self.oob_listener: Optional[OOBListener] = None
        
        self.use_proxy = False
        self.proxy_manager = ProxyManager(self.log, enabled=self.use_proxy)
        self.neural_engine = NeuralEngine(self.log)
        
        self.ai_request_queue: asyncio.Queue = asyncio.Queue()
        self.ai_queue_task: Optional[asyncio.Task] = None

        self.config_profile = config_profile
        self.total_cvss_deduction = 0.0

        self.module_deduction_tracker = {mod: False for mod in self.MODULE_WEIGHTS.keys()}
        self.port_deduction_tracker = set()

        self.total_requests = 0
        self.dynamic_scanner = None
        self.exploit_manager = None
        self.script_manager = None

        self.discovered_params = set()
        self.calibration_latency_ms = 4000
        self.throttle_delay_ms = 0
        self.latency_cv = 0.0
        self.calibration_headers: Dict[str, str] = {}

        self.fp_database: List[Dict[str, str]] = self._load_fp_database()

        self.token_count = BURST
        self.last_request_time = time.time()

        self._pre_scanners = []
        self._main_scanners = []

        self.total_scanners = 0
        self.scanners_completed = 0
        self.progress_update(0)

        self.protected_domains = self._load_protected_domains()
        self.stop_requested = False
        
        self.thread_executor = concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKER_THREADS)
        self.log(f"[PERFORMANS] Thread Pool Executor başlatıldı (Workers: {MAX_WORKER_THREADS}).", "INFO")

    def _headless_log(self, message, level="INFO"):
        pass

    def _headless_progress(self, val):
        pass

    def _get_base_path(self):
        if getattr(sys, 'frozen', False):
            return os.path.dirname(sys.executable)
        return os.getcwd()

    def _get_hostname(self, url: str) -> str:
        try:
            parsed = urlparse(url)
            netloc = parsed.netloc.split(':')[0]
            if netloc.startswith('www.'):
                return netloc[4:]
            return netloc
        except:
            return ""

    def _load_protected_domains(self) -> List[str]:
        protected_file_path = os.path.join(self._get_base_path(), "protected_domains.json")
        if not os.path.exists(protected_file_path):
            self.log("[GÜVENLİK] UYARI: protected_domains.json bulunamadı. Koruma filtresi devre dışı.", "WARNING")
            return []
        try:
            with open(protected_file_path, 'r', encoding='utf-8') as f:
                domains = json.load(f)
                if isinstance(domains, list) and all(isinstance(d, str) for d in domains):
                    self.log(f"[GÜVENLİK] {len(domains)} adet korunan alan adı yüklendi.", "INFO")
                    return domains
                else:
                    self.log("[GÜVENLİK] HATA: protected_domains.json geçersiz formatte.", "CRITICAL")
                    return []
        except Exception as e:
            self.log(f"[GÜVENLİK] JSON okuma hatası: {str(e)}. Koruma filtresi devre dışı.", "CRITICAL")
            return []

    def _load_fp_database(self) -> List[Dict[str, str]]:
        fp_file_path = os.path.join(self._get_base_path(), FP_DB_PATH)
        if not os.path.exists(fp_file_path):
            self.log(f"[ML-FP] UYARI: Hata Pozitif Veritabanı ({FP_DB_PATH}) bulunamadı. Boş DB ile devam ediliyor.", "WARNING")
            return []
        try:
            with open(fp_file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, list):
                    self.log(f"[ML-FP] {len(data)} adet bilinen Hata Pozitif kaydı yüklendi.", "INFO")
                    return data
                else:
                    self.log("[ML-FP] HATA: FP Veritabanı geçersiz formatte.", "CRITICAL")
                    return []
        except Exception as e:
            self.log(f"[ML-FP] Veritabanı okuma hatası: {str(e)}. Boş DB ile devam ediliyor.", "CRITICAL")
            return []

    def _is_false_positive(self, category: str, message: str) -> bool:
        if not self.fp_database:
            return False
        lower_message = message.lower()
        for fp_entry in self.fp_database:
            if fp_entry.get("category") == category:
                fp_message = fp_entry.get("message", "").lower()
                escaped_fp_message = re.escape(fp_message)
                if re.search(escaped_fp_message, lower_message):
                    self.log(f"[{category} | FP TESPİTİ] Bulgu, bilinen hata pozitif veritabanı ile eşleşti. Raporlama atlandı.", "INFO")
                    return True
        return False

    def increment_request_count(self):
        self.total_requests += 1

    def add_discovered_param(self, param_name: str):
        self.discovered_params.add(param_name)
        self.log(f"[PRE-SCAN] Yeni parametre keşfedildi: '{param_name}'", "INFO")

    def _recalculate_score(self):
        # FAZ 27: Skoru hesaplamak için artık DB'deki zafiyetleri çekmemiz gerekiyor.
        if not self.report_manager or not self.report_manager.scan_id:
            # Tarama başlatılmadıysa veya DB bağlantısı yoksa skor 100.
            self.score = 100.0
            return

        # ReportManager'dan zafiyetleri çek (DB'den çekecektir)
        current_results = self.report_manager.get_vulnerabilities()
        
        total_deduction = 0.0
        
        # Mevcut sonuç listesi yerine, DB'deki zafiyet tiplerine göre SRP düşüşü hesaplanıyor.
        unique_categories = set()
        for res in current_results:
            unique_categories.add(res['type'])

        for category in unique_categories:
            # Bu, her kategorideki en yüksek riskli tek bir bulgu için SRP düşüşünü temsil eder (modül başına bir kez düşüş).
            # Detaylı SRP hesaplaması `add_result` içinde yapılıyordu, bu kısım basit tutuldu.
            total_deduction += self.MODULE_WEIGHTS.get(category, 0.0) 
            
        # Önemli Düzeltme: `total_cvss_deduction` değişkenini kullanmaya geri dönülmeli, 
        # fakat bu değişkenin sadece `add_result` içinde güncellendiğinden emin olunmalı.
        self.score = max(0.0, 100.0 - self.total_cvss_deduction)


    def add_result(self, category: str, level: str, message: str, cvss_score: float, poc_data: Optional[Dict[str, Any]] = None):
        if self._is_false_positive(category, message):
            self.log(f"[{category} | FP TESPİTİ] Bulgu, bilinen hata pozitif veritabanı ile eşleşti. Raporlama atlandı.", "INFO")
            return

        original_score = cvss_score
        original_level = level
        srp_deduction = 0.0

        # --- SRP Düşüş Hesaplama Mantığı (Aynı Bırakıldı) ---
        if level == "CRITICAL":
            srp_deduction = self.MODULE_WEIGHTS.get(category, 0.0)
        elif level == "HIGH":
            srp_deduction = self.MODULE_WEIGHTS.get(category, 0.0) * 0.7
        elif level == "WARNING":
            srp_deduction = self.MODULE_WEIGHTS.get(category, 0.0) * 0.3
        else:
            srp_deduction = 0.0

        is_google = "google.com" in self.target_url.lower() or "gmail.com" in self.target_url.lower()
        is_time_based_sqli = category == "SQLI" and "Time-Based SQLi" in message
        is_idor = category == "IDOR" and original_score > 0

        if is_google and (is_time_based_sqli or is_idor):
            level = "INFO"
            srp_deduction = 0.0
            message += " [UYARI: HYPERSCALE FİLTRESİ AKTİF. Güvenilirlik 0.0'a düşürüldü.]"

        if category in self.MODULE_WEIGHTS and category not in ["PORT_SCAN", "SYSTEM"]:
            if srp_deduction > 0.0 and self.module_deduction_tracker.get(category, False):
                srp_deduction = 0.0
            elif srp_deduction > 0.0:
                self.module_deduction_tracker[category] = True
        elif category in ["PORT_SCAN", "SYSTEM"]:
            pass
            
        exploit_suggestion = ""
        if original_level in ["CRITICAL", "HIGH", "CHAINING_CRITICAL"] and self.exploit_manager:
            exploit_suggestion = self.exploit_manager.generate_exploit_suggestion(
                {'category': category, 'level': original_level, 'cvss_score': original_score}
            )
            if level == "INFO" and exploit_suggestion:
                exploit_suggestion = "[Exploit önerisi filtrelendi: Büyük ölçekli ortamda manuel doğrulama gerekli.]"
            elif exploit_suggestion and "Otomatik sömürü önerisi bulunamadı." not in exploit_suggestion:
                message += f" [Exploit Önerisi: {exploit_suggestion}]"

        critical_ai_categories = ["RCE_SSRF", "CLOUD_EXPLOIT", "LEAKAGE", "REACT_RCE", "HTTP_SMUGGLING", "INTERNAL_SCAN", "SQLI", "AUTH_BYPASS"]
        
        if self.neural_engine.is_active and category in critical_ai_categories and original_level in ["CRITICAL", "HIGH"]:
            if self.exploit_manager:
                vuln_data_for_ai = {
                    "category": category,
                    "level": original_level,
                    "message": message,
                    "url": poc_data.get('url', self.target_url) if poc_data else self.target_url
                }
                self.run_manual_exploit("CRITICAL_AI_ANALYSIS", json.dumps(vuln_data_for_ai))
                message += " [AI DERİN ANALİZ BAŞLATILDI]"
            else:
                message += " [AI Analiz Motoru Hazır Değil.]"

        generated_poc_report = None
        if poc_data and level in ["CRITICAL", "HIGH", "WARNING"]:
            try:
                vuln_url = poc_data.get('url', self.target_url)
                generated_poc_report = POCGenerator.create_vulnerability_report(
                    vuln_name=category,
                    severity=level,
                    target_url=vuln_url,
                    description=message,
                    impact="Potential unauthorized access, data leakage, or remote code execution depending on the context.",
                    poc_inputs=poc_data
                )
                message += " [AUTO-POC OLUŞTURULDU]"
                if level == "CRITICAL":
                    self.log(f"[{category}] Otomatik POC kanıtı ve raporu başarıyla oluşturuldu.", "SUCCESS")
                
            except Exception as e:
                self.log(f"[{category}] POC oluşturma hatası: {e}", "WARNING")
        
        # FAZ 27: DB'ye kaydetme işlemi burada yapılmalı (ReportManager üzerinden)
        if self.report_manager:
            self.report_manager.add_vulnerability(
                type=category,
                severity=level,
                url=poc_data.get('url', self.target_url) if poc_data else self.target_url,
                parameter=poc_data.get('param', None) if poc_data else None,
                payload=poc_data.get('payload', None) if poc_data else None,
                proof=generated_poc_report, # POC raporunu kanıt olarak kaydediyoruz
                request_data=poc_data.get('raw_request', None) if poc_data else None
            )
        
        # DİKKAT: Eski RAM tabanlı `self.results.append` kaldırıldı.
        # cvss_score (srp_deduction) hesaplamasını `total_cvss_deduction` değişkenine yansıt.
        self.total_cvss_deduction += srp_deduction

        self._recalculate_score()
        self.log(f"[{category} | SRP Düşüş: {srp_deduction:.1f}] {message}", level)
        
    def stop_scan(self):
        self.log("[MOTOR] Durdurma sinyali (STOP) alındı. İşlemler iptal ediliyor...", "WARNING")
        self.stop_requested = True
        self.proxy_manager.stop_updater()
        
        if self.ai_queue_task:
            self.ai_queue_task.cancel()
            self.log("[NEURAL] AI Kuyruk İşçisi (Worker) iptal edildi.", "INFO")
        
        self.log("[PERFORMANS] Thread Pool Executor kapatılıyor...", "INFO")
        self.thread_executor.shutdown(wait=False)
        
        # FAZ 27: Tarama sonlandırıldığında DB oturumunu kapat
        if self.report_manager:
            self.report_manager.finish_scan(status="CANCELED")
        if self.db:
            self.db.close()


    async def _ai_queue_worker(self):
        self.log(f"[NEURAL] AI Kuyruk İşçisi başlatıldı (Hız: {AI_QUEUE_QPS} QPS).", "SUCCESS")
        
        try:
            while not self.stop_requested:
                item = await self.ai_request_queue.get()
                context_data, vuln_type, count, future_obj = item
                
                self.log(f"[NEURAL] Kuyruktan AI isteği çekildi ({vuln_type}, Kalan: {self.ai_request_queue.qsize()}).", "INFO")

                try:
                    payloads = await self.neural_engine.generate_ai_payloads(context_data, vuln_type, count)
                    
                    # KRİTİK DÜZELTME (v2.5.10): Neural Engine'dan dönen sonucun tip kontrolü
                    if not isinstance(payloads, List):
                        error_msg = f"AI Payload üretimi KRİTİK HATA: Beklenen 'List' yerine '{type(payloads).__name__}' tipinde yanıt alındı."
                        self.log(f"[NEURAL] {error_msg}", "CRITICAL")
                        # Hatalı tipte ise simüle edilmiş payload'ları kullan
                        payloads = DataSimulator.simulate_ai_payloads(vuln_type, count)
                    
                    if not future_obj.done():
                        future_obj.set_result(payloads)
                except Exception as e:
                    self.log(f"[NEURAL] KRİTİK HATA: AI Payload üretimi başarısız oldu: {e}", "CRITICAL")
                    if not future_obj.done():
                        # Hata durumunda bile DataSimulator'dan gelen liste tipini garanti et
                        simulated_payloads = DataSimulator.simulate_ai_payloads(vuln_type, count)
                        if not isinstance(simulated_payloads, List):
                            self.log(f"[NEURAL] DataSimulator'dan da hatalı tip geldi: {type(simulated_payloads).__name__}. Boş liste kullanılıyor.", "CRITICAL")
                            simulated_payloads = []
                        future_obj.set_result(simulated_payloads)
                        
                self.ai_request_queue.task_done()
                sleep_time = 1.0 / AI_QUEUE_QPS
                await asyncio.sleep(sleep_time)

        except asyncio.CancelledError:
            self.log("[NEURAL] AI Kuyruk İşçisi (Worker) iptal sinyali aldı.", "WARNING")
        except Exception as e:
            self.log(f"[NEURAL] İşçi beklenmedik hata verdi: {e}", "CRITICAL")
        
        self.log("[NEURAL] AI Kuyruk İşçisi durduruldu.", "WARNING")

    async def queue_ai_payload_request(self, context_data: Dict[str, Any], vulnerability_type: str, count: int = 5) -> List[str]:
        if not self.neural_engine.is_active:
            self.log("[PAYLOAD GOV] AI pasif. Simüle payload kullanılıyor.", "WARNING")
            return DataSimulator.simulate_ai_payloads(vulnerability_type, count)

        future_result = asyncio.get_running_loop().create_future()
        await self.ai_request_queue.put((context_data, vulnerability_type, count, future_result))
        self.log(f"[PAYLOAD GOV] AI Payload isteği sıraya eklendi ({vulnerability_type}, Kuyruk: {self.ai_request_queue.qsize()}).", "INFO")
        
        try:
            payloads = await asyncio.wait_for(future_result, timeout=40.0) 
            return payloads
        except asyncio.TimeoutError:
            self.log("[PAYLOAD GOV] HATA: AI Kuyruk Zaman Aşımı (40.0s). Simüle payload kullanılıyor.", "CRITICAL")
            return DataSimulator.simulate_ai_payloads(vulnerability_type, count)
        except Exception as e:
            self.log(f"[PAYLOAD GOV] HATA: AI Kuyruk İletişim Hatası ({e}). Simüle payload kullanılıyor.", "CRITICAL")
            return DataSimulator.simulate_ai_payloads(vulnerability_type, count)

    async def _run_calibration_scan(self, session, url):
        self.log("\n--- SİSTEM KALİBRASYONU BAŞLATILIYOR (90. Persentil Ölçümü) ---", "HEADER")

        NUM_TESTS = 5 # DÜZELTME: 10'dan 5'e düşürüldü
        latency_list = []
        rate_limit_headers = ["X-RateLimit-Limit", "Retry-After", "X-Request-Attempt", "X-Cache", "CF-RAY", "Server-Timing"]

        try:
            for i in range(NUM_TESTS):
                if self.stop_requested:
                    self.log("[KALİBRASYON] Kullanıcı iptali nedeniyle durduruldu.", "WARNING")
                    return

                start = time.time()
                await self._apply_jitter_and_throttle()
                self.increment_request_count()

                async with session.get(url, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=10)) as res: # DÜZELTME: Timeout 5s'den 10s'ye çıkarıldı
                    if i == 0:
                        self.calibration_headers = {h: res.headers.get(h, "") for h in rate_limit_headers}
                    await res.read()
                end = time.time()
                latency_list.append(end - start)

            if len(latency_list) < NUM_TESTS:
                raise Exception("Yetersiz kalibrasyon verisi.")

            latency_list.sort()
            # P90 hesaplama mantığı, 5 test için index 4 veya 3'e denk gelir.
            if len(latency_list) >= 5:
                # P90'ı hesaplayalım. 5 eleman için 0.9 * 5 = 4.5. Index 4 (yani son eleman) P100'e yakındır.
                # Daha güvenli bir ortalama almak için P90 indeksi kullanılıyor.
                p90_index = int(0.9 * len(latency_list) - 1) 
                p90_latency_s = latency_list[min(p90_index, len(latency_list) - 1)]
            else:
                # Bu blok teorik olarak çalışmamalı (çünkü len(latency_list) < NUM_TESTS zaten hata fırlatır)
                p90_latency_s = max(latency_list)


            mean = statistics.mean(latency_list)
            stdev = statistics.stdev(latency_list) if len(latency_list) > 1 else 0.0
            latency_cv = (stdev / mean) if mean != 0 else 0.0
            self.latency_cv = latency_cv

            self.log(f"[KALİBRASYON] P90 Yanıt Süresi (Baseline): {p90_latency_s*1000:.2f} ms", "INFO")

            DYNAMIC_THRESHOLD_SAFETY_FACTOR = 1.0
            dynamic_threshold_s = p90_latency_s + DYNAMIC_THRESHOLD_SAFETY_FACTOR
            self.calibration_latency_ms = dynamic_threshold_s * 1000

            self.log(f"[KALİBRASYON] Dinamik SQLi Zaman Eşiği (Threshold): {dynamic_threshold_s:.2f} saniye olarak belirlendi (P90 + {DYNAMIC_THRESHOLD_SAFETY_FACTOR}s).", "SUCCESS")
            self.log(f"[KALİBRASYON] Yanıt Gecikme Varyansı (CV): {latency_cv:.2f}", "INFO")

            if dynamic_threshold_s > 1.5:
                self.throttle_delay_ms = int((dynamic_threshold_s / 3) * 1000)
                if dynamic_threshold_s > 6.0:
                    self.throttle_delay_ms = 2000
                self.log(f"[KALİBRASYON] Yüksek Dinamik Eşik tespit edildi. Dinamik Throttling (Yavaşlatma) {self.throttle_delay_ms:.0f} ms olarak ayarlandı.", "WARNING")
            else:
                self.throttle_delay_ms = 0

        except Exception as e:
            self.log(f"[KALİBRASYON] Kalibrasyon Hatası ({type(e).__name__}): Sabit 4.0s eşiği kullanılacak.", "CRITICAL")
            self.calibration_latency_ms = 4000

        return
    
    def _analyze_and_prioritize_main_scanners(self, final_url: str):
        self.log("\n--- FAZ 25: NEURAL TAKTİK MÜDAHALE BAŞLATILIYOR (Dinamik Önceliklendirme) ---", "HEADER")
        
        waf_scanner = next((s for s in self._pre_scanners if s.category == 'WAF_DETECT'), None)
        waf_detected = waf_scanner.waf_found if waf_scanner and hasattr(waf_scanner, 'waf_found') else False
        
        param_count = len(self.discovered_params)
        priorities: Dict[str, float] = {}
        
        for scanner in self._main_scanners:
            score = 0.0
            category = scanner.category
            
            if waf_detected:
                if category == 'HTTP_SMUGGLING': score += 5.0
                if category == 'BUSINESS_LOGIC': score += 3.0
            
            if param_count > 0:
                if category in ['SQLI', 'XSS', 'LFI', 'RCE_SSRF']: score += 2.0
                if category == 'JSON_API': score += 4.0
                
            if category in ['CLOUD_EXPLOIT', 'REACT_EXPLOIT', 'INTERNAL_SCAN']:
                score += 4.0
            
            if category in ['HEADERS', 'FILES', 'HEURISTIC', 'PORT_SCAN']:
                if category != 'HEURISTIC': score -= 1.0
                
            max_srp = self.MODULE_WEIGHTS.get(category, 0.0)
            score += min(5.0, max_srp / 5.0) 

            priorities[category] = score
        
        self._main_scanners.sort(key=lambda s: priorities.get(s.category, 0.0), reverse=True)
        self.log(f"[NEURAL TAKTİK] Ana Tarama modülleri {len(self._main_scanners)} modül bazında yeniden önceliklendirildi.", "SUCCESS")
        
        new_order = [(s.category, priorities.get(s.category, 0.0)) for s in self._main_scanners]
        self.log(f"[NEURAL TAKTİK] Yeni Çalışma Sırası (Modül: Skor): {[f'{cat}:{score:.1f}' for cat, score in new_order]}", "INFO")
        
        return new_order

    def _run_chaining_analysis(self):
        self.log("\n--- ZAFİYET ZİNCİRLEME ANALİZİ BAŞLATILIYOR (Exploitability Score) ---", "HEADER")

        # FAZ 27: self.results yerine DB'den verileri çekerek analiz yapmalıyız.
        if not self.report_manager:
            self.log("[CHAINING] Rapor Yöneticisi başlatılmadı. Analiz atlandı.", "WARNING")
            return

        current_results = self.report_manager.get_vulnerabilities()
        
        # GÜVENLİK DÜZELTMESİ: current_results boş (None veya boş liste) ise döngüye girmeden dön
        if not current_results:
            self.log("[CHAINING] Zafiyet bulunamadı. Analiz atlandı.", "INFO")
            return

        lfi_or_ssrf_found = any(res['type'] in ['LFI', 'RCE_SSRF'] and res['severity'] == 'CRITICAL' for res in current_results)
        rce_or_file_found = any((res['type'] == 'RCE_SSRF' and 'RCE Tespiti!' in res['proof']) or (res['type'] == 'FILES' and res['severity'] == 'CRITICAL') for res in current_results)
        
        json_api_issue_found = any(res['type'] == 'JSON_API' and res['severity'] in ['CRITICAL', 'WARNING'] for res in current_results)
        xss_or_sqli_found = any(res['type'] in ['XSS', 'SQLI'] and res['severity'] == 'CRITICAL' for res in current_results)
        
        heuristic_scanner = next((s for s in self._main_scanners if s.category == 'HEURISTIC'), None)
        is_heuristic_reflected = heuristic_scanner and hasattr(heuristic_scanner, 'reflection_info') and heuristic_scanner.reflection_info.get("is_reflected")
        
        xss_found_critical = any(res['type'] == 'XSS' and res['severity'] == 'CRITICAL' for res in current_results)
        
        if lfi_or_ssrf_found and rce_or_file_found:
            srp_deduction = self.MODULE_WEIGHTS.get("CHAINING", 0.0)
            self.add_result("CHAINING", "CRITICAL", "KRİTİK ZİNCİRLEME: Yüksek riskli LFI/SSRF zafiyetleri ile RCE/Hassas Dosya İfşası (FILES) potansiyeli tespit edildi. Exploitability Score YÜKSEK.", srp_deduction)
            self.log("[CHAINING] Zafiyet Zinciri Başarısı: Potansiel RCE yolu bulundu.", "CRITICAL")
            return

        if is_heuristic_reflected and xss_found_critical:
            srp_deduction = self.MODULE_WEIGHTS.get("CHAINING", 0.0) * 0.7
            self.add_result("CHAINING", "HIGH", "YÜKSEK ZİNCİRLEME: Heuristic yansıma testi pozitif. Kanıtlanmış XSS zafiyeti (XSS Modülü) bu yansıma noktasını exploit ediyor olabilir. Exploitability Score YÜKSEK.", srp_deduction)
            self.log("[CHAINING] Zafiyet Zinciri Başarısı: Heuristic Reflection + XSS Tespiti.", "HIGH")
            return

        if json_api_issue_found and xss_or_sqli_found:
            srp_deduction = self.MODULE_WEIGHTS.get("CHAINING", 0.0) * 0.5
            self.add_result("CHAINING", "WARNING", "RİSK ZİNCİRLEME: API endpoint'lerinde XSS/SQLi potansiyeli ve JSON API Fuzzing hataları tespit edildi. Bağlam zafiyeti riski.", srp_deduction)
            self.log("[CHAINING] Zafiyet Zinciri Başarısı: API Erişim/Enjeksiyon Zafiyeti.", "WARNING")
            return

        self.log("[CHAINING] Zafiyet zincirleme analizini tamamlandı. Yüksek riskli zincir bulunamadı.", "INFO")

    def _run_post_scan_analysis(self):
        self.log("\n--- POST-SCAN ANALİZİ BAŞLATILIYOR (Güvenilirlik Skorlaması) ---", "HEADER")

        # FAZ 27: self.results yerine DB'den çekilen veriler üzerinden işlem yapılmalı.
        if not self.report_manager:
            self.log("[POST-SCAN] Rapor Yöneticisi başlatılmadı. Analiz atlandı.", "WARNING")
            return
        
        # Sadece bu aşamada DB'ye yazma işlemi yapılacağı için DB oturumunun açık olduğunu varsayıyoruz (start_scan içinde açıldı).
        if not self.db:
            self.log("[POST-SCAN] Veritabanı oturumu mevcut değil. XSS düzeltmesi atlandı.", "CRITICAL")
            return

        # Zafiyetleri çekmek için yeni bir oturum kullanmaya gerek yok, ReportManager içindeki oturumu kullanmalıyız.
        current_results = self.report_manager.get_vulnerabilities()
        
        # GÜVENLİK DÜZELTMESİ: current_results boş (None veya boş liste) ise döngüye girmeden dön
        if not current_results:
            self.log("[POST-SCAN] Zafiyet bulunamadı. Analiz atlandı.", "INFO")
            return

        is_csp_active = False
        for res in current_results:
            # Kanıt (proof) alanını kullanıyoruz
            if res['type'] == 'HEADERS' and res['severity'] == 'SUCCESS' and 'CSP politikası aktif' in res['proof']: 
                is_csp_active = True
                break

        if not is_csp_active:
            self.log("[POST-SCAN] CSP bulunamadı, XSS sonuçları olduğu gibi bırakılıyor.", "INFO")
            return

        xss_fixes_count = 0
        for res in current_results:
            if res['type'] == 'XSS' and res['severity'] == 'CRITICAL':
                # DB'deki kaydı güncelle
                original_srp_score = self.MODULE_WEIGHTS.get("XSS", 0.0)
                new_srp_score = self.MODULE_WEIGHTS.get("XSS", 0.0) * 0.3
                
                # Düşüş farkını global toplamdan çıkar
                deduction_difference = original_srp_score - new_srp_score
                self.total_cvss_deduction -= deduction_difference
                
                # Güncelleme işlemi için DB oturumu kullanılmalı
                try:
                    # SQLAlchemy 2.0 stilini kullanarak kaydı çek (query() yerine select())
                    vuln_to_update = self.db.scalars(
                        select(Vulnerability).filter(
                            Vulnerability.scan_id == self.report_manager.scan_id, 
                            Vulnerability.id == res['id']
                        )
                    ).one()
                    
                    vuln_to_update.severity = 'WARNING'
                    vuln_to_update.proof = "[POST-SCAN DÜZELTME] " + vuln_to_update.proof + " | Yüksek CSP varlığı nedeniyle SRP Düşüş {:.1f} seviyesinden {:.1f} seviyesine düşürüldü.".format(original_srp_score, new_srp_score)
                    self.db.commit()
                    self.log(f"[{res['type']}] [DÜZELTİLDİ] XSS sonucu CSP nedeniyle WARNING'e düşürüldü.", "WARNING")
                except NoResultFound:
                    self.db.rollback()
                    self.log(f"[POST-SCAN] DB XSS güncelleme hatası: Zafiyet ID {res['id']} bulunamadı.", "WARNING")
                    continue # Sonraki sonuca geç
                except Exception as e:
                    self.db.rollback()
                    self.log(f"[POST-SCAN] DB XSS güncelleme hatası: {e}", "CRITICAL")
                    continue # Sonraki sonuca geç

                xss_fixes_count += 1

        if xss_fixes_count > 0:
            self._recalculate_score()
            self.log(f"[POST-SCAN] XSS Güvenilirlik Ayarlaması Tamamlandı. {xss_fixes_count} zafiyet düşürüldü.", "SUCCESS")
        else:
            self.log("[POST-SCAN] XSS sonuçlarında düzeltme gerekmedi.", "INFO")

    async def _apply_jitter_and_throttle(self):
        jitter_delay = random.uniform(0.07, 0.13)
        await asyncio.sleep(jitter_delay)

        time_elapsed = time.time() - self.last_request_time
        self.token_count += time_elapsed * MAX_QPS
        self.token_count = min(self.token_count, BURST)
        self.last_request_time = time.time()

        if self.token_count < 1.0:
            wait_time = (1.0 - self.token_count) / MAX_QPS
            actual_wait_time = wait_time
            if wait_time > MAX_THROTTLE_WAIT_TIME:
                self.log(f"[RATE_LIMIT | LOCK] Modülün bekleme süresi ({wait_time:.3f}s) MAX_WAIT({MAX_THROTTLE_WAIT_TIME}s) aştı. Bekleme süresi {MAX_THROTTLE_WAIT_TIME}s ile sınırlanıyor.", "WARNING")
                actual_wait_time = MAX_THROTTLE_WAIT_TIME
            
            if actual_wait_time > 2.0:
                self.log(f"[RATE_LIMIT] KRİTİK GECİKME: QPS Limiti aşıldı. {actual_wait_time:.3f} saniye beklenecek (Konsol Filtresi Aktif).", "WARNING")
            
            await asyncio.sleep(actual_wait_time)
            
            time_spent_waiting = time.time() - self.last_request_time
            self.token_count += time_spent_waiting * MAX_QPS
            self.token_count = min(self.token_count, BURST)
            self.last_request_time = time.time()

        self.token_count -= 1.0

    def _load_scanners(self, config_profile: str):
        if config_profile not in SCAN_PROFILES:
            self.log(f"[CONFIG] UYARI: Bilinmeyen profil '{config_profile}'. Kazanmak için {self.DEFAULT_PROFILE} kullanılıyor.", "WARNING")
            config_profile = self.DEFAULT_PROFILE
        
        profile = SCAN_PROFILES[config_profile]
        self.log(f"[CONFIG] '{config_profile}' profili yükleniyor: {profile['description']}", "INFO")

        request_cb = self.increment_request_count
        discovery_cb = self.add_discovered_param

        self.script_manager = DynamicScriptManager(self.log, self.target_url)
        self.exploit_manager = ExploitManager(self.log, self)
        self.oob_listener = OOBListener(self.log)

        is_scripting_enabled = getattr(self.script_manager, 'DYNAMIC_SCRIPTING_ENABLED', False)
        if is_scripting_enabled or 'XSS' in profile['modules']:
            self.dynamic_scanner = DynamicScanner(self.log)
        else:
            self.dynamic_scanner = None
        
        self.payload_generator = PayloadGenerator(self)
        self.log("[CONFIG] Payload Generator, Neural Engine ile başlatıldı.", "INFO")

        available_scanners = {
            'WAF_DETECT': WAFDetector(self.log, self.add_result, request_cb),
            'SUBDOMAIN': DiscoveryOrchestrator(self.log, self.add_result, request_cb),
            'SUBDOMAIN_TAKEOVER': SubdomainTakeoverScanner(self.log, self.add_result, request_cb),
            'PRE_SCAN': PreScanner(self.log, self.add_result, request_cb, discovery_cb),
            'HEADERS': HeadersScanner(self.log, self.add_result, request_cb),
            'FILES': FilesScanner(self.log, self.add_result, request_cb),
            'HEURISTIC': HeuristicScanner(self.log, self.add_result, request_cb),
            'AUTH_BYPASS': AuthBypassScanner(self.log, self.add_result, request_cb),
            'LFI': LFIScanner(self.log, self.add_result, request_cb),
            'XSS': XSSScanner(self.log, self.add_result, request_cb, dynamic_scanner_instance=self.dynamic_scanner),
            'SQLI': SQLiScanner(self.log, self.add_result, request_cb),
            'IDOR': IDORScanner(self.log, self.add_result, request_cb),
            'RCE_SSRF': RCE_SSRFScanner(self.log, self.add_result, request_cb, oob_listener_instance=self.oob_listener),
            'JSON_API': JSONAPIScanner(self.log, self.add_result, request_cb), # DÜZELTME: JSONAPIScaner -> JSONAPIScanner
            'PORT_SCAN': PortScanner(self.log, self.add_result, request_cb),
            'NUCLEI': NucleiScanner(self.log, self.add_result, request_cb), # AKTİF EDİLDİ
            'INTERNAL_SCAN': InternalScanner(self.log, self.add_result, request_cb),
            'JS_ENDPOINT': JSEndpointScanner(self.log, self.add_result, request_cb, endpoint_pattern=JS_ENDPOINT_PATTERN),
            'GRAPHQL': GraphQLScanner(self.log, self.add_result, request_cb),
            'CLOUD_EXPLOIT': CloudExploitScanner(self.log, self.add_result, request_cb),
            'HTTP_SMUGGLING': HTTPSmugglingScanner(self.log, self.add_result, request_cb),
            'CLIENT_LOGIC': ClientLogicAnalyzer(self.log, self.add_result, request_cb),
            'BUSINESS_LOGIC': BusinessLogicFuzzer(self.log, self.add_result, request_cb),
            'REACT_EXPLOIT': ReactExploitScanner(self.log, self.add_result, request_cb),
            'OSINT': OSINTScanner(self.log, self.add_result, request_cb),
            'LEAKAGE': LeakageScanner(self.log, self.add_result, request_cb),
            'RACE_CONDITION': RaceConditionHunter(self.log),
            'LLM_INJECTION': LLMPromptInjectionScanner(self.log, self.add_result, request_cb),
            'CLOUD_BUCKET': CloudBucketLeakerScanner(self.log, self.add_result, request_cb) # FAZ 41
        }

        self._pre_scanners = []
        self._main_scanners = []

        for module_name in profile['modules']:
            if module_name in available_scanners:
                scanner_instance = available_scanners[module_name]

                # FIX: RaceConditionHunter için eksik callback'leri manuel enjekte et
                if module_name == 'RACE_CONDITION':
                    if not hasattr(scanner_instance, 'add_result'):
                        setattr(scanner_instance, 'add_result', self.add_result)
                    if not hasattr(scanner_instance, 'request_cb'):
                        setattr(scanner_instance, 'request_cb', request_cb)
                    if not hasattr(scanner_instance, 'category'):
                        setattr(scanner_instance, 'category', 'RACE_CONDITION')
                    if not hasattr(scanner_instance, 'name'):
                        setattr(scanner_instance, 'name', 'Race Condition Hunter')

                module_limit = PER_MODULE_LIMIT
                if module_name == 'NUCLEI':
                    module_limit = NUCLEI_LIMIT 

                try:
                    module_semaphore = asyncio.Semaphore(module_limit)
                    setattr(scanner_instance, 'module_semaphore', module_semaphore)
                    self.log(f"[CONFIG] {module_name} için Concurrency Limit: {module_limit}", "INFO")
                except AttributeError:
                    self.log(f"[CONFIG] {module_name} (Senkron) için Concurrency Limit atlanıyor.", "WARNING")

                setattr(scanner_instance, 'throttle_delay_ms', self.throttle_delay_ms)
                setattr(scanner_instance, 'calibration_latency_ms', self.calibration_latency_ms)
                setattr(scanner_instance, 'latency_cv', self.latency_cv)
                setattr(scanner_instance, 'calibration_headers', self.calibration_headers)
                setattr(scanner_instance, '_apply_jitter_and_throttle', self._apply_jitter_and_throttle)
                
                setattr(scanner_instance, 'engine_instance', self)
                setattr(scanner_instance, 'user_agents', DataSimulator.REAL_USER_AGENTS)
                setattr(scanner_instance, 'proxy_manager', self.proxy_manager)
                setattr(scanner_instance, 'neural_engine', self.neural_engine)
                setattr(scanner_instance, 'payload_generator', self.payload_generator)

                if module_name == 'PORT_SCAN':
                    setattr(scanner_instance, 'thread_executor', self.thread_executor)
                    self.log(f"[CONFIG] {module_name} Thread Executor'a bağlandı.", "INFO")

                if module_name in ['WAF_DETECT', 'SUBDOMAIN', 'SUBDOMAIN_TAKEOVER', 'PRE_SCAN', 'JS_ENDPOINT', 'CLIENT_LOGIC', 'OSINT', 'LEAKAGE', 'CLOUD_BUCKET']:
                    self._pre_scanners.append(scanner_instance)
                else:
                    self._main_scanners.append(scanner_instance)

            # NUCLEI yükleme kontrolü
            if module_name == 'NUCLEI' and 'NUCLEI' in available_scanners:
                scanner_instance = available_scanners['NUCLEI']
                # Güncelleme: Yeni NucleiScanner sınıfı 'binary_path' kullanıyor
                if hasattr(scanner_instance, 'binary_path') and scanner_instance.binary_path:
                    self.log(f"[CONFIG] Nuclei bulundu: {scanner_instance.binary_path}", "INFO")
                elif hasattr(scanner_instance, 'nuclei_path') and scanner_instance.nuclei_path: # Eski uyumluluk
                    self.log(f"[CONFIG] Nuclei bulundu: {scanner_instance.nuclei_path}", "INFO")
                else:
                    self.log("[CONFIG] Nuclei yol tespiti Scanner'a devredildi.", "INFO")

        self.total_scanners = len(self._pre_scanners) + len(self._main_scanners)
        self.log(f"Toplam {self.total_scanners} adet tarama modülü yüklendi (Profil: {config_profile}).", "INFO")

    async def _scan_async(self, url):
        self.log("\n--- ASENKRON MOTOR BAŞLATILIYOR (2 AŞAMA) ---", "HEADER")
        
        proxy_task = asyncio.create_task(self.proxy_manager.start_updater())
        self.ai_queue_task = asyncio.create_task(self._ai_queue_worker())

        # --- AŞAMA 0: DİNAMİK SCRIPT ---
        final_url = url
        if self.stop_requested: return

        is_scripting_enabled_runtime = getattr(self.script_manager, 'DYNAMIC_SCRIPTING_ENABLED', False)
        if self.dynamic_scanner and is_scripting_enabled_runtime and self.script_manager.is_script_loaded():
            self.log("\n--- AŞAMA 0: DİNAMİK SCRIPT YÜRÜTÜCÜ BAŞLATILIYOR (LOGIN/SETUP) ---", "HEADER")
            actions = self.script_manager.get_script()
            success, new_url = await asyncio.to_thread(self.dynamic_scanner.execute_script, url, actions)

            if success:
                self.log(f"[DYNAMIC SCRIPT] Aksiyonlar başarıyla yürütüldü. Yeni hedef: {new_url}", "SUCCESS")
                final_url = new_url
            else:
                self.log("[DYNAMIC SCRIPT] KRİTİK HATA: Aksiyonlar yürütülemedi. Statik URL ile devam ediliyor.", "CRITICAL")
            self.log(f"--- AŞAMA 0 TAMAMLANDI. TARAMA HEDEFİ: {final_url} ---", "HEADER")

        self.target_url = final_url
        if self.stop_requested: return

        # --- KALİBRASYON ---
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as init_session:
            await self._run_calibration_scan(init_session, final_url)

        p90_s = self.calibration_latency_ms / 1000
        new_timeout = max(MIN_TIMEOUT, min(MAX_TIMEOUT, p90_s * 10))
        new_timeout = round(new_timeout, 2)
        self.log(f"[PERFORMANS] Adaptif Zaman Aşımı (P90 Tabanlı): {new_timeout} saniye olarak ayarlandı.", "INFO")

        try:
            scan_connector = aiohttp.TCPConnector(limit=MAX_GLOBAL_CONCURRENCY)
            async with aiohttp.ClientSession(connector=scan_connector, timeout=aiohttp.ClientTimeout(total=new_timeout)) as session:

                async def _run_safe_scan(scanner_instance, scan_url, scan_session):
                    if self.stop_requested:
                        self.log(f"[{scanner_instance.category}] İptal edildi (Kullanıcı İsteği).", "WARNING")
                        self._scanner_completed_callback()
                        return

                    try:
                        await asyncio.wait_for(
                            scanner_instance.scan(scan_url, scan_session, self._scanner_completed_callback),
                            timeout=MODULE_HARD_TIMEOUT
                        )
                    except asyncio.TimeoutError:
                        self.log(f"[{scanner_instance.category}] ZAMAN AŞIMI SİGORTASI: Modül {MODULE_HARD_TIMEOUT} saniyedir yanıt vermiyor. İptal ediliyor.", "WARNING")
                        self._scanner_completed_callback()
                    except asyncio.CancelledError:
                        self.log(f"[{scanner_instance.category}] GÖREV İPTAL EDİLDİ (Async Cancelled).", "WARNING")
                        self._scanner_completed_callback()
                    except concurrent.futures.CancelledError:
                        self.log(f"[{scanner_instance.category}] GÖREV İPTAL EDİLDİ (Thread Cancelled).", "WARNING")
                        self._scanner_completed_callback()
                    except Exception as e:
                        error_type = type(e).__name__
                        self.log(f"[{scanner_instance.category}] BEKLENMEDİK KRİTİK HATA ({error_type}): {e}", "CRITICAL")
                        self._scanner_completed_callback()

                # --- AŞAMA 2: KEŞİF ---
                if self._pre_scanners:
                    self.log("\n--- AŞAMA 2: KRİTİK KEŞİF VE WAF ANALİZİ BAŞLATILIYOR ---", "HEADER")
                    if not self.stop_requested:
                        pre_scan_tasks = []
                        for scanner in self._pre_scanners:
                            if self.stop_requested: break
                            self.log(f"\n--- FAZ: {scanner.name} ---", "HEADER")
                            pre_scan_tasks.append(_run_safe_scan(scanner, final_url, session))
                        await asyncio.gather(*pre_scan_tasks)
                    self.log(f"\n--- KEŞİF TAMAMLANDI. ---", "SUCCESS")
                else:
                    self.log("\n--- AŞAMA 2: KEŞİF MODÜLLERİ YÜKLÜ DEĞİL. ATLANIYOR. ---", "WARNING")

                if self.stop_requested:
                    self.log("\n[STOP] Tarama kullanıcı tarafından durduruldu.", "WARNING")
                    return
                
                # --- VERİ AKIŞI: LEAKAGE ---
                leakage_scanner = next((s for s in self._pre_scanners if s.category == 'LEAKAGE'), None)
                if leakage_scanner:
                    osint_emails = []
                    discovery_subdomains = []
                    base_domain = self._get_hostname(final_url)
                    
                    subdomain_scanner = next((s for s in self._pre_scanners if s.category == 'SUBDOMAIN'), None)
                    if subdomain_scanner and hasattr(subdomain_scanner, 'subdomains_found'):
                        discovery_subdomains.extend(subdomain_scanner.subdomains_found)

                    protected_domain_found = any(base_domain.endswith(p) for p in self.protected_domains)
                    if not protected_domain_found:
                        all_domains = list(set(discovery_subdomains + [base_domain]))
                        setattr(leakage_scanner, 'target_domains', all_domains)
                        simulated_emails = [f"admin@{base_domain}", f"support@{base_domain}", f"dev@{base_domain}"]
                        setattr(leakage_scanner, 'target_emails', simulated_emails)
                        self.log(f"[LEAKAGE] Ana Tarayıcıya {len(leakage_scanner.target_emails)} adet e-posta ve {len(leakage_scanner.target_domains)} adet domain enjekte edildi.", "INFO")
                    else:
                        self.log(f"[LEAKAGE] KORUMA: {base_domain} korunan alanda. Sızıntı taraması atlandı.", "WARNING")

                self._analyze_and_prioritize_main_scanners(final_url)

                # --- AŞAMA 3: ANA TARAMA ---
                if self._main_scanners:
                    self.log("\n--- AŞAMA 3: FUZZING VE ANALİZ MODÜLLERİ BAŞLATILIYOR (Taktiksel Sıra) ---", "HEADER")
                    if not self.stop_requested:
                        main_scan_tasks = []
                        
                        # [SYNARA FIX: PIPELINE TIKANIKLIĞI GİDERME BAŞLANGIÇ]
                        
                        # 1. PRE_SCAN'den gelen parametre adlarını al
                        target_params = self.discovered_params
                        
                        fuzzing_targets = []
                        if target_params:
                            parsed_url = urlparse(final_url)
                            # 2. Her bir parametre için hedef URL'leri oluştur
                            for param in target_params:
                                # URL'e parametreyi ekleyerek fuzzing hedefi oluştur
                                query_parts = parse_qs(parsed_url.query)
                                query_parts[param] = ['FUZZ_TARGET'] # PLACEHOLDER değeri
                                new_query = urlencode(query_parts, doseq=True)
                                
                                # Yeni URL'i oluştur
                                fuzz_url = urlunparse(parsed_url._replace(query=new_query, fragment=''))
                                fuzzing_targets.append(fuzz_url)
                        
                        # 3. Ana Tarayıcıları yapılandır ve başlat
                        for scanner in self._main_scanners:
                            if self.stop_requested: break

                            setattr(scanner, 'discovered_params', target_params) # Keşfedilen parametre adlarını modüle ilet
                            setattr(scanner, 'exploit_manager', self.exploit_manager)

                            # 4. KRİTİK ADIM: SQLI, XSS, LFI, IDOR tarayıcılarına parametreli URL'leri enjekte et
                            if scanner.category in ['SQLI', 'XSS', 'LFI', 'IDOR']:
                                # scanner'a doğrudan oluşturulan fuzzing hedeflerini enjekte et
                                self.log(f"[{scanner.category}] Pipeline'a {len(fuzzing_targets)} adet parametreli hedef enjekte edildi.", "INFO")
                                setattr(scanner, 'fuzzing_targets', fuzzing_targets)
                                
                            if scanner.category == 'XSS':
                                heuristic_scanner = next((s for s in self._main_scanners if s.category == 'HEURISTIC'), None)
                                if heuristic_scanner and hasattr(heuristic_scanner, 'reflection_info'):
                                    setattr(scanner, 'is_heuristic_reflected', heuristic_scanner.reflection_info.get("is_reflected"))
                                    reflection_context = heuristic_scanner.reflection_info.get("context")
                                    setattr(scanner, 'reflection_context_type', reflection_context)
                                    self.log(f"[{scanner.category}] Heuristic yansıma bilgisi aktarıldı.", "INFO")
                                
                            self.log(f"\n--- FAZ: {scanner.name} ---", "HEADER")
                            main_scan_tasks.append(_run_safe_scan(scanner, final_url, session))

                        # [SYNARA FIX: PIPELINE TIKANIKLIĞI GİDERME BİTİŞ]

                        await asyncio.gather(*main_scan_tasks)
                    else:
                        self.log("\n--- AŞAMA 3: ANA TARAMA MODÜLLERİ YÜKLÜ DEĞİL. ATLANIYOR. ---", "WARNING")

        except Exception as e:
            error_message = f"Asenkron Tarama Hatası: {str(e)}"
            srp_deduction = self.MODULE_WEIGHTS.get("SYSTEM", 10.0)
            self.add_result("SYSTEM", "CRITICAL", error_message, srp_deduction)
            # Not: _recalculate_score çağrısı add_result içinde var.
            self.log(error_message, "CRITICAL")
            
            # Tarama sırasında kritik hata oluşursa, taramayı FAILED olarak işaretle
            if self.report_manager:
                try:
                    # Hata durumunda bile Tarama Durumunu FAILED olarak işaretle
                    self.report_manager.finish_scan(status="FAILED")
                except Exception as rm_e:
                    self.log(f"[DB] ReportManager Hata Durumu Güncelleme Hatası: {rm_e}", "CRITICAL")

        finally:
            # Proxy ve AI Queue temizliğini burada bırakıyoruz.
            self.proxy_manager.stop_updater()
            if self.dynamic_scanner:
                self.dynamic_scanner.stop_dynamic_scan()
            if self.ai_queue_task:
                self.ai_queue_task.cancel()
                self.log("[NEURAL] AI Kuyruk İşçisi (Worker) durduruldu.", "INFO")
            
            self.log(f"[MOTOR] Asenkron tarama görevleri sonlandırıldı.", "HEADER")
            # Kalan DB ve Thread Executor temizliği start_scan içinde yapılacak.
            
        return self.score

    def _scanner_completed_callback(self):
        self.scanners_completed += 1
        if self.total_scanners > 0:
            progress_ratio = self.scanners_completed / self.total_scanners
            self.progress_update(progress_ratio)

    def run_manual_exploit(self, exploit_type: str, exploit_data: str):
        if not self.exploit_manager:
            self.log("[EXPLOIT] Exploit Manager yüklenmedi. Exploit yürütülüyor.", "CRITICAL")
            return

        def exploit_task():
            self.exploit_manager.execute_manual_exploit(self.target_url, exploit_type, exploit_data)

        threading.Thread(target=exploit_task, daemon=True).start()

    def start_scan(self, url: str, config_profile: str = DEFAULT_PROFILE):
        try:
            parsed_url = urlparse(url)
            hostname = parsed_url.netloc or parsed_url.path
            if ':' in hostname: hostname = hostname.split(':')[0]
            if hostname.startswith('www.'): hostname = hostname[4:]

            if any(hostname.endswith(domain) for domain in self.protected_domains):
                self.log(f"[GÜVENLİK] KRİTİK HATA: Hedef alan adı ({hostname}) koruma listesindedir. Tarama iptal edildi.", "CRITICAL")
                self.progress_update(1)
                return 0.0
        except Exception as e:
            self.log(f"[GÜVENLİK] URL Analiz Hatası: {e}. Koruma atlanıyor.", "CRITICAL")

        # FAZ 27: VERİTABANI BAĞLANTISI VE İLK BAŞLATMA
        try:
            # init_db() API Server/Main.py içinde çağrılmalı. Burada sadece oturum açılmalı.
            # Ancak yerel çalıştırma için Engine de init_db'yi çağırabilir. Güvenlik için yine de bırakıldı.
            # init_db() # API Server/Main.py içinde çağrılıyor
            self.db = SessionLocal() # Yeni bir DB oturumu oluştur
            self.log("[DB] Veritabanı (SQLite) başarıyla başlatıldı ve oturum açıldı.", "SUCCESS")
        except Exception as e:
            self.log(f"[DB] KRİTİK HATA: Veritabanı başlatılamadı veya oturum açılamadı: {e}", "CRITICAL")
            self.db = None
            return 0.0
        
        self.score = 100.0
        self.module_deduction_tracker = {mod: False for mod in self.MODULE_WEIGHTS.keys()}
        self.port_deduction_tracker = set()
        self.stop_requested = False
        self.start_time = datetime.datetime.now()
        self.target_url = url
        self.scanners_completed = 0
        self.total_requests = 0
        self.discovered_params = set()
        self.calibration_latency_ms = 4000
        self.throttle_delay_ms = 0
        self.latency_cv = 0.0
        self.calibration_headers = {}
        self.total_cvss_deduction = 0.0 # Yeniden başlat

        # FAZ 27: ReportManager'ı DB oturumuyla başlat
        if self.db:
            self.report_manager = ReportManager(
                target_url=self.target_url,
                target_ip=self._get_hostname(self.target_url), # Geçici IP/hostname
                scan_config=SCAN_PROFILES[config_profile],
                db=self.db
            )
        else:
            self.log("[DB] Veritabanı oturumu başlatılamadığı için ReportManager devre dışı bırakıldı.", "CRITICAL")
            self.report_manager = None

        # SynaraReporter'ı Engine referansıyla başlatıyoruz
        self.reporter = SynaraReporter(self)
        
        # ReportManager başlatılamazsa (DB hatası), taramayı durdur
        if not self.report_manager or not self.report_manager.scan_id:
            self.log("[DB] KRİTİK HATA: Yeni Tarama Kaydı (Scan) DB'de oluşturulamadı. Tarama iptal ediliyor.", "CRITICAL")
            if self.db: self.db.close()
            self.db = None
            return 0.0
        
        self._load_scanners(config_profile)
        self.progress_update(0)

        self.log(f"Hedef Sistem Analiz Ediliyor: {url} (Scan ID: {self.report_manager.scan_id})", "HEADER")
        self.log(f"[PERFORMANS] Maksimum Ağ Deneme Sayısı (Retry) {MAX_REQUEST_RETRIES} olarak sabitlendi (Sonsuz döngü koruması).", "INFO")

        final_score = 0.0

        try:
            if sys.platform == 'win32':
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                def win_handler(loop, context):
                    msg = context.get("message", "")
                    if "connection_lost" in str(context.get("exception", "")) or "connection_lost" in msg: return
                    if "SSL" in msg: return
                    loop.default_exception_handler(context)
                loop.set_exception_handler(win_handler)
                try:
                    final_score = loop.run_until_complete(self._scan_async(url))
                finally:
                    loop.close()
            else:
                final_score = asyncio.run(self._scan_async(url))

            # --- POST-SCAN AŞAMALARI (DB oturumu hala aktifken) ---
            self._run_chaining_analysis()
            self._run_post_scan_analysis()

            # Tarama başarılı tamamlandıysa DB'deki kaydı COMPLETED olarak işaretle
            if self.report_manager:
                self.report_manager.finish_scan(status="COMPLETED")
                
        except Exception as e:
            error_message = f"Kritik Motor Hatası: {str(e)}"
            srp_deduction = self.MODULE_WEIGHTS.get("SYSTEM", 10.0)
            self.add_result("SYSTEM", "CRITICAL", error_message, srp_deduction)
            self.log(error_message, "CRITICAL")
            
            # Tarama sırasında kritik hata oluşursa, taramayı FAILED olarak işaretle
            if self.report_manager:
                try:
                    self.report_manager.finish_scan(status="FAILED")
                except Exception as rm_e:
                    self.log(f"[DB] ReportManager Hata Durumu Güncelleme Hatası: {rm_e}", "CRITICAL")

        finally:
            self.thread_executor.shutdown()
            if self.db:
                self.db.close()
                self.db = None
            self.report_manager = None
            self.log(f"[MOTOR] Tüm tarama işlemleri sonlandırıldı. Toplam istek: {self.total_requests}", "HEADER")

        return final_score

    def save_report(self):
        # Bu metod API tarafından çağrıldığında, raporlama verisi DB'den çekilecektir.
        # Tarama durumu Engine.start_scan sonunda zaten ayarlanmış olmalıdır.
        
        # total_srp_deduction artık self.total_cvss_deduction'dan geliyor.
        self.total_cvss_deduction = max(0.0, 100.0 - self.score) # Skoru baz alarak tekrar hesapla
        
        html_path, pdf_path = self.reporter.generate_report()
        return html_path, pdf_path