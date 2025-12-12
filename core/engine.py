# path: core/engine.py

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
import concurrent.futures # FAZ 26: ThreadPoolExecutor için

from .dynamic_scanner import DynamicScanner
from .exploit_manager import ExploitManager
from .dynamic_script_manager import DynamicScriptManager
from .oob_listener import OOBListener
from .proxy_manager import ProxyManager
# YENİ: Neural Engine (Yapay Zeka)
from .neural_engine import NeuralEngine
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse

# Mimarinin diğer bileşenleri
from .reporter import SynaraReporter
# Faz 3: Payload Generator'ı import et (Diğer modüller tarafından kullanılabilir olması için)
from .payload_generator import PayloadGenerator
# FAZ 18: Auto-POC Generator Entegrasyonu
from .poc_generator import POCGenerator
# GHOST PROTOCOL: Veri Simülatöründen User-Agent listesini çek
from .data_simulator import DataSimulator

# Faz 1'de elle eklenecek ilk modüller
from .scanners.headers import HeadersScanner
from .scanners.files import FilesScanner
# Faz 3: Zeka Katmanı modülleri
from .scanners.heuristic import HeuristicScanner
from .scanners.xss import XSSScanner
# Faz 5: SQL Injection Scanner eklendi
from .scanners.sqli import SQLiScanner
# Faz 6: LFI Scanner eklendi
from .scanners.lfi import LFIScanner
# V5.0: Auth Bypass Scanner eklendi
from .scanners.auth_bypass import AuthBypassScanner
# V6.0: IDOR Scanner eklendi
from .scanners.idor import IDORScanner
# V7.0: Pre-Scan (Parametre Keşfi) eklendi
from .scanners.pre_scan import PreScanner
# V7.0: SSRF/RCE Tarayıcı eklendi
from .scanners.rce_ssrf import RCE_SSRFScanner
# V8.0: JSON API Tarayıcı eklendi
from .scanners.json_api_scanner import JSONAPIScanner
# FAZ 14: Port Tarayıcı eklendi
from .scanners.port_scanner import PortScanner
# FAZ 15: WAF Dedektörü eklendi
from .scanners.waf_detector import WAFDetector
# FAZ 19: Subdomain Tarayıcı eklendi
from .scanners.subdomain_scanner import DiscoveryOrchestrator
# FAZ 19: Subdomain Takeover Tarayıcı (YENİ)
from .scanners.subdomain_takeover import SubdomainTakeoverScanner
# FAZ 22: Nuclei Entegrasyonu eklendi
from .scanners.nuclei_scanner import NucleiScanner
# YENİ MODÜL: Dahili Sistem Tarayıcı
from .scanners.internal_scanner import InternalScanner
# YENİ MODÜL: JS Endpoint Extractor
from .scanners.js_finder import JSEndpointScanner
# YENİ MODÜL: GraphQL Scanner (Faz 20)
from .scanners.graphql_scanner import GraphQLScanner
# YENİ MODÜL: Cloud Exploit Scanner (Faz 18 Cloudstorm)
from .scanners.cloud_exploit import CloudExploitScanner
# YENİ MODÜL: React2Shell Exploit
from .scanners.react_exploit import ReactExploitScanner
# YENİ MODÜL: Client-Side Logic Analyzer (Phase 31)
from .scanners.client_logic_analyzer import ClientLogicAnalyzer
# YENİ MODÜL: HTTP Request Smuggling Scanner (Phase 32)
from .scanners.http_smuggling_scanner import HTTPSmugglingScanner
# YENİ MODÜL: Business Logic Fuzzer (Phase 33)
from .scanners.business_logic_fuzzer import BusinessLogicFuzzer
# YENİ MODÜL: OSINT Scanner (Faz 19 - OSINT)
from .scanners.osint_scanner import OSINTScanner
# YENİ MODÜL: Leakage Scanner (Faz 24 - PII Leakage)
from .scanners.leakage_scanner import LeakageScanner

# --- KONFIGURASYON SABİTLERİ ---
MAX_GLOBAL_CONCURRENCY = 10
PER_MODULE_LIMIT = 5
NUCLEI_LIMIT = 3
MAX_WORKER_THREADS = 10
# ---------------------------------------------------

# --- GÜVENLİK ZAMAN AŞIMI (ANTI-FREEZE) ---
MODULE_HARD_TIMEOUT = 90
# ------------------------------------------

# --- ADAPTİF ZAMAN AŞIMI SABİTLERİ (YENİ) ---
MIN_TIMEOUT = 2.0
MAX_TIMEOUT = 7.0
# --------------------------------------------

# --- DENEME SAYISI (RETRY) SABİTİ (YENİ) ---
MAX_REQUEST_RETRIES = 1
# ------------------------------------------

# --- JS ENDPOINT EXTRACTOR SABİTİ (YENİ FAZ 6) ---
JS_ENDPOINT_PATTERN = r'[A-Za-z0s9_\-]+\.(php|json|js|jsp|aspx)'
# --------------------------------------------------

# --- ML FALSE POSITIVE VERİTABANI YOLU (YENİ FAZ 7) ---
FP_DB_PATH = "fp_database.json"
# ------------------------------------------------------

# --- TOKEN BUCKET RATE LIMIT SABİTLERİ (YENİ FAZ 7) ---
MAX_QPS = 5.0
BURST = 10.0
# FAZ 27: Maksimum tek seferlik bekleme süresi (Hata 3 Çözümü)
MAX_THROTTLE_WAIT_TIME = 2.5 # KRİTİK DÜZELTME: 1.5'tan 2.5'a çıkarıldı.
# ------------------------------------------------------

# --- FAZ 40: AKILLI AI KUYRUK SABİTLERİ ---
AI_QUEUE_QPS = 1.0 # Neural Engine API'ye saniyede maksimum 1 istek atsın
# ------------------------------------------

# Faz 10: Tanımlanmış Tarama Profilleri
SCAN_PROFILES = {
    # GUI'nin beklediği FULL_SCAN'ı geri ekledik (KeyError'ı engeller)
    "FULL_SCAN": {
        "description": "Tüm modüller (Hafiften Kapsamlı Fuzzing'e kadar). En yavaş ve en derin tarama.",
        "modules": ['WAF_DETECT', 'SUBDOMAIN', 'SUBDOMAIN_TAKEOVER', 'PRE_SCAN', 'HEADERS', 'FILES', 'PORT_SCAN', 'HEURISTIC', 'AUTH_BYPASS', 'LFI', 'XSS', 'SQLI', 'IDOR', 'RCE_SSRF', 'JSON_API', 'CLOUD_EXPLOIT', 'REACT_EXPLOIT', 'NUCLEI', 'INTERNAL_SCAN', 'JS_ENDPOINT', 'GRAPHQL', 'CLIENT_LOGIC', 'HTTP_SMUGGLING', 'BUSINESS_LOGIC', 'OSINT', 'LEAKAGE'] # YENİ: OSINT, LEAKAGE
    },
    # KRİTİK KAZANÇ PROFİLİ (Kullanıcının tercih ettiği modül listesi)
    "BUG_BOUNTY_CORE": {
        "description": "BBH (Bug Bounty Hunter - SADECE KAZANÇ): Yüksek Ödüllü Kritik Zafiyetler ve Gelişmiş Keşif için optimize edilmiştir.",
        "modules": ['WAF_DETECT', 'SUBDOMAIN', 'SUBDOMAIN_TAKEOVER', 'PRE_SCAN', 'JS_ENDPOINT', 'HEADERS', 'FILES', 'HEURISTIC', 'AUTH_BYPASS', 'LFI', 'XSS', 'SQLI', 'IDOR', 'RCE_SSRF', 'REACT_EXPLOIT', 'JSON_API', 'CLOUD_EXPLOIT', 'PORT_SCAN', 'CLIENT_LOGIC', 'HTTP_SMUGGLING', 'BUSINESS_LOGIC', 'OSINT', 'LEAKAGE'] # YENİ: OSINT, LEAKAGE
    },
    # Diğer eski modüller (GUI'nin ihtiyacı için geri getirildi)
    "LIGHT": {
        "description": "Sadece Temel Analiz ve Zeka (Headers, Files, Heuristic). Çok hızlı.",
        "modules": ['WAF_DETECT', 'SUBDOMAIN', 'PRE_SCAN', 'JS_ENDPOINT', 'HEADERS', 'FILES', 'PORT_SCAN', 'HEURISTIC', 'INTERNAL_SCAN', 'CLIENT_LOGIC', 'OSINT', 'LEAKAGE'] # YENİ: OSINT, LEAKAGE
    },
    "FUZZING_ONLY": {
        "description": "Sadece Fuzzing Modülleri (XSS, SQLi, LFI, RCE).",
        "modules": ['WAF_DETECT', 'PRE_SCAN', 'LFI', 'XSS', 'SQLI', 'IDOR', 'RCE_SSRF', 'REACT_EXPLOIT', 'GRAPHQL']
    },
    "INTERNAL_MISSION": {
        "description": "Sadece Synara'nın çekirdeğini (Codebase, Manifest, Sırlar) analiz eder.",
        "modules": ['INTERNAL_SCAN', 'HEADERS']
    }
}


class SynaraScannerEngine:
    """
    Synara'nın ana tarama motoru. Zafiyet modüllerini (plugin) yükler,
    tarama sürecini yönetir, sonuçları biriktirir ve skoru hesaplar.
    """
    # AR-GE: SYNARA GERÇEKLİK PUANI (SRP) V3.0 - MODÜL AĞIRLIKLARI (Hata 2 Garantisi)
    # Global değişken yerine Sınıf değişkeni olarak tanımlandı.
    MODULE_WEIGHTS = {
        "SQLI": 20.0,      # SQL Injection (En kritik)
        "RCE_SSRF": 18.0,  # RCE/SSRF
        "REACT_RCE": 25.0, # YENİ: React2Shell (CVSS 10.0)
        "LFI": 15.0,       # Local File Inclusion
        "AUTH_BYPASS": 12.0,  # Yetki Bypass
        "XSS": 10.0,       # XSS (Farklı tipleri tek zafiyet say)
        "IDOR": 8.0,       # IDOR
        "FILES": 6.0,      # Hassas Dosya İfşası (robots.txt hariç)
        "HEADERS": 0.0,    # GÜNCELLENDİ (Playtika Filtresi): Güvenlik Başlıkları Kapsam Dışı.
        "HEURISTIC": 3.0,  # Genel Heuristik Uyarılar
        "JSON_API": 3.0,   # API Fuzzing/Hata İfşası
        "GRAPHQL": 12.0,   # GraphQL Introspection/Injection (Yüksek Risk)
        "CLOUD_EXPLOIT": 25.0, # YENİ: Bulut Metadata/S3 İfşası (Çok Kritik)
        "SUBDOMAIN_TAKEOVER": 25.0, # YENİ: Domain Snatching (Çok Kritik)
        "HTTP_SMUGGLING": 22.0, # YENİ: HTTP/2 Request Smuggling (Phase 32 - ÇOK KRİTİK)
        "CLIENT_LOGIC": 18.0, # YENİ: Client-Side Logic/Source Map Secret Hunting (Phase 31)
        "BUSINESS_LOGIC": 18.0, # YENİ: Stateful Business Logic Fuzzing (Phase 33)
        "PORT_SCAN": 5.0,  # DÜZELTME 4: 0.0'dan 5.0'a çıkarıldı (Zincirleme ve SRP uyumu için)
        "WAF_DETECT": 0.0, # GÜNCELLENDİ (Playtika Filtresi): WAF Tespiti Kapsam Dışı.
        "SUBDOMAIN": 0.0,  # Sadece Bilgi Amaçlı
        "NUCLEI": 0.0,     # Nuclei sonuçları ayrı değerlendirilebilir, şimdilik 0
        "CHAINING": 15.0,  # Zafiyet Zincirleme (Ekstra düşüş)
        "SYSTEM": 5.0,     # Kritik Sistem/Motor Hatası (Genel hatalar için düşürüldü)
        "INTERNAL_SCAN": 20.0,  # YENİ: Dahili sistem sızıntısı (Hardcoded sır vb.)
        "OSINT": 4.0,      # YENİ: OSINT Bilgi Sızıntısı (Whois/E-posta ifşası)
        "LEAKAGE": 25.0    # YENİ: Kritik PII/Secret Key Sızıntısı (Çok Kritik - FAZ 24)
    }

    # Faz 10: Varsayılan profil
    DEFAULT_PROFILE = "BUG_BOUNTY_CORE" # KRİTİK DEĞİŞİKLİK

    # Faz 10: Skor, CVSS 0.0 - 10.0 aralığından normalize edilerek hesaplanacaktır.
    # Başlangıç skoru 100 (CVSS Skalasına göre 0.0) olacaktır.
    # KRİTİK: HEADLESS MOD İÇİN CALLBACK'LER OPSİYONEL YAPILDI
    def __init__(self, logger_callback=None, progress_callback=None, config_profile: str = DEFAULT_PROFILE):
        # Eğer callback yoksa (Headless/Server Modu), boş bir fonksiyon ata.
        self.log = logger_callback if logger_callback else self._headless_log
        self.progress_update = progress_callback if progress_callback else self._headless_progress
        
        # NOTE: self.MODULE_WEIGHTS = MODULE_WEIGHTS ataması sınıf seviyesine taşındı.
        
        self.score = 100.0  # Faz 10: Float'a çevrildi
        self.results = []
        self.start_time = None
        self.target_url = ""
        self.reporter = SynaraReporter(self)  # Raporlama sınıfı
        self.oob_listener: Optional[OOBListener] = None # YENİ: OOB Sinyal Takibi için
        
        # PROXY AYARI: Programevi gibi statik hedefler için False,
        # Lido/Sushi gibi WAF'lı hedefler için True yap.
        # Varsayılan olarak False (Hız ve Stabilite için)
        self.use_proxy = False
        
        # Proxy Manager Başlatma (enabled parametresi ile)
        self.proxy_manager = ProxyManager(self.log, enabled=self.use_proxy)
        
        # Neural Engine Başlatma (Gemini API)
        # API anahtarını çevre değişkeninden veya gui_main.py'den alacak
        # Şimdilik boş bırakıyoruz, kullanıcı GUI'den girmeli veya .env'den okumalı
        self.neural_engine = NeuralEngine(self.log)
        
        # --- FAZ 40 KRİTİK EKLENTİ: AI İstek Kuyruğu ---
        self.ai_request_queue: asyncio.Queue = asyncio.Queue()
        self.ai_queue_task: Optional[asyncio.Task] = None
        # ----------------------------------------------

        # Faz 10: Yapılandırma değişkenleri
        self.config_profile = config_profile
        self.total_cvss_deduction = 0.0  # KRİTİK DÜZELTME: Raporlama için geri eklendi.

        # YENİ: Her modül için düşüşün bir kez yapıldığını takip et
        self.module_deduction_tracker = {mod: False for mod in self.MODULE_WEIGHTS.keys()}
        # YENİ KRITİK: Port tarama için ayrı takipçi (Birden fazla kritik port cezası için)
        self.port_deduction_tracker = set()

        # YENİ: Toplam HTTP İstek Sayacı
        self.total_requests = 0

        # V8.0 KRITIK: Dinamik Tarayıcı instance'ı (XSSScanner'a atanacak)
        self.dynamic_scanner = None
        # FAZ 11: Exploit Manager instance'ı
        self.exploit_manager = None
        # FAZ 12: Dinamik Script Manager instance'ı
        self.script_manager = None

        # V7.0: Keşfedilen Gizli Parametreler (Set kullanılır, benzersiz olması için)
        self.discovered_params = set()

        # V7.0 KALİBRASYON: Dinamik gecikme süresi (Milisaniye)
        self.calibration_latency_ms = 4000  # Varsayılan: 4 saniye
        # YENİ: Dinamik throttling için gecikme süresi
        self.throttle_delay_ms = 0  # Başlangıçta gecikme yok

        # YENİ FAZ 2.2: Kalibrasyon/Anti-Bot Zekası
        self.latency_cv = 0.0  # Tepki süresi varyasyon katsayısı (Coefficient of Variation)
        self.calibration_headers: Dict[str, str] = {}  # İlk yanıttan çekilen Rate-Limit/Anti-Bot başlıkları

        # YENİ FAZ 7: Hata Pozitif Veritabanı
        self.fp_database: List[Dict[str, str]] = self._load_fp_database()

        # --- YENİ FAZ 7: TOKEN BUCKET DEĞİŞKENLERİ ---
        self.token_count = BURST  # Başlangıçta tam kapasite
        self.last_request_time = time.time()
        # ---------------------------------------------

        # Yüklü tarayıcı modülleri listesi
        self._pre_scanners = []  # Aşama 1: Keşif (WAF Detect burada olacak)
        self._main_scanners = []  # Aşama 2: Fuzzing ve Analiz

        # İlerleme takibi değişkenleri
        # DÜZELTME: self._load_scanners çağrılmadığı için total_scanners 0 kalır.
        # Bu değer, start_scan içinde ayarlanacaktır.
        self.total_scanners = 0
        self.scanners_completed = 0
        self.progress_update(0)  # Başlangıçta ilerlemeyi sıfırla

        # YENİ: Korunan alan adlarını yükle
        self.protected_domains = self._load_protected_domains()
        
        # --- YENİ: STOP MEKANİZMASI ---
        # Pause/Resume yerine sadece STOP (İptal) kullanılacak.
        # Bu bayrak True olduğunda tüm döngüler kırılır.
        self.stop_requested = False
        # ------------------------------
        
        # FAZ 26: Blocking I/O için Thread Havuzu
        self.thread_executor = concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKER_THREADS)
        self.log(f"[PERFORMANS] Thread Pool Executor başlatıldı (Workers: {MAX_WORKER_THREADS}).", "INFO")

    # --- HEADLESS HELPER FUNCTIONS ---
    def _headless_log(self, message, level="INFO"):
        """GUI olmayan ortamlar için varsayılan log fonksiyonu."""
        pass

    def _headless_progress(self, val):
        """GUI olmayan ortamlar için varsayılan progress fonksiyonu."""
        pass
    # ---------------------------------

    def _get_base_path(self):
        """Uygulamanın çalıştığı ana dizini döndürür."""
        if getattr(sys, 'frozen', False):
            return os.path.dirname(sys.executable)
        return os.getcwd()

    def _get_hostname(self, url: str) -> str:
        """URL'den hostname'i ayıklar."""
        try:
            # KRİTİK EKSİK METOT: URL'den temiz hostname'i (www. ve portlar olmadan) ayıklar.
            parsed = urlparse(url)
            netloc = parsed.netloc.split(':')[0]
            if netloc.startswith('www.'):
                return netloc[4:]
            return netloc
        except:
            return ""

    def _load_protected_domains(self) -> List[str]:
        """protected_domains.json dosyasını okur ve listeyi döndürür."""

        protected_file_path = os.path.join(self._get_base_path(), "protected_domains.json")

        if not os.path.exists(protected_file_path):
            self.log("[GÜVENLİK] UYARI: protected_domains.json bulunamadı. Koruma filtresi devre dışı.", "WARNING")
            return []

        try:
            with open(protected_file_path, 'r', encoding='utf-8') as f:
                domains = json.load(f)
                # Sadece string listesi olduğundan emin ol
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
        """FP veritabanını (fp_database.json) yükler."""
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
        """
        DÜZELTME 3: ML tabanlı simülasyon: Sonucun daha önce raporlanmış bir FP olup olmadığını REGEX ile kontrol eder.
        """
        if not self.fp_database:
            return False

        # Basit regex tabanlı karşılaştırma mantığı (ML simülasyonu)
        lower_message = message.lower()
        
        for fp_entry in self.fp_database:
            if fp_entry.get("category") == category:
                # Eğer mesajın herhangi bir kısmı bilinen FP mesajını içeriyorsa (regex ile daha esnek)
                fp_message = fp_entry.get("message", "").lower()
                
                # Regex'i özel karakterlerden kaçınarak oluştur
                escaped_fp_message = re.escape(fp_message)
                
                # Eğer FP mesajı, tarama sonucunun içinde bulunuyorsa, FP olarak işaretle
                if re.search(escaped_fp_message, lower_message):
                    self.log(f"[{category} | FP TESPİTİ] Bulgu, bilinen hata pozitif veritabanı ile eşleşti. Raporlama atlandı.", "INFO")
                    return True
        return False

    def increment_request_count(self):
        """
        Herhangi bir tarayıcı modülü tarafından bir HTTP isteği yapıldığında çağrılır.
        """
        self.total_requests += 1

    def add_discovered_param(self, param_name: str):
        """
        PreScanner tarafından keşfedilen yeni bir parametre adını listeye ekler.
        """
        self.discovered_params.add(param_name)
        self.log(f"[PRE-SCAN] Yeni parametre keşfedildi: '{param_name}'", "INFO")

    def _recalculate_score(self):
        """
        FAZ 38: PUANLAMA ALGORİTMASI V4.0 (Multi-Layer Scoring)
        Modül başına tek düşüş kuralı (add_result içinde SRP=0.0 olarak ayarlandığı için)
        artık burada sadece skorları toplar.
        """
        total_deduction = 0.0

        for res in self.results:
            # Sadece pozitif SRP değeri olan sonuçları topla (PORT_SCAN dahil)
            if res['cvss_score'] > 0:
                total_deduction += res['cvss_score']

        # Skoru hesapla ve 0-100 arasında sınırla
        self.score = max(0.0, 100.0 - total_deduction)

    def add_result(self, category: str, level: str, message: str, cvss_score: float, poc_data: Optional[Dict[str, Any]] = None):
        """
        Faz 38: Tarayıcı modüllerinden gelen sonuçları ana listeye ekler, skoru CVSS/SRP'ye göre günceller ve
        kritik bulgular için AI Derin Analizini tetikler.
        """

        # --- KRİTİK FAZ 7: ML-FP KONTROLÜ ---
        if self._is_false_positive(category, message):
            self.log(f"[{category} | FP TESPİTİ] Bulgu, bilinen hata pozitif veritabanı ile eşleşti. Raporlama atlandı.", "INFO")
            return
        # --------------------------------------

        original_score = cvss_score
        original_level = level

        # YENİ SRP MANTIK: Modül ağırlığını belirle. Eğer zafiyet yoksa düşüş 0'dır.
        srp_deduction = 0.0

        if level == "CRITICAL":
            srp_deduction = self.MODULE_WEIGHTS.get(category, 0.0)  # Tam ağırlık
        elif level == "HIGH":
            srp_deduction = self.MODULE_WEIGHTS.get(category, 0.0) * 0.7  # %70 ağırlık
        elif level == "WARNING":
            srp_deduction = self.MODULE_WEIGHTS.get(category, 0.0) * 0.3  # %30 ağırlık
        else:
            srp_deduction = 0.0

        # --- BÜYÜK ÖLÇEKLİ ORTAM FİLTRESİ (HYPERSCALE) ---
        is_google = "google.com" in self.target_url.lower() or "gmail.com" in self.target_url.lower()
        is_time_based_sqli = category == "SQLI" and "Time-Based SQLi" in message # DÜZELTME: SQLi kategorisi kullanıldı
        is_idor = category == "IDOR" and original_score > 0

        if is_google and (is_time_based_sqli or is_idor):
            level = "INFO"
            srp_deduction = 0.0
            message += " [UYARI: HYPERSCALE FİLTRESİ AKTİF. Güvenilirlik 0.0'a düşürüldü.]"

        # KRİTİK SRP V2.1: Modül başına bir kez düşüş kuralı
        # PORT_SCAN ve SYSTEM dışındaki modüller için normal kuralı uygula
        if category in self.MODULE_WEIGHTS and category not in ["PORT_SCAN", "SYSTEM"]:
            if srp_deduction > 0.0 and self.module_deduction_tracker.get(category, False):
                srp_deduction = 0.0  # Zaten düşülmüş, tekrar düşme
            elif srp_deduction > 0.0:
                self.module_deduction_tracker[category] = True  # İlk kez düşüldü olarak işaretle

        # PORT_SCAN ve SYSTEM mantığı (cvss_score'u doğrudan kullanır, SRP sadece referanstır)
        elif category in ["PORT_SCAN", "SYSTEM"]:
            pass
            
        # FAZ 11 KRİTİK: Exploit önerisi ekle
        exploit_suggestion = ""
        if original_level in ["CRITICAL", "HIGH", "CHAINING_CRITICAL"] and self.exploit_manager:
            exploit_suggestion = self.exploit_manager.generate_exploit_suggestion(
                {'category': category, 'level': original_level, 'cvss_score': original_score}
            )
            # Eğer HYPERSCALE filtresi devreye girdiyse, öneriyi filtrele
            if level == "INFO" and exploit_suggestion:
                exploit_suggestion = "[Exploit önerisi filtrelendi: Büyük ölçekli ortamda manuel doğrulama gerekli.]"
            elif exploit_suggestion and "Otomatik sömürü önerisi bulunamadı." not in exploit_suggestion:
                message += f" [Exploit Önerisi: {exploit_suggestion}]"


        # --- FAZ 38: KRİTİK AI ANALİZ TETİKLEME ---
        critical_ai_categories = ["RCE_SSRF", "CLOUD_EXPLOIT", "LEAKAGE", "REACT_RCE", "HTTP_SMUGGLING", "INTERNAL_SCAN", "SQLI", "AUTH_BYPASS"]
        
        if self.neural_engine.is_active and category in critical_ai_categories and original_level in ["CRITICAL", "HIGH"]:
            if self.exploit_manager:
                vuln_data_for_ai = {
                    "category": category,
                    "level": original_level,
                    "message": message,
                    "url": poc_data.get('url', self.target_url) if poc_data else self.target_url
                }
                # Exploit Manager'a AI analizini yeni bir thread'de başlatması için talimat ver
                self.run_manual_exploit("CRITICAL_AI_ANALYSIS", json.dumps(vuln_data_for_ai))
                message += " [AI DERİN ANALİZ BAŞLATILDI]"
            else:
                 message += " [AI Analiz Motoru Hazır Değil.]"
        # -----------------------------------------


        # YENİ FAZ 18: AUTO-POC VE RAPORLAMA MOTORU
        generated_poc_report = None
        if poc_data and level in ["CRITICAL", "HIGH", "WARNING"]:
            try:
                # Hedef URL'yi poc_data içinden veya genel target_url'den al
                vuln_url = poc_data.get('url', self.target_url)
                
                # Otomatik Raporu Oluştur
                generated_poc_report = POCGenerator.create_vulnerability_report(
                    vuln_name=category,
                    severity=level,
                    target_url=vuln_url,
                    description=message,
                    impact="Potential unauthorized access, data leakage, or remote code execution depending on the context.",
                    poc_inputs=poc_data
                )
                
                # Mesaja ufak bir bildirim ekle
                message += " [AUTO-POC OLUŞTURULDU]"
                # Loga başarı mesajı düş
                if level == "CRITICAL":
                    self.log(f"[{category}] Otomatik POC kanıtı ve raporu başarıyla oluşturuldu.", "SUCCESS")
                
            except Exception as e:
                self.log(f"[{category}] POC oluşturma hatası: {e}", "WARNING")


        self.results.append({
            "category": category,
            "level": level,
            "message": message,
            "cvss_score": srp_deduction, # ARTIK SRP DÜŞÜŞ PUANINI TUTUYOR
            "time": datetime.datetime.now().strftime("%H:%M:%S"),
            "poc_report": generated_poc_report # YENİ: POC raporunu sonuca ekle
        })

        # YENİ PUANLAMA SİSTEMİ ÇAĞRISI
        self._recalculate_score()

        # GUI'ye log gönder
        self.log(f"[{category} | SRP Düşüş: {srp_deduction:.1f}] {message}", level)
        
    def stop_scan(self):
        """
        Kullanıcı isteğiyle taramayı durdurur (Graceful Stop).
        Bu fonksiyon, döngüleri kırmak için stop_requested bayrağını set eder.
        """
        self.log("[MOTOR] Durdurma sinyali (STOP) alındı. İşlemler iptal ediliyor...", "WARNING")
        self.stop_requested = True
        self.proxy_manager.stop_updater()
        
        # FAZ 40: AI Worker'ı iptal et
        if self.ai_queue_task:
            self.ai_queue_task.cancel()
            self.log("[NEURAL] AI Kuyruk İşçisi (Worker) iptal edildi.", "INFO")
        
        # FAZ 26: Thread havuzunu kapat
        self.log("[PERFORMANS] Thread Pool Executor kapatılıyor...", "INFO")
        self.thread_executor.shutdown(wait=False)

    async def _ai_queue_worker(self):
        """
        [FAZ 40] AI İstek Kuyruğunu yöneten asenkron işçi. 
        Saniyede AI_QUEUE_QPS hızını aşmayacak şekilde istekleri tüketir.
        """
        self.log(f"[NEURAL] AI Kuyruk İşçisi başlatıldı (Hız: {AI_QUEUE_QPS} QPS).", "SUCCESS")
        
        try:
            while not self.stop_requested:
                # Kuyruktan isteği al (payload_generator'dan gelir)
                # İstek yapısı: (context_data, vulnerability_type, count, future_obj)
                item = await self.ai_request_queue.get()
                context_data, vuln_type, count, future_obj = item
                
                self.log(f"[NEURAL] Kuyruktan AI isteği çekildi ({vuln_type}, Kalan: {self.ai_request_queue.qsize()}).", "INFO")

                # 1. Neural Engine'i Çağır
                # generate_ai_payloads, artık Devre Kesici ve Backoff ile API'yi çağıracak.
                try:
                    payloads = await self.neural_engine.generate_ai_payloads(context_data, vuln_type, count)
                    # Sonucu Future objesine set et
                    if not future_obj.done():
                        future_obj.set_result(payloads)
                except Exception as e:
                    self.log(f"[NEURAL] KRİTİK HATA: AI Payload üretimi başarısız oldu: {e}", "CRITICAL")
                    # Başarısızlık durumunda DataSimulator'dan mock verileri döndür
                    if not future_obj.done():
                        future_obj.set_result(DataSimulator.simulate_ai_payloads(vuln_type, count))
                    
                self.ai_request_queue.task_done()

                # 2. Hız Sınırlaması (QPS) Uygula
                sleep_time = 1.0 / AI_QUEUE_QPS
                await asyncio.sleep(sleep_time)

        except asyncio.CancelledError:
            self.log("[NEURAL] AI Kuyruk İşçisi (Worker) iptal sinyali aldı.", "WARNING")
        except Exception as e:
            self.log(f"[NEURAL] İşçi beklenmedik hata verdi: {e}", "CRITICAL")
        
        self.log("[NEURAL] AI Kuyruk İşçisi durduruldu.", "WARNING")


    async def queue_ai_payload_request(self, context_data: Dict[str, Any], vulnerability_type: str, count: int = 5) -> List[str]:
        """
        [FAZ 40] PayloadGenerator tarafından çağrılan yeni arayüz. 
        AI Payload isteğini kuyruğa atar ve sonucu bekler.
        """
        if not self.neural_engine.is_active:
            self.log("[PAYLOAD GOV] AI pasif. Simüle payload kullanılıyor.", "WARNING")
            return DataSimulator.simulate_ai_payloads(vulnerability_type, count)

        # Sonucun geleceği asenkron Future objesini oluştur
        future_result = asyncio.get_running_loop().create_future()
        
        # İsteği kuyruğa ekle
        await self.ai_request_queue.put((context_data, vulnerability_type, count, future_result))
        
        self.log(f"[PAYLOAD GOV] AI Payload isteği sıraya eklendi ({vulnerability_type}, Kuyruk: {self.ai_request_queue.qsize()}).", "INFO")
        
        # Sonucu bekle (Bu asenkron çağrıyı engeller)
        try:
            # KRİTİK NOT: Normal tarama süresine uygun bir zaman aşımı koymalıyız. 
            # AI yanıtı 30 saniye sürüyorsa ve kuyrukta bekleme varsa bu artabilir.
            # Şimdilik kilitlenmeyi önlemek için yüksek bir limit kullanalım.
            payloads = await asyncio.wait_for(future_result, timeout=40.0) 
            return payloads
        
        except asyncio.TimeoutError:
            self.log("[PAYLOAD GOV] HATA: AI Kuyruk Zaman Aşımı (40.0s). Simüle payload kullanılıyor.", "CRITICAL")
            return DataSimulator.simulate_ai_payloads(vulnerability_type, count)
        except Exception as e:
            self.log(f"[PAYLOAD GOV] HATA: AI Kuyruk İletişim Hatası ({e}). Simüle payload kullanılıyor.", "CRITICAL")
            return DataSimulator.simulate_ai_payloads(vulnerability_type, count)

    async def _run_calibration_scan(self, session, url):
        """
        FAZ 17 GÜNCELLEMESİ: Hedef sisteme 10 adet normal istek göndererek
        90. Persentil (P90) gecikmesini hesaplar ve Dinamik SQLi Zaman Eşiğini belirler.
        KRİTİK DÜZELTME: Artık dışarıdan gelen TEK session objesini kullanıyor.
        """
        self.log("\n--- SİSTEM KALİBRASYONU BAŞLATILIYOR (90. Persentil Ölçümü) ---", "HEADER")

        NUM_TESTS = 10
        latency_list = []

        # Yeni: Anti-Bot/Rate-Limit Başlıkları için tanım
        rate_limit_headers = ["X-RateLimit-Limit", "Retry-After", "X-Request-Attempt", "X-Cache", "CF-RAY", "Server-Timing"]

        try:
            for i in range(NUM_TESTS):
                # STOP KONTROLÜ
                if self.stop_requested:
                    self.log("[KALİBRASYON] Kullanıcı iptali nedeniyle durduruldu.", "WARNING")
                    return

                start = time.time()
                # Jitter ve Token Bucket
                await self._apply_jitter_and_throttle()
                self.increment_request_count()

                # Sadece başlıkları al, hızlı ol
                # KRİTİK DÜZELTME: Timeout'ı 5s sabit tutuldu
                async with session.get(url, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=5)) as res:

                    # Sadece ilk başarılı yanıttan başlıkları çek
                    if i == 0:
                        self.calibration_headers = {h: res.headers.get(h, "") for h in rate_limit_headers}

                    await res.read()
                end = time.time()
                latency_list.append(end - start)

            # 1. P90 Gecikme Hesaplama
            if len(latency_list) < NUM_TESTS:
                raise Exception("Yetersiz kalibrasyon verisi.")

            latency_list.sort()
            # P90, listenin %90'lık kısmındaki değerdir (index 9).
            p90_latency_s = latency_list[int(0.9 * len(latency_list) - 1)]

            # YENİ FAZ 2.2: Varyasyon Katsayısı (CV) Hesaplama
            mean = statistics.mean(latency_list)
            stdev = statistics.stdev(latency_list) if len(latency_list) > 1 else 0.0

            # CV = (Standart Sapma / Ortalama) * 100
            latency_cv = (stdev / mean) if mean != 0 else 0.0
            self.latency_cv = latency_cv

            self.log(f"[KALİBRASYON] P90 Yanıt Süresi (Baseline): {p90_latency_s*1000:.2f} ms", "INFO")

            # 2. Dinamik Eşik (Threshold) Hesaplaması
            # Eşik = P90 + 1.0 saniye güvenlik payı (Yanlış pozitifleri önlemek için)
            DYNAMIC_THRESHOLD_SAFETY_FACTOR = 1.0
            dynamic_threshold_s = p90_latency_s + DYNAMIC_THRESHOLD_SAFETY_FACTOR

            self.calibration_latency_ms = dynamic_threshold_s * 1000

            self.log(f"[KALİBRASYON] Dinamik SQLi Zaman Eşiği (Threshold): {dynamic_threshold_s:.2f} saniye olarak belirlendi (P90 + {DYNAMIC_THRESHOLD_SAFETY_FACTOR}s).", "SUCCESS")
            self.log(f"[KALİBRASYON] Yanıt Gecikme Varyansı (CV): {latency_cv:.2f}", "INFO")

            # YENİ DİNAMİK THROTTLING HESAPLAMASI
            if dynamic_threshold_s > 1.5:
                # Gecikme = Eşiğin 1/3'ü (sunucuyu rahatlatmak için)
                self.throttle_delay_ms = int((dynamic_threshold_s / 3) * 1000)
                # DÜZELTME 2: Log filtresi 0.5s'den 2.0s'ye çıkarıldı
                if dynamic_threshold_s > 6.0: # Eğer eşik 6 saniyeden büyükse, throttling 2 saniyeye sabitlensin
                    self.throttle_delay_ms = 2000
                self.log(f"[KALİBRASYON] Yüksek Dinamik Eşik tespit edildi. Dinamik Throttling (Yavaşlatma) {self.throttle_delay_ms:.0f} ms olarak ayarlandı.", "WARNING")
            else:
                self.throttle_delay_ms = 0

        except Exception as e:
            self.log(f"[KALİBRASYON] Kalibrasyon Hatası ({type(e).__name__}): Sabit 4.0s eşiği kullanılacak.", "CRITICAL")
            self.calibration_latency_ms = 4000  # Hata durumunda varsayılan sabit değer

        return
    
    def _analyze_and_prioritize_main_scanners(self, final_url: str):
        """
        [FAZ 25 - NEURAL TAKTİK MÜDAHALE]
        Keşif sonuçlarını (Aşama 2) analiz ederek Ana Tarama (Aşama 3) modüllerinin
        çalışma sırasını dinamik olarak yeniden düzenler (Önceliklendirir).
        """
        self.log("\n--- FAZ 25: NEURAL TAKTİK MÜDAHALE BAŞLATILIYOR (Dinamik Önceliklendirme) ---", "HEADER")
        
        # 1. Keşif Bulgularını Topla (Hazır verilere dayanarak)
        
        # WAF Durumu (WAFDetector'dan)
        waf_scanner = next((s for s in self._pre_scanners if s.category == 'WAF_DETECT'), None)
        waf_detected = waf_scanner.waf_found if waf_scanner and hasattr(waf_scanner, 'waf_found') else False
        
        # Heuristic Reflection Context (HeuristicScanner'dan)
        # NOT: HeuristicScanner AŞAMA 3'te çalıştığı için, buradaki mantıkta doğrudan kullanılamaz.
        # Bu yüzden geçici olarak bu kısım yoksayılıyor ve sadece WAF/Parametre kullanılıyor.
        heuristic_scanner = next((s for s in self._main_scanners if s.category == 'HEURISTIC'), None)
        reflection_context = "None"
        if heuristic_scanner and hasattr(heuristic_scanner, 'reflection_info'):
            pass # Bu aşamada henüz çalışmadı.
        
        # Keşfedilen Parametre Sayısı (PreScanner'dan)
        param_count = len(self.discovered_params)
        
        # 2. Öncelik Skorlarını Hesapla (Modül Adı: Skor)
        priorities: Dict[str, float] = {}
        
        # Ana Tarama Modüllerini Geç
        for scanner in self._main_scanners:
            score = 0.0
            category = scanner.category
            
            # --- Taktiksel Önceliklendirme Kuralları ---
            
            # KURAL 1: WAF Tespiti -> Smuggling ve Mantık Fuzzing'i Önceliklendir
            if waf_detected:
                if category == 'HTTP_SMUGGLING':
                    score += 5.0 # WAF'ı atlatma potansiyeli yüksek
                if category == 'BUSINESS_LOGIC':
                    score += 3.0 # WAF'ın Business Logic'e odaklanma ihtimali düşük
            
            # KURAL 2: Giriş Noktası Varlığı -> Enjeksiyon Modüllerine Yönlendir
            if param_count > 0:
                if category in ['SQLI', 'XSS', 'LFI', 'RCE_SSRF']:
                    score += 2.0 # Parametre varsa zafiyet aramak mantıklı
                
                # JSON/API Önceliği
                if category == 'JSON_API':
                    score += 4.0
                
            # KURAL 3: Kritik ve Temel Modüllere Statik Yüksek Puan (Hata ifşası, Exploit)
            if category in ['CLOUD_EXPLOIT', 'REACT_EXPLOIT', 'INTERNAL_SCAN']:
                score += 4.0 # Bu modüller her zaman yüksek kazanç potansiyeli taşır
            
            # KURAL 4: Düşük Etkili veya Dışsal Modüllere Düşük Puan
            if category in ['HEADERS', 'FILES', 'HEURISTIC', 'PORT_SCAN']:
                # Heuristic'in kendisi burada olduğu için -1.0 cezasını kaldırıyoruz, çünkü bu veriye ihtiyacımız var.
                if category != 'HEURISTIC':
                    score -= 1.0 # Keşif amaçlıdır, fuzzing sırasında öncelik düşebilir
                
            # KURAL 5: Mevcut SRP Ağırlığına Göre Dinamik Puanlama (Maksimum 5 puan ekler)
            max_srp = self.MODULE_WEIGHTS.get(category, 0.0)
            score += min(5.0, max_srp / 5.0) 

            priorities[category] = score
        
        # 3. Modülleri Yeniden Sırala
        # Modülleri skorlarına göre azalan sırada sırala (Yüksek skorlu olanlar öne alınır)
        self._main_scanners.sort(key=lambda s: priorities.get(s.category, 0.0), reverse=True)
        
        self.log(f"[NEURAL TAKTİK] Ana Tarama modülleri {len(self._main_scanners)} modül bazında yeniden önceliklendirildi.", "SUCCESS")
        
        # Loglama: Yeni sırayı göster
        new_order = [(s.category, priorities.get(s.category, 0.0)) for s in self._main_scanners]
        self.log(f"[NEURAL TAKTİK] Yeni Çalışma Sırası (Modül: Skor): {[f'{cat}:{score:.1f}' for cat, score in new_order]}", "INFO")
        
        return new_order

    def _run_chaining_analysis(self):
        """
        FAZ 9: Zafiyet zincirleme analizini gerçekleştirir.
        V7.0 GÜNCELLEMESİ: Heuristic Reflection verisi ile XSS zincirlemesi eklendi.
        """
        self.log("\n--- ZAFİYET ZİNCİRLEME ANALİZİ BAŞLATILIYOR (Exploitability Score) ---", "HEADER")

        # 1. KRİTİK ZİNCİR: LFI/SSRF + RCE/Files
        lfi_or_ssrf_found = any(
            res['category'] in ['LFI', 'RCE_SSRF'] and res['level'] == 'CRITICAL'
            for res in self.results
        )

        rce_or_file_found = any(
            (res['category'] == 'RCE_SSRF' and 'RCE Tespiti!' in res['message']) or
            (res['category'] == 'FILES' and res['level'] == 'CRITICAL')
            for res in self.results
        )
        
        # 2. ORTA ZİNCİR: JSON API Fuzzing + Enjeksiyon
        json_api_issue_found = any(res['category'] == 'JSON_API' and res['level'] in ['CRITICAL', 'WARNING'] for res in self.results)
        xss_or_sqli_found = any(res['category'] in ['XSS', 'SQLI'] and res['level'] == 'CRITICAL' for res in self.results)
        
        # 3. YENİ ZİNCİR: Heuristic Reflection + XSS Payload
        # Heuristic Scanner'ın reflection_info'sunu al (main_scanners listesi içinde bulmalıyız)
        heuristic_scanner = next((s for s in self._main_scanners if s.category == 'HEURISTIC'), None)
        is_heuristic_reflected = heuristic_scanner and hasattr(heuristic_scanner, 'reflection_info') and heuristic_scanner.reflection_info.get("is_reflected")
        
        xss_found_critical = any(res['category'] == 'XSS' and res['level'] == 'CRITICAL' for res in self.results)
        
        # --- ZİNCİR KONTROLLERİ ---

        # Zincir 1: LFI/SSRF -> RCE/Files
        if lfi_or_ssrf_found and rce_or_file_found:
            srp_deduction = self.MODULE_WEIGHTS.get("CHAINING", 0.0)  # Tam ağırlık
            self.add_result(
                "CHAINING",
                "CRITICAL",
                "KRİTİK ZİNCİRLEME: Yüksek riskli LFI/SSRF zafiyetleri ile RCE/Hassas Dosya İfşası (FILES) potansiyeli tespit edildi. Exploitability Score YÜKSEK.",
                srp_deduction,
            )
            self.log("[CHAINING] Zafiyet Zinciri Başarısı: Potansiel RCE yolu bulundu.", "CRITICAL")
            return

        # Zincir 3: Heuristic Reflection -> XSS
        if is_heuristic_reflected and xss_found_critical:
             srp_deduction = self.MODULE_WEIGHTS.get("CHAINING", 0.0) * 0.7 # Yüksek risk
             self.add_result(
                "CHAINING",
                "HIGH",
                "YÜKSEK ZİNCİRLEME: Heuristic yansıma testi pozitif. Kanıtlanmış XSS zafiyeti (XSS Modülü) bu yansıma noktasını exploit ediyor olabilir. Exploitability Score YÜKSEK.",
                srp_deduction,
             )
             self.log("[CHAINING] Zafiyet Zinciri Başarısı: Heuristic Reflection + XSS Tespiti.", "HIGH")
             return

        # Zincir 2: JSON API -> XSS/SQLi
        if json_api_issue_found and xss_or_sqli_found:
            srp_deduction = self.MODULE_WEIGHTS.get("CHAINING", 0.0) * 0.5
            self.add_result(
                "CHAINING",
                "WARNING",
                "RİSK ZİNCİRLEME: API endpoint'lerinde XSS/SQLi potansiyeli ve JSON API Fuzzing hataları tespit edildi. Bağlam zafiyeti riski.",
                srp_deduction,
            )
            self.log("[CHAINING] Zafiyet Zinciri Başarısı: API Erişim/Enjeksiyon Zafiyeti.", "WARNING")
            return

        # Hiçbir zincir bulunamadı
        self.log("[CHAINING] Zafiyet zincirleme analizini tamamlandı. Yüksek riskli zincir bulunamadı.", "INFO")

    def _run_post_scan_analysis(self):
        """
        V8.0: Tarama sonrası sonuçları analiz eder ve yanlış pozitifleri düzeltir.
        """
        self.log("\n--- POST-SCAN ANALİZİ BAŞLATILIYOR (Güvenilirlik Skorlaması) ---", "HEADER")

        is_csp_active = False
        for res in self.results:
            if res['category'] == 'HEADERS' and res['level'] == 'SUCCESS' and 'CSP politikası aktif' in res['message']:
                is_csp_active = True
                break

        if not is_csp_active:
            self.log("[POST-SCAN] CSP bulunamadı, XSS sonuçları olduğu gibi bırakılıyor.", "INFO")
            return

        xss_fixes_count = 0

        for res in self.results:
            if res['category'] == 'XSS' and res['level'] == 'CRITICAL':

                original_srp_score = self.MODULE_WEIGHTS.get("XSS", 0.0)
                new_srp_score = self.MODULE_WEIGHTS.get("XSS", 0.0) * 0.3

                res['level'] = 'WARNING'
                res['cvss_score'] = new_srp_score
                res['message'] = "[POST-SCAN DÜZELTME] " + res['message'] + " | Yüksek CSP varlığı nedeniyle SRP Düşüş {:.1f} seviyesinden {:.1f} seviyesine düşürüldü.".format(original_srp_score, new_srp_score)

                self.log(f"[{res['category']}] [DÜZELTİLDİ] {res['message']}", "WARNING")
                xss_fixes_count += 1

        if xss_fixes_count > 0:
            self._recalculate_score()
            self.log(f"[POST-SCAN] XSS Güvenilirlik Ayarlaması Tamamlandı. {xss_fixes_count} zafiyet düşürüldü.", "SUCCESS")
        else:
            self.log("[POST-SCAN] XSS sonuçlarında düzeltme gerekmedi.", "INFO")

    async def _apply_jitter_and_throttle(self):
        """
        Jitter ve Token Bucket Rate Limit mekanizmalarını uygular.
        Tüm HTTP istekleri bu metottan önce çağrılmalıdır.
        """
        # 1. JITTER Uygula (70ms - 130ms arası rastgele gecikme)
        jitter_delay = random.uniform(0.07, 0.13)
        await asyncio.sleep(jitter_delay)

        # 2. TOKEN BUCKET Uygula (QPS limitini koru)
        time_elapsed = time.time() - self.last_request_time

        # Tokenları doldur
        self.token_count += time_elapsed * MAX_QPS
        self.token_count = min(self.token_count, BURST)  # Kapasiteyi aşma

        self.last_request_time = time.time()

        # Token tüket
        if self.token_count < 1.0:
            # Token yok, bekle
            wait_time = (1.0 - self.token_count) / MAX_QPS
            
            # FAZ 27 KRİTİK KONTROL: Çok uzun bekleme süresi var mı?
            actual_wait_time = wait_time
            if wait_time > MAX_THROTTLE_WAIT_TIME:
                 self.log(f"[RATE_LIMIT | FAZ 27 LOCK] Modülün bekleme süresi ({wait_time:.3f}s) MAX_WAIT({MAX_THROTTLE_WAIT_TIME}s) aştı. Bekleme süresi {MAX_THROTTLE_WAIT_TIME}s ile sınırlanıyor.", "WARNING")
                 actual_wait_time = MAX_THROTTLE_WAIT_TIME
            
            # --- KRİTİK FP DÜZELTMESİ: SADECE CİDDİ GECİKME VARSA LOGLA (DÜZELTME 2: 2.0s yapıldı) ---
            if actual_wait_time > 2.0:
                 self.log(f"[RATE_LIMIT] KRİTİK GECİKME: QPS Limiti aşıldı. {actual_wait_time:.3f} saniye beklenecek (Konsol Filtresi Aktif).", "WARNING")
            
            await asyncio.sleep(actual_wait_time)
            
            # Beklemeden sonra, geçen süreyi hesapla ve token'ı tekrar güncelle (Refill the tokens based on the actual time spent waiting)
            time_spent_waiting = time.time() - self.last_request_time # Toplam geçen süre (Jitter + Bekleme)
            self.token_count += time_spent_waiting * MAX_QPS # Geri doldur
            self.token_count = min(self.token_count, BURST) # Kapat
            self.last_request_time = time.time() # Zamanı tekrar sıfırla

        self.token_count -= 1.0

    def _load_scanners(self, config_profile: str):
        """
        Faz 10: Seçilen yapılandırma profiline göre tarayıcı modüllerini yükler.
        """

        # KRİTİK DÜZELTME: GUI'nin hala FULL_SCAN arama ihtimaline karşın,
        # profil adını manuel olarak BUG_BOUNTY_CORE'a ayarlıyoruz.
        if config_profile not in SCAN_PROFILES:
            # GUI'den gelen eski/bilinmeyen profil ise, KAZANÇ moduna yönlendir
            self.log(f"[CONFIG] UYARI: Bilinmeyen profil '{config_profile}'. Kazanmak için {self.DEFAULT_PROFILE} kullanılıyor.", "WARNING")
            config_profile = self.DEFAULT_PROFILE
        
        # PROFİL SEÇİMİ
        profile = SCAN_PROFILES[config_profile]
        self.log(f"[CONFIG] '{config_profile}' profili yükleniyor: {profile['description']}", "INFO")

        request_cb = self.increment_request_count
        discovery_cb = self.add_discovered_param

        # Target URL'yi script manager'a gönder
        self.script_manager = DynamicScriptManager(self.log, self.target_url)
        self.exploit_manager = ExploitManager(self.log, self)
        self.oob_listener = OOBListener(self.log) # YENİ: OOB Listener'ı başlat

        is_scripting_enabled = getattr(self.script_manager, 'DYNAMIC_SCRIPTING_ENABLED', False)

        if is_scripting_enabled or 'XSS' in profile['modules']:
            self.dynamic_scanner = DynamicScanner(self.log)
        else:
            self.dynamic_scanner = None
        
        # FAZ 29 KRİTİK: Payload Generator'ı Neural Engine ile başlat
        # FAZ 40 DÜZELTME: PayloadGenerator artık Engine (self) üzerinden kuyruk sistemini kullanıyor.
        self.payload_generator = PayloadGenerator(self)
        self.log("[CONFIG] Payload Generator, Neural Engine ile başlatıldı (FAZ 29).", "INFO")

        available_scanners = {
            'WAF_DETECT': WAFDetector(self.log, self.add_result, request_cb),
            'SUBDOMAIN': DiscoveryOrchestrator(self.log, self.add_result, request_cb), # GÜNCELLENDİ: DiscoveryOrchestrator
            'SUBDOMAIN_TAKEOVER': SubdomainTakeoverScanner(self.log, self.add_result, request_cb), # YENİ MODÜL
            'PRE_SCAN': PreScanner(self.log, self.add_result, request_cb, discovery_cb),
            'HEADERS': HeadersScanner(self.log, self.add_result, request_cb),
            'FILES': FilesScanner(self.log, self.add_result, request_cb),
            'HEURISTIC': HeuristicScanner(self.log, self.add_result, request_cb),
            'AUTH_BYPASS': AuthBypassScanner(self.log, self.add_result, request_cb),
            'LFI': LFIScanner(self.log, self.add_result, request_cb),
            'XSS': XSSScanner(self.log, self.add_result, request_cb, dynamic_scanner_instance=self.dynamic_scanner),
            'SQLI': SQLiScanner(self.log, self.add_result, request_cb),
            'IDOR': IDORScanner(self.log, self.add_result, request_cb),
            # KRİTİK DEĞİŞİKLİK: OOBListener'ı RCE_SSRFScanner'a enjekte et
            'RCE_SSRF': RCE_SSRFScanner(self.log, self.add_result, request_cb, oob_listener_instance=self.oob_listener),
            'JSON_API': JSONAPIScanner(self.log, self.add_result, request_cb), # DÜZELTME: JSONAPIScaner -> JSONAPIScanner
            'PORT_SCAN': PortScanner(self.log, self.add_result, request_cb),
            'NUCLEI': NucleiScanner(self.log, self.add_result, request_cb),
            'INTERNAL_SCAN': InternalScanner(self.log, self.add_result, request_cb),
            'JS_ENDPOINT': JSEndpointScanner(self.log, self.add_result, request_cb, endpoint_pattern=JS_ENDPOINT_PATTERN),
            'GRAPHQL': GraphQLScanner(self.log, self.add_result, request_cb),
            'CLOUD_EXPLOIT': CloudExploitScanner(self.log, self.add_result, request_cb),
            'HTTP_SMUGGLING': HTTPSmugglingScanner(self.log, self.add_result, request_cb), # YENİ MODÜL: Smuggling
            'CLIENT_LOGIC': ClientLogicAnalyzer(self.log, self.add_result, request_cb), # YENİ MODÜL: ClientLogicAnalyzer
            'BUSINESS_LOGIC': BusinessLogicFuzzer(self.log, self.add_result, request_cb), # YENİ MODÜL: Logic Fuzzer
            # YENİ MODÜL: React2Shell Exploit
            'REACT_EXPLOIT': ReactExploitScanner(self.log, self.add_result, request_cb),
            'OSINT': OSINTScanner(self.log, self.add_result, request_cb), # YENİ MODÜL: OSINT
            'LEAKAGE': LeakageScanner(self.log, self.add_result, request_cb), # YENİ MODÜL: Leakage Scanner (FAZ 24)
        }

        self._pre_scanners = []
        self._main_scanners = []

        for module_name in profile['modules']:
            if module_name in available_scanners:
                scanner_instance = available_scanners[module_name]

                # YENİ: Modül eşzamanlılık semaforunu oluştur ve enjekte et (PER_MODULE_LIMIT)
                module_limit = PER_MODULE_LIMIT
                if module_name == 'NUCLEI':
                    module_limit = NUCLEI_LIMIT

                # Her modüle kendi semaforunu atama (Modülün kendi iç görevlerini limitler)
                try:
                    # Modül içindeki concurrency'yi kontrol etmek için semaphore
                    module_semaphore = asyncio.Semaphore(module_limit)
                    setattr(scanner_instance, 'module_semaphore', module_semaphore)
                    self.log(f"[CONFIG] {module_name} için Concurrency Limit: {module_limit}", "INFO")
                except AttributeError:
                    # Semaphore desteklemeyen (async olmayan) modüller olabilir
                    self.log(f"[CONFIG] {module_name} (Senkron) için Concurrency Limit atlanıyor.", "WARNING")

                # YENİ KRİTİK BAĞLANTI: Kalibrasyon ve Throttling verilerini tarayıcıya ata.
                setattr(scanner_instance, 'throttle_delay_ms', self.throttle_delay_ms)
                setattr(scanner_instance, 'calibration_latency_ms', self.calibration_latency_ms)
                # YENİ FAZ 2.2: Kalibrasyon verilerini SQLi'a iletmek için
                setattr(scanner_instance, 'latency_cv', self.latency_cv)
                setattr(scanner_instance, 'calibration_headers', self.calibration_headers)

                # YENİ FAZ 7: Token Bucket ve Jitter metodunu modüllere enjekte et
                setattr(scanner_instance, '_apply_jitter_and_throttle', self._apply_jitter_and_throttle)
                
                # --- YENİ FAZ 20: STOP MEKANİZMASI ENJEKSİYONU ---
                # Modüllerin engine'e erişerek stop_requested'ı kontrol etmesi için
                setattr(scanner_instance, 'engine_instance', self)
                # ------------------------------------------------

                # --- GHOST PROTOCOL (V18.2): KİMLİK VE PROXY ENJEKSİYONU ---
                setattr(scanner_instance, 'user_agents', DataSimulator.REAL_USER_AGENTS)
                
                # --- LIVE PROXY ENGINE (V21.0) ---
                setattr(scanner_instance, 'proxy_manager', self.proxy_manager)
                
                # --- PROJECT NEURAL (V23.0) ---
                setattr(scanner_instance, 'neural_engine', self.neural_engine)
                
                # --- FAZ 40: PAYLOAD GENERATOR'A KUYRUK ENJEKSİYONU ---
                # Payload Generator'ın Engine üzerindeki kuyruk metodunu kullanmasını sağla
                # Not: Payload Generator'ın kendisi zaten _load_scanners içinde başlatıldı.
                # Tarayıcılara Payload Generator'ı enjekte etmeden önce, Payload Generator'ı Engine'e bağlayın.
                setattr(scanner_instance, 'payload_generator', self.payload_generator)

                # FAZ 26: Thread Executor'ı sadece Senkron Modüllere enjekte et (PortScanner)
                if module_name == 'PORT_SCAN':
                    setattr(scanner_instance, 'thread_executor', self.thread_executor)
                    self.log(f"[CONFIG] {module_name} Thread Executor'a bağlandı.", "INFO")

                # SUBDOMAIN_TAKEOVER bir keşif modülüdür, pre_scanners'a ekle
                if module_name in ['WAF_DETECT', 'SUBDOMAIN', 'SUBDOMAIN_TAKEOVER', 'PRE_SCAN', 'JS_ENDPOINT', 'CLIENT_LOGIC', 'OSINT', 'LEAKAGE']: # YENİ: LEAKAGE de bir keşif/bilgi modülüdür
                    self._pre_scanners.append(scanner_instance)
                else:
                    self._main_scanners.append(scanner_instance)

            if module_name == 'NUCLEI':
                if hasattr(scanner_instance, 'nuclei_path') and scanner_instance.nuclei_path:
                    self.log(f"[CONFIG] Nuclei bulundu: {scanner_instance.nuclei_path}", "INFO")
                else:
                    self.log("[CONFIG] Nuclei yol tespiti Scanner'a devredildi.", "INFO")

        self.total_scanners = len(self._pre_scanners) + len(self._main_scanners)
        self.log(f"Toplam {self.total_scanners} adet tarama modülü yüklendi (Profil: {config_profile}).", "INFO")

    async def _scan_async(self, url):
        """
        İki aşamalı asenkron tarama döngüsünü yönetir.
        """
        self.log("\n--- ASENKRON MOTOR BAŞLATILIYOR (2 AŞAMA) ---", "HEADER")
        
        # PROXY MOTORUNU BAŞLAT (Eğer enabled ise)
        proxy_task = asyncio.create_task(self.proxy_manager.start_updater())
        
        # --- FAZ 40: AI KUYRUK İŞÇİSİNİ BAŞLAT ---
        self.ai_queue_task = asyncio.create_task(self._ai_queue_worker())

        # --- AŞAMA 0: DİNAMİK SCRIPT YÜRÜTME ---
        final_url = url

        # STOP KONTROLÜ
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
        
        # STOP KONTROLÜ
        if self.stop_requested: return

        # --- KRİTİK: İlk kalibrasyon session'ı (Adaptif timeout hesaplaması için) ---
        # NOT: Burada kullanılan session kendi connector'ı ile açılır; ana tarama connector'ından tamamen bağımsızdır.
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=5)  # Sabit 5s timeout
        ) as init_session:

            # ESKİ KONTROL KALDIRILDI: await self._run_graphql_check(init_session, final_url)
            # Artık GraphQL Scanner modülü bu işi yapacak.

            # FAZ 17: P90 Kalibrasyonu (Adaptif Timeout için veri topla)
            await self._run_calibration_scan(init_session, final_url)

        # --- ADAPTİF ZAMAN AŞIMI HESAPLAMASI (YENİ FAZ 8) ---
        p90_s = self.calibration_latency_ms / 1000
        new_timeout = max(MIN_TIMEOUT, min(MAX_TIMEOUT, p90_s * 10))
        new_timeout = round(new_timeout, 2)

        self.log(f"[PERFORMANS] Adaptif Zaman Aşımı (P90 Tabanlı): {new_timeout} saniye olarak ayarlandı.", "INFO")
        # --------------------------------------------------------

        try:
            # KRİTİK: Ana tarama için ayrı bir TCPConnector kullanılır.
            scan_connector = aiohttp.TCPConnector(limit=MAX_GLOBAL_CONCURRENCY)

            # Ana tarama session'ı, adaptif timeout ile oluşturuluyor.
            async with aiohttp.ClientSession(
                connector=scan_connector,
                timeout=aiohttp.ClientTimeout(total=new_timeout)
            ) as session:

                # --- HELPER: SAFETY WRAPPER FOR SCANNERS ---
                # Her bir tarayıcıyı belirli bir süre içinde bitmeye zorlayan,
                # aksi halde iptal eden koruyucu kapsül.
                async def _run_safe_scan(scanner_instance, scan_url, scan_session):
                    # BAŞLAMADAN ÖNCE STOP KONTROLÜ
                    if self.stop_requested:
                        self.log(f"[{scanner_instance.category}] İptal edildi (Kullanıcı İsteği).", "WARNING")
                        self._scanner_completed_callback()
                        return

                    try:
                        # Modül başına sert zaman aşımı uygulanıyor
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
                    except concurrent.futures.CancelledError: # FAZ 30 DÜZELTME
                        self.log(f"[{scanner_instance.category}] GÖREV İPTAL EDİLDİ (Thread Cancelled).", "WARNING")
                        self._scanner_completed_callback()
                    except Exception as e:
                        # FAZ 30 DÜZELTME: Genel hataları daha spesifik yakala
                        error_type = type(e).__name__
                        self.log(f"[{scanner_instance.category}] BEKLENMEDİK KRİTİK HATA ({error_type}): {e}", "CRITICAL")
                        self._scanner_completed_callback()


                # --- AŞAMA 2: KRİTİK KEŞİF VE WAF ANALİZİ ---
                if self._pre_scanners:
                    self.log("\n--- AŞAMA 2: KRİTİK KEŞİF VE WAF ANALİZİ BAŞLATILIYOR ---", "HEADER")
                    
                    if not self.stop_requested:
                        pre_scan_tasks = []
                        for scanner in self._pre_scanners:
                            if self.stop_requested: break # Döngü içi iptal
                            self.log(f"\n--- FAZ: {scanner.name} ---", "HEADER")
                            pre_scan_tasks.append(_run_safe_scan(scanner, final_url, session))

                        await asyncio.gather(*pre_scan_tasks)

                    self.log(f"\n--- KEŞİF TAMAMLANDI. ---", "SUCCESS")
                else:
                    self.log("\n--- AŞAMA 2: KEŞİF MODÜLLERİ YÜKLÜ DEĞİL. ATLANIYOR. ---", "WARNING")

                # STOP KONTROLÜ (Aşama 2 sonrası)
                if self.stop_requested:
                    self.log("\n[STOP] Tarama kullanıcı tarafından durduruldu.", "WARNING")
                    return
                
                # --- FAZ 24 KRİTİK VERİ AKIŞI: Keşif verilerini Sızıntı Tarayıcıya Enjekte Et ---
                leakage_scanner = next((s for s in self._pre_scanners if s.category == 'LEAKAGE'), None)
                if leakage_scanner:
                    # LeakageScanner bir keşif modülü olarak AŞAMA 2'ye taşındı.
                    
                    osint_emails = []
                    discovery_subdomains = []
                    # Basit ve güvenilir veri toplama simülasyonu
                    base_domain = self._get_hostname(final_url)
                    
                    # 1. Alt Alan Adlarını Topla (DiscoveryOrchestrator'dan)
                    subdomain_scanner = next((s for s in self._pre_scanners if s.category == 'SUBDOMAIN'), None)
                    if subdomain_scanner and hasattr(subdomain_scanner, 'subdomains_found'):
                        discovery_subdomains.extend(subdomain_scanner.subdomains_found)

                    # Ana alan adını da hedef listesine ekle
                    # DÜZELTME 7: Subdomain eşleşmesi için endswith mantığı eklendi.
                    protected_domain_found = any(base_domain.endswith(p) for p in self.protected_domains)
                    if not protected_domain_found:
                        all_domains = list(set(discovery_subdomains + [base_domain]))
                        setattr(leakage_scanner, 'target_domains', all_domains)

                        # 2. Potansiyel E-postaları Simüle Et (Whois / Yaygın formatlar)
                        simulated_emails = [
                            f"admin@{base_domain}",
                            f"support@{base_domain}",
                            f"dev@{base_domain}"
                        ]
                        setattr(leakage_scanner, 'target_emails', simulated_emails)
                        self.log(f"[LEAKAGE] Ana Tarayıcıya {len(leakage_scanner.target_emails)} adet e-posta ({base_domain} bazlı) ve {len(leakage_scanner.target_domains)} adet domain enjekte edildi.", "INFO")
                    else:
                        self.log(f"[LEAKAGE] KORUMA: {base_domain} korunan alanda. Sızıntı taraması atlandı.", "WARNING")

                # --- FAZ 25 KRİTİK MÜDAHALE: Ana Tarayıcıları Önceliklendir ---
                self._analyze_and_prioritize_main_scanners(final_url)

                # --- AŞAMA 3: ANA TARAMA VE FUZZING ---
                # Kalibrasyon sonuçları modüllere _load_scanners'da zaten atandı.
                # NOT: Modül sırası artık dinamiktir.
                if self._main_scanners:
                    self.log("\n--- AŞAMA 3: FUZZING VE ANALİZ MODÜLLERİ BAŞLATILIYOR (Taktiksel Sıra) ---", "HEADER")
                    
                    if not self.stop_requested:
                        main_scan_tasks = []
                        for scanner in self._main_scanners:
                            if self.stop_requested: break # Döngü içi iptal

                            # Keşif verilerini tarayıcılara enjekte et
                            setattr(scanner, 'discovered_params', self.discovered_params)
                            setattr(scanner, 'exploit_manager', self.exploit_manager)

                            # KRİTİK ZİNCİRLEME BAĞLANTISI: Heuristic verisini XSS'e geçir
                            if scanner.category == 'XSS':
                                heuristic_scanner = next((s for s in self._main_scanners if s.category == 'HEURISTIC'), None)
                                if heuristic_scanner and hasattr(heuristic_scanner, 'reflection_info'):
                                    # 1. Reflection durumu (Zafiyet Zincirleme için eski kod)
                                    setattr(scanner, 'is_heuristic_reflected', heuristic_scanner.reflection_info.get("is_reflected"))
                                    
                                    # 2. YENİ: Reflection Context bilgisini XSSScanner'a aktar (Context-Aware Polyglot için)
                                    reflection_context = heuristic_scanner.reflection_info.get("context")
                                    setattr(scanner, 'reflection_context_type', reflection_context)
                                    
                                    self.log(f"[{scanner.category}] Heuristic yansıma bilgisi aktarıldı (IsReflected: {heuristic_scanner.reflection_info.get('is_reflected')}, Context: {reflection_context}).", "INFO")


                            self.log(f"\n--- FAZ: {scanner.name} ---", "HEADER")
                            # Tüm modüller ortak session kullanıyor ve WRAPPER ile korunuyor
                            main_scan_tasks.append(_run_safe_scan(scanner, final_url, session))

                        await asyncio.gather(*main_scan_tasks)
                else:
                    self.log("\n--- AŞAMA 3: ANA TARAMA MODÜLLERİ YÜKLÜ DEĞİL. ATLANIYOR. ---", "WARNING")

        except Exception as e:
            error_message = f"Asenkron Tarama Hatası: {str(e)}"
            srp_deduction = self.MODULE_WEIGHTS.get("SYSTEM", 10.0)
            self.add_result("SYSTEM", "CRITICAL", error_message, srp_deduction)
            self._recalculate_score()
            self.log(error_message, "CRITICAL")

        finally:
            self.proxy_manager.stop_updater()
            if self.dynamic_scanner:
                self.dynamic_scanner.stop_dynamic_scan()
            # FAZ 40: AI Worker'ı durdur (Eğer run_until_complete'den önce hata olursa)
            if self.ai_queue_task:
                self.ai_queue_task.cancel()
                self.log("[NEURAL] AI Kuyruk İşçisi (Worker) durduruldu.", "INFO")


        return self.score

    def _scanner_completed_callback(self):
        """
        Bir tarayıcı modülü işini bitirdiğinde bu metot çağrılır.
        """
        self.scanners_completed += 1

        if self.total_scanners > 0:
            progress_ratio = self.scanners_completed / self.total_scanners
            # SİLİNDİ: Loglama kaldırıldı
            # self.log(f"İlerleme: %{int(progress_ratio * 100)}", "INFO")
            self.progress_update(progress_ratio)

    def run_manual_exploit(self, exploit_type: str, exploit_data: str):
        """
        GUI'den gelen manuel exploit isteğini asenkron olmayan bir thread'de Exploit Manager'a iletir.
        """
        if not self.exploit_manager:
            self.log("[EXPLOIT] Exploit Manager yüklenmedi. Exploit yürütülüyor.", "CRITICAL")
            return

        def exploit_task():
            # Exploit Data artık JSON stringi olabilir (FAZ 38 için vuln_data'yı taşır)
            self.exploit_manager.execute_manual_exploit(self.target_url, exploit_type, exploit_data)

        threading.Thread(target=exploit_task, daemon=True).start()

    def start_scan(self, url: str, config_profile: str = DEFAULT_PROFILE):
        """
        Yeni bir tarama sürecini başlatır.
        """

        # --- KRİTİK KORUMA KONTROLÜ BAŞLANGIÇ ---
        try:
            parsed_url = urlparse(url)
            hostname = parsed_url.netloc or parsed_url.path

            # Hostname'i temizle (www. ve portları kaldır)
            if ':' in hostname:
                hostname = hostname.split(':')[0]
            if hostname.startswith('www.'):
                hostname = hostname[4:]

            # Listeyi kontrol et
            # DÜZELTME 7: Yanlış pozitif engellemeyi önlemek için endswith() kullanıldı (örn: evilgoogle.com engellenir)
            if any(hostname.endswith(domain) for domain in self.protected_domains):
                self.log(f"[GÜVENLİK] KRİTİK HATA: Hedef alan adı ({hostname}) koruma listesindedir. Tarama iptal edildi.", "CRITICAL")
                # Hata durumunda bile tarayıcıları tamamlanmış sayıp GUI'yi temizleriz
                self.progress_update(1)
                return 0.0  # Skor, koruma nedeniyle sıfır olarak döndürülür.

        except Exception as e:
            self.log(f"[GÜVENLİK] URL Analiz Hatası: {e}. Koruma atlanıyor.", "CRITICAL")

        # --- KRİTİK KORUMA KONTROLÜ SONU ---

        self.score = 100.0
        self.results = []
        self.module_deduction_tracker = {mod: False for mod in self.MODULE_WEIGHTS.keys()}
        self.port_deduction_tracker = set()
        
        # STOP BAYRAĞINI SIFIRLA
        self.stop_requested = False

        self.start_time = datetime.datetime.now()
        self.target_url = url
        self.scanners_completed = 0
        self.total_requests = 0
        self.discovered_params = set()
        self.calibration_latency_ms = 4000
        self.throttle_delay_ms = 0

        # YENİ FAZ 2.2: Kalibrasyon verilerini sıfırla
        self.latency_cv = 0.0
        self.calibration_headers = {}

        # Scanner'ları yüklemeden önce kalibrasyon ve throttling değerleri sıfırlandı.
        self._load_scanners(config_profile)

        self.progress_update(0)

        self.log(f"Hedef Sistem Analiz Ediliyor: {url}", "HEADER")
        self.log(f"[PERFORMANS] Maksimum Ağ Deneme Sayısı (Retry) {MAX_REQUEST_RETRIES} olarak sabitlendi (Sonsuz döngü koruması).", "INFO")  # YENİ LOG

        try:
            if sys.platform == 'win32':
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

                def win_handler(loop, context):
                    msg = context.get("message", "")
                    if "connection_lost" in str(context.get("exception", "")) or "connection_lost" in msg:
                        return
                    if "SSL" in msg:
                        return
                    loop.default_exception_handler(context)

                loop.set_exception_handler(win_handler)

                try:
                    loop.run_until_complete(self._scan_async(url))
                finally:
                    loop.close()
            else:
                asyncio.run(self._scan_async(url))

            self._run_chaining_analysis()
            self._run_post_scan_analysis()

        except Exception as e:
            error_message = f"Kritik Motor Hatası: {str(e)}"
            srp_deduction = self.MODULE_WEIGHTS.get("SYSTEM", 10.0)
            self.add_result("SYSTEM", "CRITICAL", error_message, srp_deduction)
            self._recalculate_score()
            self.log(error_message, "CRITICAL")

        finally:
            self.thread_executor.shutdown() # FAZ 26: Thread havuzunu kapat
            if self.dynamic_scanner:
                self.dynamic_scanner.stop_dynamic_scan()
            # FAZ 40: AI Worker'ı durdur (Eğer run_until_complete'den önce hata olursa)
            if self.ai_queue_task:
                self.ai_queue_task.cancel()
                self.log("[NEURAL] AI Kuyruk İşçisi (Worker) durduruldu.", "INFO")

        return self.score

    def save_report(self):
        """
        Raporlama sınıfını kullanarak HTML ve PDF raporları oluşturur.
        """
        total_srp_deduction = sum(res['cvss_score'] for res in self.results if res['cvss_score'] > 0)
        self.total_cvss_deduction = total_srp_deduction

        html_path, pdf_path = self.reporter.generate_report()
        return html_path, pdf_path