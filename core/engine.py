# path: core/engine.py

import datetime
import asyncio  # Asenkron çalışma için eklendi
import aiohttp  # Asenkron HTTP istekleri için eklendi
import time  # Yüksek hassasiyetli zaman ölçümü için eklendi
import threading  # YENİ: Dinamik tarayıcı yönetimi için
import sys  # YENİ: Platform kontrolü için eklendi (Windows Fix)
import shutil
import os  # YENİ: Dosya yolu kontrolü için
import statistics  # YENİ: P90 hesaplaması için
import re  # Port analizi için
import json  # YENİ: Protected Domains JSON dosyasını okumak için
import math  # Adaptif timeout için
import random  # YENİ FAZ 7: Jitter için eklendi

from .dynamic_scanner import DynamicScanner  # GÖRECELİ İMPORT: Headless tarayıcı (Selenium) entegrasyonu için
from .exploit_manager import ExploitManager  # GÖRECELİ İMPORT: FAZ 11: Yeni Exploit Yöneticisi
from .dynamic_script_manager import DynamicScriptManager  # GÖRECELİ İMPORT: FAZ 12: Dinamik Aksiyon Yöneticisi
from .oob_listener import OOBListener # YENİ: OOB Sinyal Takibi için
from .proxy_manager import ProxyManager # YENİ FAZ 21: Canlı Proxy Yöneticisi
# YENİ: Neural Engine (Yapay Zeka)
from .neural_engine import NeuralEngine 
from typing import List, Dict, Any, Optional # YENİ: Optional import edildi
from urllib.parse import urlparse  # YENİ: URL parse etmek için

# Mimarinin diğer bileşenleri
from .reporter import SynaraReporter  # GÖRECELİ İMPORT
# Faz 3: Payload Generator'ı import et (Diğer modüller tarafından kullanılabilir olması için)
from .payload_generator import PayloadGenerator # GÖRECELİ İMPORT
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


# --- KONFIGURASYON SABİTLERİ ---
# Global eşzamanlı HTTP istek limiti (Ağ şişmesini ve hedef sistemi yavaşlatmayı engeller)
MAX_GLOBAL_CONCURRENCY = 10
# Her bir modülün kendi içinde kullanabileceği maksimum eşzamanlı görev sayısı
PER_MODULE_LIMIT = 5
# NucleiScanner için özel limit (Dış işlem olduğu için daha düşük tutuldu)
NUCLEI_LIMIT = 3
# ---------------------------------------------------

# --- GÜVENLİK ZAMAN AŞIMI (ANTI-FREEZE) ---
# Bir modül (örn: PortScanner) bu sürede yanıt vermezse motor onu zorla kapatır ve devam eder.
MODULE_HARD_TIMEOUT = 90  # KRİTİK DÜZELTME: 240'tan 90 saniyeye düşürüldü.
# ------------------------------------------

# --- ADAPTİF ZAMAN AŞIMI SABİTLERİ (YENİ) ---
MIN_TIMEOUT = 2.0  # Minimum zaman aşımı saniye
MAX_TIMEOUT = 7.0  # Maksimum zaman aşımı saniye
# --------------------------------------------

# --- DENEME SAYISI (RETRY) SABİTİ (YENİ) ---
# Deneme sayısı 1'e düşürüldü (Initial attempt + 0 retries)
MAX_REQUEST_RETRIES = 1
# ------------------------------------------

# --- JS ENDPOINT EXTRACTOR SABİTİ (YENİ FAZ 6) ---
# Endpoint'leri yakalamak için Regex (php, json, js, jsp, aspx)
JS_ENDPOINT_PATTERN = r'[A-Za-z0s9_\-]+\.(php|json|js|jsp|aspx)'
# --------------------------------------------------

# --- ML FALSE POSITIVE VERİTABANI YOLU (YENİ FAZ 7) ---
FP_DB_PATH = "fp_database.json"
# ------------------------------------------------------

# --- TOKEN BUCKET RATE LIMIT SABİTLERİ (YENİ FAZ 7) ---
MAX_QPS = 5.0  # Maksimum sorgu/saniye
BURST = 10.0   # Token biriktirme kapasitesi (Burst)
# ------------------------------------------------------


# Faz 10: Tanımlanmış Tarama Profilleri
SCAN_PROFILES = {
    # GUI'nin beklediği FULL_SCAN'ı geri ekledik (KeyError'ı engeller)
    "FULL_SCAN": {
        "description": "Tüm modüller (Hafiften Kapsamlı Fuzzing'e kadar). En yavaş ve en derin tarama.",
        "modules": ['WAF_DETECT', 'SUBDOMAIN', 'SUBDOMAIN_TAKEOVER', 'PRE_SCAN', 'HEADERS', 'FILES', 'PORT_SCAN', 'HEURISTIC', 'AUTH_BYPASS', 'LFI', 'XSS', 'SQLI', 'IDOR', 'RCE_SSRF', 'JSON_API', 'CLOUD_EXPLOIT', 'REACT_EXPLOIT', 'NUCLEI', 'INTERNAL_SCAN', 'JS_ENDPOINT', 'GRAPHQL', 'CLIENT_LOGIC', 'HTTP_SMUGGLING', 'BUSINESS_LOGIC']
    },
    # KRİTİK KAZANÇ PROFİLİ (Kullanıcının tercih ettiği modül listesi)
    "BUG_BOUNTY_CORE": {
        "description": "BBH (Bug Bounty Hunter - SADECE KAZANÇ): Yüksek Ödüllü Kritik Zafiyetler ve Gelişmiş Keşif için optimize edilmiştir.",
        "modules": ['WAF_DETECT', 'SUBDOMAIN', 'SUBDOMAIN_TAKEOVER', 'PRE_SCAN', 'JS_ENDPOINT', 'HEADERS', 'FILES', 'HEURISTIC', 'AUTH_BYPASS', 'LFI', 'XSS', 'SQLI', 'IDOR', 'RCE_SSRF', 'REACT_EXPLOIT', 'JSON_API', 'CLOUD_EXPLOIT', 'PORT_SCAN', 'CLIENT_LOGIC', 'HTTP_SMUGGLING', 'BUSINESS_LOGIC']
    },
    # Diğer eski modüller (GUI'nin ihtiyacı için geri getirildi)
    "LIGHT": {
        "description": "Sadece Temel Analiz ve Zeka (Headers, Files, Heuristic). Çok hızlı.",
        "modules": ['WAF_DETECT', 'SUBDOMAIN', 'PRE_SCAN', 'JS_ENDPOINT', 'HEADERS', 'FILES', 'PORT_SCAN', 'HEURISTIC', 'INTERNAL_SCAN', 'CLIENT_LOGIC']
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

# AR-GE: SYNARA GERÇEKLİK PUANI (SRP) V3.0 - MODÜL AĞIRLIKLARI (Maksimum Tek Seferlik Düşüş)
# Port cezası agresif hale getirildi.
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
    "PORT_SCAN": 0.0,  # GÜNCELLENDİ (Playtika Filtresi): Banner/Port Taraması Kapsam Dışı.
    "WAF_DETECT": 0.0, # GÜNCELLENDİ (Playtika Filtresi): WAF Tespiti Kapsam Dışı.
    "SUBDOMAIN": 0.0,  # Sadece Bilgi Amaçlı
    "NUCLEI": 0.0,     # Nuclei sonuçları ayrı değerlendirilebilir, şimdilik 0
    "CHAINING": 15.0,  # Zafiyet Zincirleme (Ekstra düşüş)
    "SYSTEM": 5.0,     # Kritik Sistem/Motor Hatası (Genel hatalar için düşürüldü)
    "INTERNAL_SCAN": 20.0  # YENİ: Dahili sistem sızıntısı (Hardcoded sır vb.)
}

class SynaraScannerEngine:
    """
    Synara'nın ana tarama motoru. Zafiyet modüllerini (plugin) yükler,
    tarama sürecini yönetir, sonuçları biriktirir ve skoru hesaplar.
    """
    # Faz 10: Varsayılan profil
    DEFAULT_PROFILE = "BUG_BOUNTY_CORE" # KRİTİK DEĞİŞİKLİK

    # Faz 10: Skor, CVSS 0.0 - 10.0 aralığından normalize edilerek hesaplanacaktır.
    # Başlangıç skoru 100 (CVSS Skalasına göre 0.0) olacaktır.
    # KRİTİK: HEADLESS MOD İÇİN CALLBACK'LER OPSİYONEL YAPILDI
    def __init__(self, logger_callback=None, progress_callback=None, config_profile: str = DEFAULT_PROFILE):
        # Eğer callback yoksa (Headless/Server Modu), boş bir fonksiyon ata.
        self.log = logger_callback if logger_callback else self._headless_log
        self.progress_update = progress_callback if progress_callback else self._headless_progress
        
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

        # Faz 10: Yapılandırma değişkenleri
        self.config_profile = config_profile
        self.total_cvss_deduction = 0.0  # KRİTİK DÜZELTME: Raporlama için geri eklendi.

        # YENİ: Her modül için düşüşün bir kez yapıldığını takip et
        self.module_deduction_tracker = {mod: False for mod in MODULE_WEIGHTS.keys()}
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

    # --- HEADLESS HELPER FUNCTIONS ---
    def _headless_log(self, message, level="INFO"):
        """GUI olmayan ortamlar için varsayılan log fonksiyonu."""
        # Burada gerekirse dosyaya yazma veya stdout yapılabilir.
        # Server modunda bu, API tarafından override edilir.
        # print(f"[{level}] {message}") 
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
        ML tabanlı simülasyon: Sonucun daha önce raporlanmış bir FP olup olmadığını kontrol eder.
        """
        if not self.fp_database:
            return False

        # Basit karşılaştırma mantığı (ML simülasyonu)
        # Gerçek ML burada bir vektör karşılaştırması yapardı.
        for fp_entry in self.fp_database:
            if fp_entry.get("category") == category:
                # Eğer mesajın büyük bir kısmı bilinen FP mesajını içeriyorsa, FP olarak işaretle
                if fp_entry.get("message", "").lower() in message.lower():
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
        PUANLAMA ALGORİTMASI V3.0 (Gerçeklik Düzeni)
        """

        total_deduction = 0.0
        deductions_applied = set()

        for res in self.results:
            category = res['category']

            # PORT_SCAN için özel kural (Her kritik port için ceza)
            if category == "PORT_SCAN" and res['cvss_score'] > 0:
                total_deduction += res['cvss_score']

            # Diğer Modüller için normal kural (Modül başına bir kez)
            elif category in MODULE_WEIGHTS and category != "PORT_SCAN" and category not in deductions_applied and res['cvss_score'] > 0:
                total_deduction += res['cvss_score']
                deductions_applied.add(category)

        # Skoru hesapla ve 0-100 arasında sınırla
        self.score = max(0.0, 100.0 - total_deduction)

    def add_result(self, category: str, level: str, message: str, cvss_score: float, poc_data: Optional[Dict[str, Any]] = None):
        """
        Faz 10: Tarayıcı modüllerinden gelen sonuçları ana listeye ekler ve skoru CVSS/SRP'ye göre günceller.
        Faz 18: poc_data parametresi ile otomatik POC raporu ve cURL komutu üretir.
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
            srp_deduction = MODULE_WEIGHTS.get(category, 0.0)  # Tam ağırlık
        elif level == "HIGH":
            srp_deduction = MODULE_WEIGHTS.get(category, 0.0) * 0.7  # %70 ağırlık
        elif level == "WARNING":
            srp_deduction = MODULE_WEIGHTS.get(category, 0.0) * 0.3  # %30 ağırlık
        else:
            srp_deduction = 0.0

        # --- BÜYÜK ÖLÇEKLİ ORTAM FİLTRESİ (HYPERSCALE) ---
        # Bu filtre artık genel koruma listesinden sonra, sadece hassas zafiyetler için çalışır.
        is_google = "google.com" in self.target_url.lower() or "gmail.com" in self.target_url.lower()
        is_time_based_sqli = category == "SQLi" and "Time-Based SQLi" in message
        is_idor = category == "IDOR" and original_score > 0

        if is_google and (is_time_based_sqli or is_idor):
            if is_time_based_sqli or is_idor:
                level = "INFO"
                srp_deduction = 0.0
                message += " [UYARI: HYPERSCALE FİLTRESİ AKTİF. Güvenilirlik 0.0'a düşürüldü.]"

        # KRİTİK SRP V2.1: Modül başına bir kez düşüş kuralı
        # PORT_SCAN ve SYSTEM dışındaki modüller için normal kuralı uygula
        if category in MODULE_WEIGHTS and category not in ["PORT_SCAN", "SYSTEM"]:
            if srp_deduction > 0.0 and self.module_deduction_tracker.get(category, False):
                srp_deduction = 0.0  # Zaten düşülmüş, tekrar düşme
            elif srp_deduction > 0.0:
                self.module_deduction_tracker[category] = True  # İlk kez düşüldü olarak işaretle

        # PORT_SCAN için özel mantık (Hacker Odaklı): Her KRİTİK port için ayrı düşüş
        elif category == "PORT_SCAN" and level == "CRITICAL":
            port_number = None
            try:
                port_match = re.search(r'Port: (\d+)', message)
                if port_match:
                    port_number = int(port_match.group(1))
            except Exception:
                pass

            if port_number and port_number in [21, 23, 3306] and port_number not in self.port_deduction_tracker:
                # Her kritik port, PORT_SCAN ağırlığının 1/3'ü kadar ceza alır. (27.0 / 3 = 9.0)
                srp_deduction = MODULE_WEIGHTS.get("PORT_SCAN", 0.0) / 3.0
                self.port_deduction_tracker.add(port_number)
            else:
                srp_deduction = 0.0

        # FAZ 11 KRİTİK: Exploit önerisi ekle
        exploit_suggestion = ""
        if original_level in ["CRITICAL", "HIGH", "CHAINING_CRITICAL"] and self.exploit_manager:
            exploit_suggestion = self.exploit_manager.generate_exploit_suggestion(
                {'category': category, 'level': original_level, 'cvss_score': original_score}
            )
            if level != original_level and exploit_suggestion:
                exploit_suggestion = "[Exploit önerisi filtrelendi: Büyük ölçekli ortamda manuel doğrulama gerekli.]"
            elif exploit_suggestion and "Otomatik sömürü önerisi bulunamadı." not in exploit_suggestion:
                message += f" [Exploit Önerisi: {exploit_suggestion}]"

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

        # YENİ: Neural Engine Analizi (Sadece Kritik Bulgular İçin)
        if self.neural_engine.is_active and original_level in ["CRITICAL", "HIGH"]:
            # AI Analizini arka planda başlat (Asenkron olmadığı için burada blocking olmasın diye thread veya basitçe log)
            # Not: Tam asenkron entegrasyon için add_result'ın async olması gerekirdi.
            # Şimdilik "Sonraki Adım" olarak not düşüyoruz.
            message += " [AI Analizi Bekleniyor...]"

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
                self.log(f"[KALİBRASYON] Yüksek Dinamik Eşik tespit edildi. Dinamik Throttling (Yavaşlatma) {self.throttle_delay_ms:.0f} ms olarak ayarlandı.", "WARNING")
            else:
                self.throttle_delay_ms = 0

        except Exception as e:
            self.log(f"[KALİBRASYON] Kalibrasyon Hatası ({type(e).__name__}): Sabit 4.0s eşiği kullanılacak.", "CRITICAL")
            self.calibration_latency_ms = 4000  # Hata durumunda varsayılan sabit değer

        return

    def _run_chaining_analysis(self):
        """
        FAZ 9: Zafiyet zincirleme analizini gerçekleştirir.
        V7.0 GÜNCELLEMESİ: Heuristic Reflection verisi ile XSS zincirlemesi eklendi.
        """
        self.log("\n--- ZAFİYET ZİNCİRLEME ANALİZİ BAŞLATILIYOR (Exploitability Score) ---", "HEADER")

        # 1. KRİTİK ZİNCİR: LFI/SSRF + RCE/Files
        lfi_or_ssrf_found = any(
            res['category'] in ['LFI', 'SSRF_RCE'] and res['level'] == 'CRITICAL'
            for res in self.results
        )

        rce_or_file_found = any(
            (res['category'] == 'SSRF_RCE' and 'RCE Tespiti!' in res['message']) or
            (res['category'] == 'FILES' and res['level'] == 'CRITICAL')
            for res in self.results
        )
        
        # 2. ORTA ZİNCİR: JSON API Fuzzing + Enjeksiyon
        json_api_issue_found = any(res['category'] == 'JSON_API' and res['level'] in ['CRITICAL', 'WARNING'] for res in self.results)
        xss_or_sqli_found = any(res['category'] in ['XSS', 'SQLI'] and res['level'] == 'CRITICAL' for res in self.results)
        
        # 3. YENİ ZİNCİR: Heuristic Reflection + XSS Payload
        # Heuristic Scanner'ın reflection_info'sunu al (main_scanners listesi içinde bulmalıyız)
        heuristic_scanner = next((s for s in self._main_scanners if s.category == 'HEURISTIC'), None)
        is_heuristic_reflected = heuristic_scanner and heuristic_scanner.reflection_info.get("is_reflected")
        
        xss_found_critical = any(res['category'] == 'XSS' and res['level'] == 'CRITICAL' for res in self.results)
        
        # --- ZİNCİR KONTROLLERİ ---

        # Zincir 1: LFI/SSRF -> RCE/Files
        if lfi_or_ssrf_found and rce_or_file_found:
            srp_deduction = MODULE_WEIGHTS.get("CHAINING", 0.0)  # Tam ağırlık
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
             srp_deduction = MODULE_WEIGHTS.get("CHAINING", 0.0) * 0.7 # Yüksek risk
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
            srp_deduction = MODULE_WEIGHTS.get("CHAINING", 0.0) * 0.5
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

                original_srp_score = MODULE_WEIGHTS.get("XSS", 0.0)
                new_srp_score = MODULE_WEIGHTS.get("XSS", 0.0) * 0.3

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
            
            # --- KRİTİK FP DÜZELTMESİ: SADECE CİDDİ GECİKME VARSA LOGLA (WAIT > 0.5s) ---
            if wait_time > 0.5:
                 self.log(f"[RATE_LIMIT] KRİTİK GECİKME: QPS Limiti aşıldı. {wait_time:.3f} saniye beklenecek (Konsol Filtresi Aktif).", "WARNING")
            
            await asyncio.sleep(wait_time)
            self.token_count = 1.0  # Bekleme sonrası 1 token garantisi
            self.last_request_time = time.time()  # Bekleme sonrası zamanı güncelle

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
            'JSON_API': JSONAPIScanner(self.log, self.add_result, request_cb),
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

                # SUBDOMAIN_TAKEOVER bir keşif modülüdür, pre_scanners'a ekle
                if module_name in ['WAF_DETECT', 'SUBDOMAIN', 'SUBDOMAIN_TAKEOVER', 'PRE_SCAN', 'JS_ENDPOINT', 'CLIENT_LOGIC']:  # CLIENT_LOGIC keşif modülü olarak eklendi
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
                        # Callback'i manuel çağırarak progress bar'ın takılmasını önle
                        self._scanner_completed_callback()
                    except asyncio.CancelledError:
                        self.log(f"[{scanner_instance.category}] GÖREV İPTAL EDİLDİ.", "WARNING")
                        self._scanner_completed_callback()
                    except Exception as e:
                        self.log(f"[{scanner_instance.category}] BEKLENMEDİK HATA (Wrapper): {e}", "CRITICAL")
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

                # --- AŞAMA 3: ANA TARAMA VE FUZZING ---
                # Kalibrasyon sonuçları modüllere _load_scanners'da zaten atandı.
                if self._main_scanners:
                    self.log("\n--- AŞAMA 3: FUZZING VE ANALİZ MODÜLLERİ BAŞLATILIYOR ---", "HEADER")
                    
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
            srp_deduction = MODULE_WEIGHTS.get("SYSTEM", 10.0)
            self.add_result("SYSTEM", "CRITICAL", error_message, srp_deduction)
            self._recalculate_score()
            self.log(error_message, "CRITICAL")

        finally:
            self.proxy_manager.stop_updater()
            if self.dynamic_scanner:
                self.dynamic_scanner.stop_dynamic_scan()

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
            if any(domain in hostname for domain in self.protected_domains):
                self.log(f"[GÜVENLİK] KRİTİK HATA: Hedef alan adı ({hostname}) koruma listesindedir. Tarama iptal edildi.", "CRITICAL")
                # Hata durumunda bile tarayıcıları tamamlanmış sayıp GUI'yi temizleriz
                self.progress_update(1)
                return 0.0  # Skor, koruma nedeniyle sıfır olarak döndürülür.

        except Exception as e:
            self.log(f"[GÜVENLİK] URL Analiz Hatası: {e}. Koruma atlanıyor.", "CRITICAL")

        # --- KRİTİK KORUMA KONTROLÜ SONU ---

        self.score = 100.0
        self.results = []
        self.module_deduction_tracker = {mod: False for mod in MODULE_WEIGHTS.keys()}
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
            srp_deduction = MODULE_WEIGHTS.get("SYSTEM", 10.0)
            self.add_result("SYSTEM", "CRITICAL", error_message, srp_deduction)
            self._recalculate_score()
            self.log(error_message, "CRITICAL")

        finally:
            if self.dynamic_scanner:
                self.dynamic_scanner.stop_dynamic_scan()

        return self.score

    def save_report(self):
        """
        Raporlama sınıfını kullanarak HTML ve PDF raporları oluşturur.
        """
        total_srp_deduction = sum(res['cvss_score'] for res in self.results if res['cvss_score'] > 0)
        self.total_cvss_deduction = total_srp_deduction

        html_path, pdf_path = self.reporter.generate_report()
        return html_path, pdf_path