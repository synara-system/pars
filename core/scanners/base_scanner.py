# path: core/scanners/base_scanner.py

import abc 
from typing import Callable, Tuple, Any, Dict
import aiohttp
import asyncio
import time
import random

class BaseScanner(abc.ABC):
    """
    Tüm Synara zafiyet tarama modülleri için soyut temel sınıf (Plugin arayüzü).
    Her modül bu sınıftan türemek ve zorunlu metotları uygulamak zorundadır.
    """
    
    # Faz 10: CVSS Temel Puanları (CVSS v3.1 0-10 Aralığı baz alınmıştır)
    CVSS_SCORES = {
        "CRITICAL": 9.0,      # CVSS: 9.0 - 10.0
        "HIGH": 7.0,          # CVSS: 7.0 - 8.9 (WARNING yerine YÜKSEK risk için CVSS temelli bir WARNING seviyesi)
        "WARNING": 4.0,       # CVSS: 4.0 - 6.9 (Medium)
        "INFO": 0.0,
        "SUCCESS": 0.0,
        "CHAINING_CRITICAL": 9.8, # Zincirleme saldırıların skorunu yükseltmek için
        "CHAINING_WARNING": 5.0,  # Orta riskli zincirleme saldırılar için
    }
    
    # YENİ ARGÜMAN EKLENDİ: request_callback
    def __init__(self, logger, results_callback, request_callback: Callable[[], None]):
        # Loglama ve sonuç ekleme fonksiyonlarını dışarıdan alır.
        self.log = logger
        self.add_result = results_callback
        # YENİ: Motorun istek sayacını artırmak için callback
        self.request_callback = request_callback
        # YENİ: Dinamik throttling için
        self.throttle_delay_ms = 0 # Engine tarafından atanacak (Milisaniye)
        # KRİTİK FAZ 24 DÜZELTMESİ: Simülasyon modu kapalıdır (Sahte veri parkına girmeyeceğiz).
        self.is_simulation_mode = False 
        
        # --- GHOST PROTOCOL: KIMLIK VE PROXY HAVUZU ---
        # Engine tarafından doldurulacak
        self.user_agents = []
        self.proxy_manager = None # YENİ: Proxy Yöneticisi Referansı
        # YENİ: Neural Engine Referansı (Varsayılan None)
        self.neural_engine = None 

    
    @property
    @abc.abstractmethod
    def name(self):
        """Bu tarayıcının adını döndürür (örnek: 'HTTP Headers Scanner')"""
        pass

    @property
    @abc.abstractmethod
    def category(self):
        """Raporlamada kullanılacak kategori adını döndürür (örnek: 'HEADERS')"""
        pass
        
    @abc.abstractmethod
    async def scan(self, url: str, session, completed_callback: Callable[[], None]):
        """
        Zafiyet tarama mantığını uygular.
        
        Args:
            url (str): Tarama yapılacak hedef URL.
            session (aiohttp.ClientSession): Kullanılacak asenkron HTTP oturumu.
            completed_callback (Callable): Tarayıcı işini bitirdiğinde motoru bilgilendirmek için kullanılır.
        """
        pass
    
    def _calculate_score_deduction(self, level: str) -> float:
        """
        Faz 10: Tespit edilen zafiyet seviyesine göre CVSS Temel Skorunu döndürür.
        """
        # Dictionary'den CVSS puanını doğrudan float olarak döndürürüz.
        # Bu puan, motorda 100 üzerinden düşüş puanı olarak kullanılacaktır.
        return self.CVSS_SCORES.get(level, 0.0)

    # --- YENİ: Zafiyet Kaydı ve Otomatik AI Analizi ---
    async def consult_ai(self, vuln_data: Dict[str, Any]):
        """Tespit edilen zafiyet için Yapay Zeka (Gemini) görüşü alır."""
        if self.neural_engine and self.neural_engine.is_active:
            self.log(f"[{self.category}] AI Analizi başlatılıyor...", "INFO")
            # Not: analyze_vulnerability metodu NeuralEngine içinde tanımlanmalı
            analysis = await self.neural_engine.analyze_vulnerability(vuln_data)
            self.log(f"[{self.category}] AI Görüşü: {analysis}", "SUCCESS")
            # Sonucu loga ekle (Gelişmiş versiyonda rapora da eklenebilir)

    # --- YENİ: DINAMIK HIZ SINIRLAYICI METODU (THROTTLING) VE GHOST REQUEST ---
    async def _throttled_request(self, session: aiohttp.ClientSession, method: str, url: str, **kwargs) -> Tuple[aiohttp.ClientResponse | None, float]:
        """
        Dinamik gecikme uygulayarak, kimlik değiştirerek ve istek sayacını güncelleyerek bir HTTP isteği yapar.
        V21.0 UPDATE: Proxy Rotasyonu ve Otomatik WAF Atlatma mekanizması eklendi.
        
        Returns: (response, latency_s)
        """
        
        # Throttling mantığı: Sadece fuzzing işlemleri (POST/PUT/SQLi/LFI) için uygula
        if self.throttle_delay_ms > 0 and method.upper() not in ['GET', 'HEAD']:
            # GHOST PROTOCOL: Rastgele Stealth Jitter (1.0 - 2.5s arası ek bekleme)
            stealth_jitter = random.uniform(1.0, 2.5)
            total_delay_s = (self.throttle_delay_ms / 1000.0) + stealth_jitter
            await asyncio.sleep(total_delay_s)
            self.log(f"[{self.category}] Stealth Throttling: {total_delay_s:.2f}s gecikme (Ghost Mode).", "INFO")

        self.request_callback()
        
        # PROXY ROTASYON DÖNGÜSÜ
        max_retries = 3 # Bir istek için maksimum deneme (Proxy değişimi ile)
        
        for attempt in range(max_retries):
            
            # 1. Header Hazırlığı (Her denemede taze User-Agent)
            headers = kwargs.pop('headers', {}).copy()
            
            if self.user_agents:
                headers['User-Agent'] = random.choice(self.user_agents)
                
            headers['X-Bug-Bounty'] = 'True'
            
            # kwargs'ı güncelle
            current_kwargs = kwargs.copy()
            current_kwargs['headers'] = headers
            
            # Otomatik yönlendirmeleri kapat
            current_kwargs.setdefault('allow_redirects', False) 
            current_kwargs.setdefault('timeout', aiohttp.ClientTimeout(total=20))

            # 2. Proxy Seçimi (Canlı Havuzdan)
            proxy = None
            if self.proxy_manager:
                proxy = self.proxy_manager.get_proxy()
                if proxy:
                    current_kwargs['proxy'] = proxy
            
            start_time = time.time()
            
            try:
                async with session.request(method, url, **current_kwargs) as response:
                    
                    # 3. WAF Kontrolü (403/429 = Proxy Yanmış Olabilir)
                    if response.status in [403, 429]:
                        if self.proxy_manager and proxy:
                            self.proxy_manager.report_bad_proxy(proxy)
                            # Eğer son deneme değilse, log bas ve tekrar dene
                            if attempt < max_retries - 1:
                                self.log(f"[{self.category}] WAF Engellemesi ({response.status}). Proxy ({proxy}) değiştiriliyor...", "DEBUG")
                                continue
                    
                    # Başarılı (veya geçerli bir HTTP yanıtı)
                    await response.read() 
                    latency = time.time() - start_time
                    return response, latency

            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                # Bağlantı hatası durumunda proxy'yi raporla ve tekrar dene
                if self.proxy_manager and proxy:
                    self.proxy_manager.report_bad_proxy(proxy)
                
                # Son denemeyse pes et
                if attempt == max_retries - 1:
                    latency = time.time() - start_time
                    return None, latency
                
                continue # Yeni proxy ile tekrar dene
                
            except Exception:
                latency = time.time() - start_time
                return None, latency
        
        return None, 0.0