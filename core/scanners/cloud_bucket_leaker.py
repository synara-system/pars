# path: core/scanners/cloud_bucket_leaker.py

import asyncio
import aiohttp
from typing import Callable, List, Dict, Any
from urllib.parse import urlparse
from core.scanners.base_scanner import BaseScanner

class CloudBucketLeakerScanner(BaseScanner):
    """
    Hedef organizasyonun ismini kullanarak AWS S3, Google Cloud Storage ve Azure Blob
    üzerinde unutulmuş veya açık bırakılmış depolama alanlarını (Bucket) tespit eder.
    
    FAZ 41: Cloud Bucket Leaker
    """

    def __init__(self, logger, results_callback, request_callback: Callable[[], None]):
        super().__init__(logger, results_callback, request_callback)
        
        # Taranacak Bulut Sağlayıcı Şablonları
        self.providers = [
            {"name": "AWS S3", "url": "https://{name}.s3.amazonaws.com"},
            {"name": "Google Cloud", "url": "https://storage.googleapis.com/{name}"},
            {"name": "Azure Blob", "url": "https://{name}.blob.core.windows.net"}
        ]
        
        # Yaygın Ekler (Permütasyonlar için)
        self.keywords = [
            "dev", "prod", "test", "staging", "backup", "private", "public", 
            "assets", "media", "static", "images", "files", "docs", "logs", 
            "db", "database", "archive", "secret", "conf", "config"
        ]

    @property
    def name(self):
        return "Cloud Bucket Leaker"

    @property
    def category(self):
        return "CLOUD_BUCKET"

    def _generate_permutations(self, base_name: str) -> List[str]:
        """
        Hedef isminden olası bucket isimlerini türetir.
        """
        names = [base_name] # Saf isim
        
        # 'google', 'gruyere' gibi kelimeleri ayır
        parts = base_name.split('-') + base_name.split('.')
        clean_parts = [p for p in parts if len(p) > 2]
        
        # Temel permütasyonlar
        for keyword in self.keywords:
            names.append(f"{base_name}-{keyword}")
            names.append(f"{base_name}_{keyword}")
            names.append(f"{keyword}-{base_name}")
            names.append(f"{base_name}{keyword}")
            
            # Parçalı permütasyonlar (örn: google-dev)
            for part in clean_parts:
                if part != base_name:
                    names.append(f"{part}-{keyword}")
                    names.append(f"{part}{keyword}")

        return list(set(names)) # Benzersiz yap

    async def scan(self, url: str, session, completed_callback: Callable[[], None]):
        self.log(f"[{self.category}] Bulut depolama alanları için keşif başlatılıyor...", "INFO")
        
        # Domainden isim kökünü çıkar (örn: google-gruyere.appspot.com -> google-gruyere)
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        if domain.startswith("www."):
            domain = domain[4:]
        
        # Kök ismi bul (basitçe ilk nokta öncesi veya tamamı)
        base_name = domain.split('.')[0]
        if len(base_name) < 3: # Çok kısaysa domainin kendisini al
             base_name = domain.replace('.', '-')

        bucket_names = self._generate_permutations(base_name)
        
        # Toplam taranacak URL sayısı
        total_checks = len(bucket_names) * len(self.providers)
        self.log(f"[{self.category}] Hedef: '{base_name}' için {total_checks} olası bucket taranacak.", "INFO")

        tasks = []
        sem = asyncio.Semaphore(15) # Aynı anda 15 istek

        async def check_bucket(bucket_name, provider):
            async with sem:
                # Durdurma kontrolü
                if hasattr(self, 'engine_instance') and self.engine_instance.stop_requested:
                    return

                target_url = provider["url"].format(name=bucket_name)
                
                try:
                    if self.request_cb: self.request_cb()
                    
                    # Timeout'u kısa tut, bucket yoksa genelde DNS hatası veya hızlı 404 döner
                    async with session.get(target_url, timeout=5) as resp:
                        status = resp.status
                        
                        # 200 OK: Bucket var ve listelenebilir (KRİTİK)
                        if status == 200:
                            content = await resp.text()
                            # XML içeriği varsa listeleme açıktır (S3/GCP)
                            if "ListBucketResult" in content or "<Name>" in content:
                                msg = f"AÇIK BUCKET BULUNDU: {target_url} ({provider['name']}) - Dosyalar Listelenebilir!"
                                self.log(f"[{self.category}] {msg}", "CRITICAL")
                                self.add_result(self.category, "CRITICAL", msg, 20.0, poc_data={"url": target_url})
                            else:
                                # Statik site vb. olabilir
                                msg = f"Erişilebilir Bucket: {target_url} ({provider['name']}) - (Statik Site Olabilir)"
                                self.log(f"[{self.category}] {msg}", "HIGH")
                                self.add_result(self.category, "HIGH", msg, 10.0, poc_data={"url": target_url})

                        # 403 Forbidden: Bucket var ama kilitli (BİLGİ)
                        elif status == 403:
                            msg = f"S3 Bucket Mevcut (Erişim Engelli): {target_url}"
                            # self.log(f"[{self.category}] {msg}", "INFO") # Çok fazla log olmaması için kapalı tutulabilir
                            # Sadece info olarak ekle, puan düşme
                            self.add_result(self.category, "INFO", msg, 0.0)
                            
                except Exception:
                    # DNS hataları veya timeout normaldir (bucket yok demektir)
                    pass

        # Görevleri oluştur
        for name in bucket_names:
            for provider in self.providers:
                tasks.append(check_bucket(name, provider))

        await asyncio.gather(*tasks)
        
        self.log(f"[{self.category}] Bulut taraması tamamlandı.", "SUCCESS")
        completed_callback()