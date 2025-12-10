# path: core/scanners/files.py

# requests kaldırıldı
import aiohttp # Asenkron HTTP istekleri için eklendi
import aiohttp.client_exceptions
from urllib.parse import urljoin
import asyncio # aiohttp'nin eş zamanlı çalışması için eklendi
from typing import Callable # Completed callback'in tipini belirtmek için eklendi

from core.scanners.base_scanner import BaseScanner

class FilesScanner(BaseScanner):
    """
    Hedef sistemde yaygın olarak hassas kabul edilen dosya ve dizinlere
    erişimi kontrol eder (.env, .git, robots.txt vb.).
    """
    
    # YENİ: request_callback argümanını alacak şekilde __init__ güncellendi
    def __init__(self, logger, results_callback, request_callback: Callable[[], None]):
        super().__init__(logger, results_callback, request_callback)
    
    @property
    def name(self):
        return "Hassas Dosya Taraması"

    @property
    def category(self):
        return "FILES"
        
    async def scan(self, url: str, session: aiohttp.ClientSession, completed_callback: Callable[[], None]):
        """
        Dosya tarama mantığını uygular (Asenkron).
        completed_callback, BaseScanner'dan gelen yeni argümandır.
        """
        # Yaygın hassas dosyalar listesi
        files_to_check = [
            '.env', 
            'package.json', 
            '.git/HEAD', 
            'wp-config.php', 
            'config.php',
            'sitemap.xml', # Bilgi ifşası
            'robots.txt' # Bilgi ifşası
        ]
        
        found_sensitive_file = False
        
        # Tüm tarama görevlerini (coroutine) oluştur
        tasks = []
        for file in files_to_check:
            # _check_single_file metoduna session objesi ve file iletilir.
            # Request callback çağrısı _check_single_file içinde yapılacaktır.
            tasks.append(self._check_single_file(url, file, session))
            
        # Tüm görevleri eş zamanlı çalıştır
        results = await asyncio.gather(*tasks)

        # Sonuçları işle
        for result in results:
            if result is not None and result.get('is_sensitive_critical'):
                found_sensitive_file = True

        if not found_sensitive_file:
            self.add_result(self.category, "SUCCESS", "Kritik hassas dosya ifşası tespit edilmedi.", 0)

        # İşlem tamamlandığında motoru bilgilendir.
        completed_callback()


    async def _check_single_file(self, base_url, file_path, session):
        """
        Tek bir dosyaya erişimi kontrol eder. Asenkron olarak çalışır.
        """
        target = urljoin(base_url, file_path)
        try:
            # İSTEK SAYACI: HTTP isteği yapmadan önce sayacı artır.
            self.request_callback()
            
            # aiohttp ile asenkron GET isteği
            async with session.get(target, allow_redirects=False) as res:
                
                # Sadece 200 dönmesi yetmez, hata sayfası değil mi kontrol et
                if res.status == 200:
                    # İçeriği oku (küçük dosyalar için uygundur)
                    content = await res.text()
                    content_lower = content.lower()
                    
                    # Basit kontrol: '404 not found' gibi ifadeler veya <html tag'i yoksa
                    # ve dosya boyutu çok küçük değilse hassas kabul et.
                    if "not found" not in content_lower and res.status != 404 and "<html" not in content_lower[:100] and len(content) > 50:
                        
                        # Robots.txt ve sitemap.xml düşük seviyeli bilgi ifşasıdır
                        if "robots.txt" in file_path or "sitemap.xml" in file_path:
                             self.add_result(self.category, "INFO", f"BİLGİ: {file_path} mevcut. İçeriği kontrol edilmeli.", 0)
                             return None
                        
                        # Diğerleri kritik
                        else:
                            score_deduction = self._calculate_score_deduction("CRITICAL")
                            self.add_result(self.category, "CRITICAL", f"KRİTİK: {file_path} dosyası erişime açık!", score_deduction)
                            return {'is_sensitive_critical': True}

        except aiohttp.client_exceptions.ClientConnectorError:
            # Ağ hatası veya zaman aşımı durumunda taramayı kesme.
            # aiohttp.ClientSession zaten motor içinde handle ediliyor, burada sadece pas geçiyoruz.
            pass
        except Exception:
            # Diğer beklenmedik hatalar
            pass
            
        return None