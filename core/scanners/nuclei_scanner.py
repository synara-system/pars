# path: core/scanners/nuclei_scanner.py

import subprocess
import json
import asyncio
import shutil
import os
from typing import Callable, List, Dict, Any
from urllib.parse import urlparse

from core.scanners.base_scanner import BaseScanner

class NucleiScanner(BaseScanner):
    """
    Sistemde yüklü olan 'nuclei' aracını çalıştırarak geniş kapsamlı zafiyet taraması yapar.
    Nuclei'nin JSON çıktısını parse eder ve Synara raporlama formatına dönüştürür.
    
    Gereksinim: Sistemde 'nuclei' komutunun çalıştırılabilir ve PATH'e ekli olması gerekir.
    """
    
    # Nuclei komut şablonu
    NUCLEI_CMD = ["nuclei", "-u", "TARGET_URL", "-silent", "-json", "-nc"]
    
    # YENİ: Nuclei için maksimum çalışma süresi (Saniye)
    # Donmaları önlemek için 180 saniye (3 dakika) sınır koyuyoruz.
    SCAN_TIMEOUT = 180 

    @property
    def name(self):
        return "Nuclei Entegrasyon Motoru"

    @property
    def category(self):
        return "NUCLEI"
        
    def __init__(self, logger, results_callback, request_callback: Callable[[], None]):
        super().__init__(logger, results_callback, request_callback)
        # Nuclei yolunu bulmaya çalış
        self.nuclei_path = self._find_nuclei_path()

    def _find_nuclei_path(self):
        """
        Nuclei çalıştırılabilir dosyasını bulmaya çalışır ve detaylı log basar.
        """
        # 1. Sistem PATH kontrolü
        path = shutil.which("nuclei")
        if path:
            self.log(f"[NUCLEI DEBUG] PATH üzerinde bulundu: {path}", "INFO")
            return path
            
        self.log("[NUCLEI DEBUG] PATH üzerinde bulunamadı. Alternatif yollar taranıyor...", "WARNING")
        
        # 2. Yaygın Windows Kurulum Yolları (Fallback)
        common_paths = [
            r"C:\Tools\Nuclei\nuclei.exe",           # Senin ekran görüntündeki yol
            r"C:\Tools\nuclei.exe",
            r"C:\Program Files\Nuclei\nuclei.exe",
            os.path.expanduser(r"~\go\bin\nuclei.exe"),
            os.path.join(os.getenv('USERPROFILE'), r"go\bin\nuclei.exe"),
            # Ekstra varyasyonlar
            r"C:\Users\Synara\go\bin\nuclei.exe",
        ]
        
        for p in common_paths:
            exists = os.path.exists(p)
            # Hata ayıklama için her denemeyi logla
            if exists:
                self.log(f"[NUCLEI DEBUG] Yedek yolda BULUNDU: {p}", "SUCCESS")
                return p
            else:
                # Sadece geliştirme aşamasında görünmesi için (Production'da kaldırılabilir)
                # self.log(f"[NUCLEI DEBUG] Kontrol edildi (Yok): {p}", "INFO")
                pass
                
        self.log("[NUCLEI DEBUG] Hiçbir yolda Nuclei bulunamadı.", "CRITICAL")
        return None

    async def scan(self, url: str, session, completed_callback: Callable[[], None]):
        """
        Nuclei taramasını başlatır ve sonuçları işler.
        """
        if not self.nuclei_path:
            self.log(f"[{self.category}] HATA: 'nuclei' aracı bulunamadı.", "CRITICAL")
            self.log(f"[{self.category}] Lütfen C:\\Tools\\Nuclei\\nuclei.exe yolunun doğru olduğundan emin olun.", "INFO")
            self.add_result(self.category, "INFO", "Nuclei aracı yüklü değil, tarama atlandı.", 0)
            completed_callback()
            return

        self.log(f"[{self.category}] Nuclei motoru başlatılıyor... (Yol: {self.nuclei_path})", "INFO")

        try:
            # Komutu hazırla
            cmd = [self.nuclei_path] + self.NUCLEI_CMD[1:] 
            cmd[2] = url 
            
            # Subprocess'i asenkron olarak çalıştır
            startupinfo = None
            if os.name == 'nt':
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                startupinfo=startupinfo
            )

            # KRİTİK GÜNCELLEME: wait_for ile zaman aşımı ekliyoruz.
            # Eğer Nuclei takılırsa, timeout süresi sonunda process kill edilir.
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=self.SCAN_TIMEOUT)
            except asyncio.TimeoutError:
                self.log(f"[{self.category}] ZAMAN AŞIMI: Nuclei {self.SCAN_TIMEOUT} saniyede tamamlanamadı. İşlem sonlandırılıyor...", "WARNING")
                try:
                    process.kill()
                except:
                    pass
                self.add_result(self.category, "WARNING", "Nuclei taraması zaman aşımına uğradı ve durduruldu.", 0)
                completed_callback()
                return

            if stderr:
                err_msg = stderr.decode(errors='ignore').strip()
                if err_msg and "error" in err_msg.lower():
                    self.log(f"[{self.category}] Nuclei stderr: {err_msg}", "INFO")

            if stdout:
                output = stdout.decode(errors='ignore')
                self._process_nuclei_output(output)
            else:
                self.log(f"[{self.category}] Nuclei taraması tamamlandı (Bulgu yok).", "INFO")
                self.add_result(self.category, "INFO", "Nuclei taraması tamamlandı. Kritik bulgu yok.", 0)

        except Exception as e:
            self.log(f"[{self.category}] Kritik Çalıştırma Hatası: {str(e)}", "CRITICAL")
            self.add_result(self.category, "CRITICAL", f"Nuclei çalıştırılamadı: {str(e)}", 0)
            
        completed_callback()

    def _process_nuclei_output(self, output: str):
        """
        Nuclei'nin JSON çıktısını (her satır bir JSON objesidir) işler.
        """
        count = 0
        for line in output.splitlines():
            if not line.strip(): continue
            
            try:
                data = json.loads(line)
                self._map_nuclei_to_synara(data)
                count += 1
            except json.JSONDecodeError:
                continue
        
        if count > 0:
             self.log(f"[{self.category}] Nuclei {count} adet bulgu raporladı.", "SUCCESS")

    def _map_nuclei_to_synara(self, data: Dict[str, Any]):
        """
        Tek bir Nuclei bulgusunu Synara sonuç formatına çevirir.
        """
        severity_map = {
            "critical": "CRITICAL",
            "high": "HIGH",
            "medium": "WARNING",
            "low": "INFO",
            "info": "INFO",
            "unknown": "INFO"
        }
        
        nuclei_severity = data.get("info", {}).get("severity", "info").lower()
        level = severity_map.get(nuclei_severity, "INFO")
        
        template_id = data.get("template-id", "unknown-template")
        name = data.get("info", {}).get("name", template_id)
        matched_at = data.get("matched-at", "")
        
        message = f"[{template_id}] {name} - Tespit: {matched_at}"
        
        cvss_score = data.get("info", {}).get("classification", {}).get("cvss-score", 0.0)
        
        if cvss_score == 0.0:
            cvss_score = self._calculate_score_deduction(level)
            
        self.add_result(self.category, level, message, cvss_score)