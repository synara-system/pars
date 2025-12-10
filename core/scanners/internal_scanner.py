# path: core/scanners/internal_scanner.py

import os
import re
import sys
import json
import shutil # KRİTİK EKLENTİ: shutil.which() kullanımı için eklendi.
from typing import Callable, List, Dict, Any, Tuple
from .base_scanner import BaseScanner # BaseScanner'dan türetilecektir.

# Bu, Synara'nın kendi sistem dosyalarını (Manifest, Codebase, Secrets, vb.) tarayan modüldür.
# Harici ağ trafiği oluşturmaz.

class InternalScanner(BaseScanner):
    """
    [AR-GE v2.1 - SELF-INSPECTION]
    Synara Core'un dahili zafiyet tarama modülü.
    Yerel dosya sistemini, hardcoded sırlar, Manifest tutarlılığını ve kritik bağımlılıkları kontrol eder.
    """
    
    # Yeni: Yüksek entropili sırları bulmak için REGEX deseni
    # En az 16 karakter uzunluğunda, büyük/küçük harf, rakam veya özel karakter içeren desenler.
    API_KEY_REGEX = r'(?:api_key|secret|token|password|passwd|auth_token)[\s:]*[\'"]?([a-zA-Z0-9_\-!@#$%^&*()+=]{16,128})[\'"]?'
    
    # Faz 28: Kodu temizlediğimiz için, artık SADECE ENV'DE OLMASI GEREKEN anahtar kontrolü yapılır.
    API_KEY_TO_CHECK = os.environ.get("GEMINI_API_KEY_HINT") or "API_KEY_A1B2C3D4E5F6G7H8_MESTEG_TOKEN"
    
    @property
    def name(self):
        return "Internal System Scanner (GİZLİ MİSYON)"

    @property
    def category(self):
        return "INTERNAL_SCAN"
        
    def __init__(self, logger, results_callback, request_callback: Callable[[], None]):
        # BaseScanner init'ini çağır
        super().__init__(logger, results_callback, request_callback)
        # KRİTİK DÜZELTME: Sadece gerçekten harici olan ve Python modülü olmayan dosyalar kontrol edilir.
        self.critical_files = [
            os.path.join(self._find_base_path(), "SYNARA_PRIME_CORE.sys"), 
            os.path.join(self._find_base_path(), "docs", "PROJE_MANIFEST.md"),
            os.path.join(self._find_base_path(), "protected_domains.json"),
        ]
        
    def _find_base_path(self):
        """Uygulamanın çalıştığı ana dizini döndürür. (PyInstaller Uyumlu)"""
        # KRİTİK DÜZELTME: Eğer program EXE içine paketlenmişse (frozen), 
        # dosyaların çıkartıldığı sanal dizini (sys._MEIPASS) kullan.
        if getattr(sys, 'frozen', False):
            return sys._MEIPASS 
        # Normal Python ortamında, o anki çalışma dizinini kullan.
        return os.getcwd()


    async def scan(self, url: str, session, completed_callback: Callable[[], None]):
        """
        Dahili sistem kontrolünü senkronize olarak yürütür (asyncio.to_thread gerekecektir).
        """
        self.log(f"[{self.category}] Synara'nın yerel çekirdeği {self._find_base_path()} konumunda analiz ediliyor...", "INFO")
        
        # 1. HASSAS DOSYA İFŞASI KONTROLÜ
        self._check_file_system_exposure()
        
        # 2. CODEBASE GİZLİLİK KONTROLÜ (Geliştirme ortamında kalan sırlar)
        self._check_secrets_in_codebase()
        
        # 3. MANIFEST TUTARLILIK KONTROLÜ
        self._check_manifest_integrity()
        
        # 4. KRİTİK BAĞIMLILIK KONTROLÜ (Nuclei/Harici Exploitler)
        self._check_critical_dependencies()
        
        # Tarama tamamlandı
        completed_callback()


    def _check_file_system_exposure(self):
        """Kritik dahili dosyaların varlığını kontrol eder."""
        missing_count = 0
        for fpath in self.critical_files:
            if not os.path.exists(fpath):
                self.add_result(
                    self.category,
                    "CRITICAL",
                    f"Kritik çekirdek dosyası '{os.path.basename(fpath)}' bulunamadı. Tamamlanmış/Paketlenmiş sistem bütünlüğü riski.",
                    self._calculate_score_deduction("CRITICAL")
                )
                missing_count += 1
            else:
                 self.log(f"[{self.category}] Kritik dosya bulundu: {os.path.basename(fpath)} [OK]", "SUCCESS")
        
        if missing_count == 0:
             self.add_result(self.category, "INFO", "Tüm kritik çekirdek dosyaları yerinde.", 0)


    def _check_secrets_in_codebase(self):
        """
        [Geri Getirildi] Python dosyalarında hardcoded sırlar var mı diye bakar.
        Sadece PyInstaller'dan bağımsız, geliştirme ortamında kalan .py dosyalarını tarar.
        """
        base_path = self._find_base_path()
        secret_found = False

        # Eğer paketlenmiş bir ortamdaysak, Codebase okuma girişimini atla.
        if getattr(sys, 'frozen', False):
            self.log(f"[{self.category}] Codebase gizlilik taraması paketlenmiş ortamda atlanıyor.", "INFO")
            return
            
        # Sadece geliştirme ortamında kalan kritik Python dosyalarını tarar (Örn: main.py, engine.py)
        code_files_to_check = [
            os.path.join(base_path, "main.py"), 
            os.path.join(base_path, "core", "engine.py"),
            os.path.join(base_path, ".env.local"), # Env dosyasını da kontrol et
        ]
        
        for fpath in code_files_to_check:
            if not os.path.exists(fpath):
                continue
            
            try:
                with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                for match in re.finditer(self.API_KEY_REGEX, content, re.IGNORECASE):
                    key_hint = match.group(0).split(':')[0].split('=')[0].strip()
                    secret_value = match.group(1).strip()
                    
                    # Eğer secret, bildiğimiz bir placeholder değilse raporla
                    if self.API_KEY_TO_CHECK not in secret_value and secret_value not in self.API_KEY_TO_CHECK:
                        self.add_result(
                            self.category,
                            "CRITICAL",
                            f"HARDCODED SECRET: Kodda hassas anahtar '{key_hint}' bulundu! Dosya: {os.path.basename(fpath)}",
                            self._calculate_score_deduction("CRITICAL")
                        )
                        secret_found = True
                        
            except Exception as e:
                self.log(f"[{self.category}] Codebase Okuma Hatası ({os.path.basename(fpath)}): {e}", "WARNING")
                
        if not secret_found and not getattr(sys, 'frozen', False):
             self.add_result(self.category, "INFO", "Açık kod dosyalarında hardcoded secret bulunamadı.", 0)


    def _check_manifest_integrity(self):
        """[YENİ] PROJE_MANIFEST.md dosyasının kritik kısımlarının varlığını ve formatını kontrol eder."""
        manifest_path = os.path.join(self._find_base_path(), "docs", "PROJE_MANIFEST.md")
        
        if not os.path.exists(manifest_path):
            self.add_result(self.category, "CRITICAL", "PROJE_MANIFEST.md dosyası eksik! Sistem mimari haritası kayıp.", self._calculate_score_deduction("CRITICAL"))
            return

        try:
            with open(manifest_path, 'r', encoding='utf-8') as f:
                content = f.read()

            critical_sections = ["## 1. MİMARİ", "## 2. GÜVENLİK KURALLARI", "## 3. VERİ YAPILARI"]
            
            integrity_ok = True
            missing_sections = [] # KRİTİK DÜZELTME: Eksik bölümleri toplayacak liste

            for section in critical_sections:
                if section not in content:
                    missing_sections.append(section)
                    integrity_ok = False
            
            if missing_sections:
                 # Tek bir bilgi mesajında topla, SRP düşüşü 0.0 olduğu için gürültüyü azaltır
                 self.add_result(self.category, "INFO", f"Manifesto'da kritik bölümler eksik: {', '.join(missing_sections)}", 0) 
            
            # Kontrol: Manifest içindeki "Gemini API" anahtarının yer tutucu olup olmadığını kontrol et
            if "GEMINI_API_KEY" in content and "YOUR_API_KEY" in content:
                # Bu bir placeholder, sorun yok
                pass
            elif re.search(self.API_KEY_REGEX, content, re.IGNORECASE):
                 self.add_result(self.category, "WARNING", "Manifesto içinde hardcoded API key bulunma şüphesi.", self._calculate_score_deduction("WARNING"))


            if integrity_ok and not missing_sections: # Sadece her şey tamamsa temiz mesajı ver
                self.add_result(self.category, "INFO", "PROJE_MANIFEST.md bütünlüğü ve formatı onaylandı.", 0)

        except Exception as e:
            self.add_result(self.category, "CRITICAL", f"Manifesto okuma/parse etme hatası: {e}", self._calculate_score_deduction("CRITICAL"))


    def _check_critical_dependencies(self):
        """[YENİ] Harici bağımlılıkların (binary'ler) sistemde varlığını kontrol eder."""
        
        # Sadece Nuclei'yi kontrol ediyoruz, çünkü o harici bir binary.
        is_nuclei_path_set = False
        
        # NucleiScanner'ın yolunu kontrol etmek için Engine'e gitmek zordur. Basitçe PATH'te arayalım.
        if shutil.which("nuclei"):
            self.add_result(self.category, "SUCCESS", "Harici bağımlılık (Nuclei) PATH'te bulundu. Kullanıma hazır.", 0)
            is_nuclei_path_set = True
        
        if not is_nuclei_path_set:
            self.add_result(self.category, "WARNING", "Harici bağımlılık (Nuclei) PATH'te bulunamadı. NucleiScanner atlanacaktır.", self._calculate_score_deduction("WARNING") / 2)
            
        # DYNAMIC SCANNER (Chromium) kontrolü de eklenebilir, ancak _setup_driver() zaten bunu yapıyor.
        pass