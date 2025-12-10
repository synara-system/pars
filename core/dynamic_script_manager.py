# path: core/dynamic_script_manager.py

import logging
import os
import re
import sys # KRİTİK DÜZELTME: sys modülü eklendi
import ast # KRİTİK DÜZELTME: ast modülü (literal_eval için) eklendi
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

class DynamicScriptManager:
    """
    Faz 12: Dinamik tarayıcı üzerinde yürütülecek aksiyon dizilerini (script) yönetir.
    Bu sınıf, GUI'den girilen hedef URL'ye göre PROJE_MANIFEST.md dosyasından
    otomatik olarak doğru scripti (login, form doldurma) seçer.
    """
    
    # --- KRİTİK KONFİGÜRASYON ALANI ---
    
    # YENİ: Kod üzerinden anında geçersiz kılma (override) için sınıf değişkeni.
    OVERRIDE_MAPPING: List[Dict[str, str]] = [] 
    
    # SCRIPT_PROFILES: Sadece GLOBAL ve Manifest'te kalan temel scriptler.
    SCRIPT_PROFILES = {
        "NO_AUTH": [], # Varsayılan: Dinamik aksiyon yok

        "GLOBAL_COMMON_LOGIN": [ 
            # 1. Bekleme
            { "action": "wait", "selector": "seconds", "value": 2.0, "description": "Global: Sayfa yüklenmesini bekle" },
            
            # 2. Kullanıcı Adı/E-posta Denemeleri (En yaygın element ID/NAME'leri)
            { "action": "type", "selector": "id", "value": "username", "text": "global_user", "description": "Global: ID='username' alanına yaz" },
            { "action": "type", "selector": "id", "value": "email", "text": "global_user@test.com", "description": "Global: ID='email' alanına yaz" },
            { "action": "type", "selector": "name", "value": "login", "text": "global_user", "description": "Global: Name='login' alanına yaz" },
            { "action": "type", "selector": "xpath", "value": "//input[@type='text' or @type='email']", "text": "global_user@test.com", "description": "Global: İlk görünen text/email input'a yaz" },

            # 3. Şifre Denemeleri
            { "action": "type", "selector": "id", "value": "password", "text": "S3cureP@ss123", "description": "Global: ID='password' alanına yaz" },
            { "action": "type", "selector": "name", "value": "sifre", "text": "S3cureP@ss123", "description": "Global: Name='sifre' alanına yaz" },
            
            # 4. Gönderme Denemeleri
            { "action": "click", "selector": "id", "value": "login-button", "description": "Global: ID='login-button' a tıkla" },
            { "action": "click", "selector": "xpath", "value": "//button[@type='submit' or @type='button'][contains(text(), 'Giriş') or contains(text(), 'Login')]", "description": "Global: 'Giriş/Login' yazılı butona tıkla" },
            
            # 5. Başarı Kontrolü
            { "action": "wait", "selector": "seconds", "value": 3.0, "description": "Global: Sonuç için bekle" },
        ],
        
        # Manifest'te var olduğu için bırakıldı (Manifest'i okuyacak)
        "MOCK_LOGIN": [ 
            { "action": "wait", "selector": "seconds", "value": 2.0, "description": "Sayfanın yüklenmesi için bekle" },
            { "action": "type", "selector": "id", "value": "username", "text": "test_user", "description": "Kullanıcı adı alanına yaz" },
            { "action": "type", "selector": "id", "value": "password", "text": "S3cureP@ss123", "description": "Şifre alanına yaz" },
            { "action": "click", "selector": "xpath", "value": "//button[@type='submit']", "description": "Giriş yap butonuna tıkla" },
            { "action": "wait", "selector": "url_contains", "value": "/dashboard", "text": "Dashboard URL'inin yüklenmesini bekle" },
        ],
    }
    
    # --- KRİTİK KONFİGÜRASYON ALANI SONU ---
    
    # GÜNCELLEME: Hedef URL artık __init__ metoduna parametre olarak geliyor.
    def __init__(self, logger_callback, target_url: str):
        self.log = logger_callback
        self.loaded_script: List[Dict[str, Any]] = []
        self.target_url = target_url # Yeni: Hedef URL'yi kaydet
        
        # Manifest'ten MAPPING kurallarını okur ve script'i yükler.
        script_name = self._determine_active_script(target_url)
        
        if script_name != "NO_AUTH":
            self.loaded_script = self.SCRIPT_PROFILES.get(script_name, [])
            self.log(f"[DYNAMIC SCRIPT] Aktif Script: '{script_name}' ({len(self.loaded_script)} aksiyon) (Hedef Eşleşmesi: {target_url})", "INFO")
        else:
            self.log("[DYNAMIC SCRIPT] URL, Manifest kuralıyla eşleşmedi. Dinamik Script Yürütme kapalı.", "INFO")


    def _get_manifest_path(self):
        """Manifest dosyasının yolunu döndürür."""
        
        # KRİTİK DÜZELTME: Paketlenmiş ortamda kaynak dosyaya kesin erişim.
        if getattr(sys, 'frozen', False):
            # Dosyamız sys._MEIPASS/docs/PROJE_MANIFEST.md yolunda paketlenmişti.
            base_path = sys._MEIPASS 
        else:
            base_path = os.getcwd()
            
        return os.path.join(base_path, "docs", "PROJE_MANIFEST.md")

    def _load_script_mapping(self):
        """PROJE_MANIFEST.md dosyasından DYNAMIC_SCRIPT_MAPPING'i okur."""
        
        # ADIM 1: OVERRIDE_MAPPING kontrolü (Yeni eklenen esneklik)
        # Eğer sınıf değişkeni (OVERRIDE_MAPPING) kod tarafından ayarlandıysa, onu kullan.
        if DynamicScriptManager.OVERRIDE_MAPPING:
            self.log("[DYNAMIC SCRIPT] OVERRIDE MAPPING kullanılıyor (Manifest atlandı).", "INFO")
            return DynamicScriptManager.OVERRIDE_MAPPING
            
        # ADIM 2: Manifest'ten okuma (Fallback mekanizması)
        try:
            manifest_path = self._get_manifest_path()
            with open(manifest_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # RegEx ile DYNAMIC_SCRIPT_MAPPING bloğunu yakala
            match = re.search(r'DYNAMIC_SCRIPT_MAPPING\s*=\s*(\[.*?\])', content, re.DOTALL)
            
            if match:
                self.log("[DYNAMIC SCRIPT] Manifest MAPPING başarıyla okundu (Fallback).", "INFO")
                # KRİTİK: Ast modülü kullanılarak string, list/dict yapısına çevrilir.
                return ast.literal_eval(match.group(1))
            
            self.log("[DYNAMIC SCRIPT] Manifest'te DYNAMIC_SCRIPT_MAPPING bloğu bulunamadı.", "WARNING")
            return []
            
        except FileNotFoundError:
             # Kritik: Dosya bulunamadı hatası. Bu, EXE içinde Manifest'in bulunamadığı anlamına gelir.
             self.log(f"[DYNAMIC SCRIPT] Manifest okuma/ayrıştırma hatası: FileNotFoundError ({self._get_manifest_path()})", "CRITICAL")
             return []
        except Exception as e:
            self.log(f"[DYNAMIC SCRIPT] Manifest okuma/ayrıştırma hatası: {type(e).__name__}", "CRITICAL")
            return []

    def _determine_active_script(self, url: str) -> str:
        """Verilen URL'ye göre Manifest/Override'dan uygun script adını döndürür."""
        
        mapping = self._load_script_mapping()
        
        # KRİTİK DÜZELTME BAŞLANGIŞ: Override kullanıldıysa, eşleşme kontrolünü atla
        # Eğer mapping'in ilk elemanı, GUI tarafından OVERRIDE için gönderildiyse
        # (yani OVERRIDE_MAPPING doluyduysa), script adını doğrudan kullan.
        if DynamicScriptManager.OVERRIDE_MAPPING and mapping and mapping[0].get("script_name") in self.SCRIPT_PROFILES:
             script_name = mapping[0].get("script_name")
             self.log(f"[DYNAMIC SCRIPT] OVERRIDE: Script '{script_name}' doğrudan yüklendi.", "INFO")
             return script_name
        # KRİTİK DÜZELTME SONU
        
        parsed_url = urlparse(url)
        target_netloc = parsed_url.netloc.lower()
        
        # www. ön ekini temizle
        if target_netloc.startswith('www.'):
            target_netloc = target_netloc[4:]

        for rule in mapping:
            fragment = rule.get("target_url_fragment", "").lower()
            script_name = rule.get("script_name", "NO_AUTH")

            # Basit string eşleşmesi (Manifest'te tanımlanan fragment, URL'nin netloc'unda geçiyor mu?)
            if fragment and fragment in target_netloc:
                # Script_name'in SCRIPT_PROFILES içinde var olup olmadığını kontrol et
                if script_name in self.SCRIPT_PROFILES:
                    return script_name
                else:
                    self.log(f"[DYNAMIC SCRIPT] UYARI: Manifest'te tanımlı script '{script_name}' mevcut profillerde yok.", "WARNING")

        return "NO_AUTH"


    def is_script_loaded(self) -> bool:
        """Yürütülecek bir scriptin yüklü olup olmadığını kontrol eder."""
        return bool(self.loaded_script)
        
    def get_script(self) -> List[Dict[str, Any]]:
        """Yüklü aksiyon dizisini döndürür."""
        return self.loaded_script