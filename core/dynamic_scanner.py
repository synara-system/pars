# path: core/dynamic_scanner.py

import logging
import time
from urllib.parse import urlparse
from typing import Optional, Tuple, List, Dict, Any, Union

# --- SAFE IMPORT BLOĞU ---
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.common.exceptions import WebDriverException, TimeoutException, NoSuchElementException
    from selenium.webdriver.common.by import By 
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False
    # Tip ipuçları için dummy sınıflar (IDE hatasını önler)
    webdriver = None
    Options = None
    WebDriverException = Exception
    TimeoutException = Exception
    NoSuchElementException = Exception
# -------------------------

class DynamicScanner:
    """
    [AR-GE v2.0 - SESSION DOMINATOR]
    Headless Chrome kullanarak dinamik DOM ve JavaScript analizini yönetir.
    Bu sınıf, geleneksel aiohttp akışından ayrılan, senkronize bir katman sağlar.
    Başarılı login sonrası oturum durumunu (çerez, localStorage) çeker.
    """
    
    # XSS'in başarılı olduğunu belirten benzersiz işaretçi
    XSS_SUCCESS_MARKER = "SynaraXSSSuccess12345"
    
    def __init__(self, logger_callback):
        self.log = logger_callback
        self.driver: Optional[Any] = None # Tip Any yapıldı çünkü webdriver olmayabilir
        # Çekilen oturum verilerini tutar
        self.session_state: Dict[str, Any] = {"cookies": [], "localStorage": {}}
        
        if not SELENIUM_AVAILABLE:
            self.log("[DYNAMIC SCANNER] UYARI: Selenium kütüphanesi yüklü değil. Dinamik modül devre dışı.", "WARNING")

    def _setup_driver(self):
        """Headless Chrome tarayıcısını başlatır."""
        
        if not SELENIUM_AVAILABLE:
            self.log("[DYNAMIC SCANNER] HATA: Selenium yüklü olmadığı için tarayıcı başlatılamaz.", "CRITICAL")
            return False

        self.log("[DYNAMIC SCANNER] Headless Chrome başlatılıyor...", "INFO")
        
        try:
            options = Options()
            options.add_argument("--headless")       # Başsız mod
            options.add_argument("--disable-gpu")
            options.add_argument("--no-sandbox")     # Güvenlik önlemi
            options.add_argument("--ignore-certificate-errors")
            options.add_argument("--window-size=1920,1080")
            
            # Anti-Bot önlemleri: Gerçek tarayıcı gibi davranmak için User-Agent ekle
            options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
            
            # Ağ isteklerini yavaşlatmadan DOM'u analiz etmek için gerekli
            options.page_load_strategy = 'eager' 

            # Sürücü yönetimini PyInstaller'a uyumlu tutmak için manuel yolla dener
            self.driver = webdriver.Chrome(options=options)
            self.driver.set_page_load_timeout(30) # Sayfa yükleme için maksimum 30 saniye
            self.log("[DYNAMIC SCANNER] Headless Chrome hazır.", "SUCCESS")
            return True
            
        except Exception as e:
            self.log(f"[DYNAMIC SCANNER] KRİTİK HATA: Headless Chrome başlatılamadı. {e}", "CRITICAL")
            self.log("Lütfen 'chromedriver' dosyasının sistem PATH'inde veya uygulamanın yanında olduğundan emin olun.", "CRITICAL")
            return False

    def _cleanup(self):
        """Tarayıcıyı kapatır."""
        if self.driver:
            try:
                self.driver.quit()
            except Exception:
                pass
            self.driver = None
            self.log("[DYNAMIC SCANNER] Headless Chrome kapatıldı.", "INFO")

    def extract_session_state(self) -> Dict[str, Any]:
        """
        [YENİ METOT] Tarayıcıdan oturum çerezlerini ve kritik localStorage verilerini çeker.
        """
        if not self.driver:
            # Sessizce dön (Log spam yapma)
            return {"cookies": [], "localStorage": {}}

        try:
            # 1. Çerezleri çek
            cookies = self.driver.get_cookies()

            # 2. LocalStorage'daki kritik anahtarları çek
            # JWT, Token, UserData gibi anahtarları ararız.
            local_storage_data = {}
            js_script = """
                const keys = ['token', 'jwt', 'auth', 'user', 'session', 'api_key'];
                const data = {};
                keys.forEach(key => {
                    const value = localStorage.getItem(key);
                    if (value) {
                        data[key] = value.substring(0, 50) + (value.length > 50 ? '...' : ''); // Kısmi değer çek
                    }
                });
                return data;
            """
            critical_ls_data = self.driver.execute_script(js_script)
            
            # Tüm localStorage'ı çek (genellikle çok büyük olmaz)
            all_ls_data = self.driver.execute_script("return window.localStorage;")

            self.session_state["cookies"] = cookies
            self.session_state["localStorage"] = all_ls_data
            
            if cookies or critical_ls_data:
                self.log(f"[SESSION EXTRACTOR] Başarılı! {len(cookies)} çerez ve {len(critical_ls_data)} kritik LS anahtarı çekildi.", "SUCCESS")
                
            return self.session_state
            
        except WebDriverException as e:
            self.log(f"[SESSION EXTRACTOR] Veri Çekme Hatası: {e}", "CRITICAL")
            return {"cookies": [], "localStorage": {}}
        except Exception as e:
            self.log(f"[SESSION EXTRACTOR] Beklenmedik Hata: {e}", "CRITICAL")
            return {"cookies": [], "localStorage": {}}


    def analyze_dom_xss(self, url: str, payload: str) -> Tuple[bool, str]:
        """
        Verilen URL'yi yükler, DOM'a payload enjekte eder ve XSS tetiklenmesini kontrol eder.
        Dönüş: (is_vulnerable, final_url)
        """
        if not SELENIUM_AVAILABLE:
            return False, ""

        # KRİTİK İYİLEŞTİRME: Payload'ı alert() yerine Synara'nın işaretçisini yazdıran 
        # ve tarayıcıyı dondurmayan bir JS kodu olarak hazırlarız.
        js_payload = payload.replace("alert(1)", f"document.body.innerHTML += '{self.XSS_SUCCESS_MARKER}'")
        js_payload = js_payload.replace("confirm(1)", f"document.body.innerHTML += '{self.XSS_SUCCESS_MARKER}'")
        js_payload = js_payload.replace("prompt(1)", f"document.body.innerHTML += '{self.XSS_SUCCESS_MARKER}'")
        

        if not self.driver and not self._setup_driver():
            return False, ""
        
        try:
            self.driver.get(url)
            
            # DOM XSS kontrolü (Senaryo 1: Payload'ın doğrudan tetiklenmesi)
            if self.XSS_SUCCESS_MARKER in self.driver.page_source:
                self.log(f"[DYNAMIC SCANNER] KRİTİK: Gerçek zamanlı DOM XSS tespiti! Marker bulundu.", "CRITICAL")
                return True, self.driver.current_url
            
            # Senaryo 2: Payload'ı Hash/URL fragment'ına yazıp tetikleme (Single Page App'ler için)
            if "#" in payload:
                # Payload'ın hash kısmını ayır
                hash_part = payload.split('#', 1)[-1]
                # Tarayıcıya hash'i değiştirme komutu gönder
                self.driver.execute_script(f"window.location.hash = '{hash_part}'")
                time.sleep(1) # DOM'un hash değişikliğine tepki vermesi için kısa bekleme
                
                if self.XSS_SUCCESS_MARKER in self.driver.page_source:
                    self.log(f"[DYNAMIC SCANNER] KRİTİK: Hash tabanlı DOM XSS tespiti! Marker bulundu.", "CRITICAL")
                    return True, self.driver.current_url
                
            return False, self.driver.current_url
            
        except TimeoutException:
            self.log("[DYNAMIC SCANNER] Tarayıcı zaman aşımı (30s) hatası.", "WARNING")
            return False, self.driver.current_url if self.driver else ""
        except WebDriverException as e:
            self.log(f"[DYNAMIC SCANNER] WebDriver Hatası: {e}", "CRITICAL")
            return False, ""
        except Exception as e:
            self.log(f"[DYNAMIC SCANNER] Beklenmedik Hata: {e}", "CRITICAL")
            return False, ""

    # Tarama bittiğinde motor bu metodu çağırmalıdır.
    def stop_dynamic_scan(self):
        self._cleanup()
        
    
    # --- FAZ 12: DİNAMİK SCRIPT YÜRÜTÜCÜ ---
    
    def execute_script(self, url: str, actions: List[Dict[str, Any]]) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Verilen URL'yi yükler ve script aksiyonlarını sırayla yürütür.
        Dönüş: (success, final_url, session_state)
        """
        if not SELENIUM_AVAILABLE:
            return False, "", {}

        if not self.driver and not self._setup_driver():
            return False, "", {}
            
        self.log(f"[DYNAMIC SCRIPT] İlk URL yükleniyor: {url}", "INFO")
        
        # Giriş öncesi temizlik (güvenlik için)
        try:
            self.driver.delete_all_cookies()
            self.driver.execute_script("window.localStorage.clear();")
        except Exception:
            pass
        
        try:
            self.driver.get(url)
            wait = WebDriverWait(self.driver, 15) # Bekleme süresi 15 saniyeye çıkarıldı
            
            for action in actions:
                action_type = action.get("action")
                selector_type = action.get("selector")
                selector_value = action.get("value")
                description = action.get("description", "Aksiyon")

                self.log(f"[DYNAMIC SCRIPT] Yürütülüyor: {description}", "INFO")
                
                if self._get_by_type(selector_type) is not None:
                    # Type ve Click aksiyonları
                    by_type = self._get_by_type(selector_type)
                    
                    if action_type == "type":
                        text_to_send = action.get("text", "")
                        try:
                            # Elementin görünür/bulunabilir olmasını bekle
                            element = wait.until(EC.presence_of_element_located((by_type, selector_value)))
                            element.send_keys(text_to_send)
                            self.log(f"[DYNAMIC SCRIPT] -> '{text_to_send}' yazıldı.", "SUCCESS")
                        except TimeoutException:
                            error_msg = f"Element bulunamadı/yüklenmedi ({selector_type}='{selector_value}') - Timeout (15s)."
                            self.log(f"[DYNAMIC SCRIPT] HATA: Yazma aksiyonu başarısız oldu: {error_msg}", "WARNING")
                            return False, self.driver.current_url, self.extract_session_state()
                        except NoSuchElementException:
                            error_msg = f"Element bulunamadı ({selector_type}='{selector_value}')."
                            self.log(f"[DYNAMIC SCRIPT] HATA: Yazma aksiyonu başarısız oldu: {error_msg}", "WARNING")
                            return False, self.driver.current_url, self.extract_session_state()

                    elif action_type == "click":
                        try:
                            # Elementin tıklanabilir olmasını bekle
                            element = wait.until(EC.element_to_be_clickable((by_type, selector_value)))
                            element.click()
                            self.log("[DYNAMIC SCRIPT] -> Tıklama başarılı.", "SUCCESS")
                        except TimeoutException:
                            error_msg = f"Element bulunamadı/tıklanamadı ({selector_type}='{selector_value}') - Timeout (15s)."
                            self.log(f"[DYNAMIC SCRIPT] HATA: Tıklama aksiyonu başarısız oldu: {error_msg}", "WARNING")
                            return False, self.driver.current_url, self.extract_session_state()
                        except NoSuchElementException:
                            error_msg = f"Element bulunamadı ({selector_type}='{selector_value}')."
                            self.log(f"[DYNAMIC SCRIPT] HATA: Tıklama aksiyonu başarısız oldu: {error_msg}", "WARNING")
                            return False, self.driver.current_url, self.extract_session_state()
                
                elif action_type == "wait":
                    wait_type = action.get("selector")
                    wait_value = action.get("value")
                    if wait_type == "seconds":
                        time.sleep(float(wait_value)) # wait_value float olmalı
                        self.log(f"[DYNAMIC SCRIPT] -> {wait_value} saniye beklendi.", "SUCCESS")
                    elif wait_type == "url_contains":
                        wait.until(EC.url_contains(wait_value))
                        self.log(f"[DYNAMIC SCRIPT] -> URL '{wait_value}' içerene kadar beklendi.", "SUCCESS")
                    elif wait_type == "element_visible":
                        # BY Tipi burada çağrılır, görünür olmasını bekle
                        element_by = self._get_by_type(selector_type)
                        wait.until(EC.visibility_of_element_located((element_by, selector_value)))
                        self.log(f"[DYNAMIC SCRIPT] -> Element '{selector_value}' görünür olana kadar beklendi.", "SUCCESS")

                # Her adımdan sonra kısa bir bekleme (Arayüz geçişleri için)
                time.sleep(0.5) 

            self.log("[DYNAMIC SCRIPT] Script yürütme tamamlandı. Oturum durumu çekiliyor...", "SUCCESS")
            # BAŞARILI SONUÇ: Oturum durumunu çek ve döndür
            session_state = self.extract_session_state()
            return True, self.driver.current_url, session_state
            
        except TimeoutException:
            self.log("[DYNAMIC SCRIPT] Script yürütme sırasında kritik zaman aşımı (15s kuralı) hatası.", "CRITICAL")
            return False, self.driver.current_url, self.extract_session_state()
        except WebDriverException as e:
            self.log(f"[DYNAMIC SCRIPT] WebDriver Hatası (Yürütme): {e}", "CRITICAL")
            return False, self.driver.current_url if self.driver else "", self.extract_session_state()
        except Exception as e:
            self.log(f"[DYNAMIC SCRIPT] Beklenmedik Hata (Yürütme): {e}", "CRITICAL")
            return False, self.driver.current_url if self.driver else "", self.extract_session_state()


    def _get_by_type(self, selector_type: str) -> Optional[str]:
        """String selector tipini Selenium By objesine çevirir."""
        if not SELENIUM_AVAILABLE: return None

        selector_type = selector_type.lower()
        if selector_type == 'id':
            return By.ID
        elif selector_type == 'name':
            return By.NAME
        elif selector_type == 'xpath':
            return By.XPATH
        elif selector_type == 'css':
            return By.CSS_SELECTOR
        elif selector_type == 'link':
            return By.LINK_TEXT
        else:
            return None


    def get_page_source_for_js_scan(self, url: str) -> str:
        """
        JS keşfi için tarayıcıyı kullanarak HTML sayfa kaynağını çeker.
        Bu, CDN engellemelerini aşmak için kullanılır.
        """
        if not SELENIUM_AVAILABLE: return ""

        if not self.driver and not self._setup_driver():
            return ""
        
        try:
            self.log(f"[JS-HEADLESS] Gerçek tarayıcı ile sayfa yükleniyor: {url}", "INFO")
            self.driver.get(url)
            
            # Sayfa kaynağını döndür (JS çalıştıktan sonraki DOM hali)
            return self.driver.page_source
            
        except TimeoutException:
            self.log("[JS-HEADLESS] Sayfa yükleme zaman aşımı (30s). Kısmi DOM ile devam ediliyor.", "WARNING")
            return self.driver.page_source if self.driver else ""
        except WebDriverException as e:
            self.log(f"[JS-HEADLESS] WebDriver Hatası (Fetch): {e}", "CRITICAL")
            return ""
        except Exception as e:
            self.log(f"[JS-HEADLESS] Beklenmedik Fetch Hatası: {e}", "CRITICAL")
            return ""