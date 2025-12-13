# path: core/oob_listener.py

import threading
import time
import uuid
import random
from typing import Dict, Set, Optional, List, Callable, Any
from dataclasses import dataclass, field

@dataclass
class OOBInteraction:
    """Bir OOB etkileşiminin detaylarını tutar."""
    token: str
    protocol: str  # DNS, HTTP, SMTP
    timestamp: float
    source_ip: str = "0.0.0.0"
    data: str = ""
    module: str = "UNKNOWN"

class OOBListener:
    """
    [AR-GE v3.1 - THE SIGNAL HUNTER & LEGACY SUPPORT]
    Gelişmiş Out-of-Band (Bant Dışı) Sinyal Yakalama ve Yönetim Modülü.
    
    Özellikler:
    - Protokol Bazlı Token Üretimi (DNS/HTTP ayrımı)
    - Gerçek Zamanlı Callback Tetikleme (Asenkron bildirim)
    - Thread-Safe Token Havuzu
    - Interactsh/Burp Collaborator mimarisine uygun altyapı
    - Geriye Dönük Uyumluluk (Legacy Support for RCE/SSRF)
    """

    # Desteklenen Protokoller
    PROTOCOL_DNS = "DNS"
    PROTOCOL_HTTP = "HTTP"
    PROTOCOL_SMTP = "SMTP"

    def __init__(self, logger):
        self.log = logger
        
        # Token veritabanı: {token_str: {metadata}}
        self._registered_tokens: Dict[str, Dict[str, Any]] = {}
        
        # Yakalanan etkileşimler: {token_str: [OOBInteraction]}
        self._captured_interactions: Dict[str, List[OOBInteraction]] = {}
        
        # Callback fonksiyonları: {token_str: callback_function}
        self._callbacks: Dict[str, Callable] = {}
        
        self._lock = threading.Lock()
        self._is_running = True
        
        # Simülasyon için sanal "dış dünya" gecikmesi
        self._simulation_delay_range = (0.5, 2.0)
        
        self.log("[OOB LISTENER] Sinyal Avcısı (Signal Hunter v3.1) Aktif. Frekanslar dinleniyor...", "SUCCESS")

    def generate_token(self, module_name: str = "GENERIC", protocol: str = "HTTP", callback: Optional[Callable] = None) -> str:
        """
        Benzersiz bir OOB token (canary) üretir ve sisteme kaydeder.
        """
        token = uuid.uuid4().hex[:12]
        
        with self._lock:
            self._registered_tokens[token] = {
                "module": module_name,
                "protocol": protocol,
                "created_at": time.time(),
                "status": "WAITING"
            }
            
            if callback:
                self._callbacks[token] = callback
                
        return token

    # --- UYUMLULUK KATMANI (LEGACY SUPPORT) ---
    def add_token(self, token: str):
        """
        [LEGACY] RCE/SSRF modülleri tarafından manuel üretilen token'ları kaydeder.
        """
        if not token:
            return
        with self._lock:
            if token not in self._registered_tokens:
                self._registered_tokens[token] = {
                    "module": "LEGACY_SCANNER",
                    "protocol": self.PROTOCOL_HTTP,
                    "created_at": time.time(),
                    "status": "WAITING"
                }
                # self.log(f"[OOB LISTENER] Manuel token kaydedildi: {token}", "INFO")

    def mark_as_hit(self, token: str) -> bool:
        """
        [LEGACY] Bir token'ı hit olarak işaretler. register_hit'e yönlendirir.
        """
        return self.register_hit(token, source_ip="LEGACY_SOURCE", data="Manual Hit Marking")
    # ------------------------------------------

    def get_payload_address(self, token: str, domain: str = "pars-oob.com") -> str:
        """
        Token için kullanılabilecek tam adresi döndürür.
        """
        meta = self._registered_tokens.get(token)
        if not meta:
            # Token yoksa bile varsayılan bir HTTP adresi dön
            return f"http://{domain}/{token}"
            
        protocol = meta["protocol"]
        
        if protocol == self.PROTOCOL_DNS:
            return f"{token}.{domain}"
        elif protocol == self.PROTOCOL_HTTP:
            return f"http://{domain}/{token}"
        else:
            return f"{token}.{domain}"

    def register_hit(self, token: str, source_ip: str = "Simulated", data: str = "") -> bool:
        """
        Dış dünyadan bir sinyal (hit) geldiğinde bu metod çağrılır.
        """
        with self._lock:
            if token not in self._registered_tokens:
                return False
            
            meta = self._registered_tokens[token]
            
            # Etkileşimi kaydet
            interaction = OOBInteraction(
                token=token,
                protocol=meta["protocol"],
                timestamp=time.time(),
                source_ip=source_ip,
                data=data,
                module=meta["module"]
            )
            
            if token not in self._captured_interactions:
                self._captured_interactions[token] = []
            
            self._captured_interactions[token].append(interaction)
            self._registered_tokens[token]["status"] = "HIT"
            
            module_name = meta["module"]

        # Loglama
        self.log(f"[OOB LISTENER] KRİTİK SİNYAL: {module_name} modülü için token '{token}' yakalandı! ({source_ip})", "CRITICAL")
        
        # Varsa Callback'i tetikle
        if token in self._callbacks:
            try:
                self._callbacks[token](token, interaction)
            except Exception as e:
                self.log(f"[OOB LISTENER] Callback Hatası: {e}", "ERROR")
                
        return True

    def check_token_status(self, token: str) -> str:
        """Token durumunu sorgular: WAITING, HIT, UNKNOWN."""
        with self._lock:
            if token not in self._registered_tokens:
                return "UNKNOWN"
            # HIT durumu interaction varsa döner
            if token in self._captured_interactions and self._captured_interactions[token]:
                return "HIT"
            return self._registered_tokens[token]["status"]

    def get_interactions(self, token: str) -> List[OOBInteraction]:
        """Bir token'a ait tüm etkileşimleri döndürür."""
        with self._lock:
            return self._captured_interactions.get(token, [])

    # --- SİMÜLASYON METOTLARI ---

    def simulate_hit(self, token: str, delay: float = 0.0):
        """
        Test amaçlı manuel hit simülasyonu.
        """
        def _delayed_hit():
            if delay > 0:
                time.sleep(delay)
            self.register_hit(token, source_ip="127.0.0.1 (SIM)", data="Simulated OOB Hit")

        threading.Thread(target=_delayed_hit, daemon=True).start()

    def clear_all(self):
        """Hafızayı temizler."""
        with self._lock:
            self._registered_tokens.clear()
            self._captured_interactions.clear()
            self._callbacks.clear()
            self.log("[OOB LISTENER] Bellek temizlendi. Yeni av için hazır.", "INFO")