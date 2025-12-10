# path: core/oob_listener.py

import threading
from typing import Dict, Set, Optional, List
import time

class OOBListener:
    """
    OOB (Out-of-Band) Sinyal Takip Modülü.
    RCE/SSRF modülü tarafından gönderilen token'ları kaydeder ve
    manuel doğrulama için geri dönen sinyalleri (hit) simüle eder.

    BBH stratejisi için kritik: Blind zafiyetleri kanıtlamanın anahtarıdır.
    """

    # Gönderilen token'lar (set hız ve benzersizlik için ideal)
    _sent_tokens: Set[str]
    # Başarılı dönüş (hit) yapan token'lar
    _hit_tokens: Set[str]
    _lock: threading.Lock

    def __init__(self, logger):
        self.log = logger
        self._sent_tokens = set()
        self._hit_tokens = set()
        self._lock = threading.Lock()
        self.log("[OOB LISTENER] Sinyal Takip Sistemi Aktif. Giden token'lar izleniyor...", "INFO")

    def add_token(self, token: str):
        """
        RCE/SSRF tarayıcıları tarafından gönderilen bir OOB token'ı kaydeder.
        """
        if not token:
            return
            
        with self._lock:
            self._sent_tokens.add(token)

    def check_token_status(self, token: str) -> str:
        """
        Bir token'ın durumunu döndürür: 'HIT', 'SENT', 'UNKNOWN'.
        """
        if not token:
            return "UNKNOWN"
            
        with self._lock:
            if token in self._hit_tokens:
                return "HIT"
            if token in self._sent_tokens:
                return "SENT"
            return "UNKNOWN"

    def mark_as_hit(self, token: str) -> bool:
        """
        Bir token'ın başarılı bir şekilde geri döndüğünü (HIT) işaretler.
        (Gerçek bir OOB sunucusundan gelen yanıtı simüle eder.)
        """
        if not token:
            return False

        with self._lock:
            if token in self._sent_tokens and token not in self._hit_tokens:
                self._hit_tokens.add(token)
                self.log(f"[OOB LISTENER] KRİTİK BAŞARI: Token '{token}' geri döndü! Blind zafiyet kanıtlandı.", "CRITICAL")
                return True
            
        return False

    def get_hit_count(self) -> int:
        """Başarılı olan OOB sinyal sayısını döndürür."""
        with self._lock:
            return len(self._hit_tokens)

    def get_sent_count(self) -> int:
        """Gönderilen OOB sinyal sayısını döndürür."""
        with self._lock:
            return len(self._sent_tokens)
            
    def clear_all(self):
        """Tüm takip listelerini temizler."""
        with self._lock:
            self._sent_tokens.clear()
            self._hit_tokens.clear()
            self.log("[OOB LISTENER] Takip listesi temizlendi.", "INFO")