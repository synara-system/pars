# path: PARS Pentest Autonomous Recon System/core/models.py

from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, JSON, Text
from sqlalchemy.orm import relationship
from datetime import datetime
import json
import uuid

# core/database.py dosyasından Base'i içe aktar
from .database import Base 

# Benzersiz tarama kimlikleri (UUID) oluşturmak için.
def generate_uuid():
    """Benzersiz bir UUID (v4) oluşturur."""
    return str(uuid.uuid4())

# --- Veritabanı Modelleri ---

class Scan(Base):
    """
    Her bir pentest tarama oturumunu temsil eden model.
    """
    __tablename__ = "scans"

    # Birincil Anahtar
    id = Column(String, primary_key=True, default=generate_uuid, index=True)
    
    # Tarama Bilgileri
    target_url = Column(String, index=True, nullable=False)
    target_ip = Column(String, nullable=True)
    status = Column(String, default="INITIALIZING", nullable=False) # Örn: INITIALIZING, RUNNING, COMPLETED, FAILED
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime, nullable=True)
    
    # Rapor ve Yapılandırma
    config = Column(JSON, nullable=True) # JSON olarak saklanacak tarama konfigürasyonu
    
    # İlişkiler: Bir taramanın birden çok zafiyeti olabilir.
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Scan(id='{self.id}', target='{self.target_url}', status='{self.status}')>"


class Vulnerability(Base):
    """
    Tespit edilen zafiyet bulgularını temsil eden model.
    """
    __tablename__ = "vulnerabilities"

    # Birincil Anahtar
    id = Column(Integer, primary_key=True, index=True)
    
    # İlişki Anahtarı: Hangi taramaya ait olduğunu belirtir.
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)
    
    # Zafiyet Bilgileri
    vulnerability_type = Column(String, index=True, nullable=False) # Örn: XSS, SQLi, IDOR
    severity = Column(String, nullable=False) # Örn: Critical, High, Medium, Low
    url = Column(String, nullable=False)
    
    # Teknik Detaylar
    parameter = Column(String, nullable=True) # Hangi parametrenin etkilendiği
    payload = Column(Text, nullable=True) # Kullanılan payload (eğer varsa)
    proof = Column(Text, nullable=True) # Kanıt (HTTP yanıt başlıkları/gövdesi, vb.)
    request_data = Column(Text, nullable=True) # Saldırı isteği (Raw HTTP, debug için)
    
    # İlişkiler: Bağlı olduğu tarama oturumu.
    scan = relationship("Scan", back_populates="vulnerabilities")

    def __repr__(self):
        return f"<Vulnerability(type='{self.vulnerability_type}', url='{self.url}', severity='{self.severity}')>"
    
    @property
    def to_dict(self):
        """Rapor yöneticisi ile uyumlu olması için dict formatında çıktı verir."""
        return {
            "type": self.vulnerability_type,
            "severity": self.severity,
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "proof": self.proof,
            "request_data": self.request_data,
        }