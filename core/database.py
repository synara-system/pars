# path: PARS Pentest Autonomous Recon System/core/database.py

import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# Logging konfigürasyonu
logger = logging.getLogger(__name__)

# Veritabanı dosyası yolu. Bu, projenin kök dizininde 'pars_data.db' olarak oluşturulacak.
DATABASE_URL = "sqlite:///./pars_data.db"

# SQLAlchemy motorunu oluşturma. 
# check_same_thread=False, SQLite'ın asenkron FastAPI ortamında çalışması için gereklidir.
# Ancak, production ortamında (PostgreSQL vb.) bu ayar KESİNLİKLE kaldırılmalıdır.
# ParS'ın şu anki yerel (FastAPI/SQLite) yapısı için uygundur.
engine = create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False}
)

# Her veritabanı işlemi için bir oturum (Session) oluşturacak fabrika.
# autocommit=False: Otomatik kaydetmeyi devre dışı bırakır. İşlemlerin manuel commit edilmesi gerekir.
# autoflush=False: Otomatik boşaltmayı devre dışı bırakır. Performans için önemlidir.
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Veritabanı modellerinin (Tabloların) miras alacağı temel sınıf.
Base = declarative_base()

def get_db():
    """
    FastAPI Dependency Injection için veritabanı oturumu sağlayan bir generator.
    Oturumu sağlar ve iş bittiğinde otomatik olarak kapatır.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
def init_db():
    """
    Veritabanı tablolarını (Base'den miras alan) oluşturan fonksiyon.
    Uygulama başlangıcında (engine.py veya main.py içinde) çağrılmalıdır.
    """
    try:
        # Modellerin yüklenmesi için dinamik içe aktarma yerine, modellerin zaten 
        # Base tarafından içe aktarılmış olduğunu varsayıyoruz (Uygulama başlatılırken).
        # Alternatif olarak:
        from . import models
        
        # Base.metadata'daki tüm modelleri motor (engine) üzerinde oluştur.
        Base.metadata.create_all(bind=engine)
        logger.info("Veritabanı tabloları başarıyla oluşturuldu veya zaten mevcut.")
    except Exception as e:
        logger.error(f"Veritabanı başlatılırken hata oluştu: {e}")