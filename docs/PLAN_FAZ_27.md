PLAN_FAZ_27: SQLite ve ORM Kalıcılık Katmanı Entegrasyonu

Durum: Hazırlık Aşamasında
Hedef: RAM tabanlı veri saklama modelinden, ilişkisel veritabanı (SQLite) ve ORM (SQLAlchemy) yapısına geçiş.
Öncelik: Yüksek (Veri kaybını önleme ve analitik altyapı)

1. MİMARİ DEĞİŞİKLİK ÖZETİ

Mevcut sistemde tarama sonuçları scan_results listesinde (RAM) tutulmakta ve işlem sonunda JSON'a dökülmektedir. Bu yapı; uzun süreli taramalarda bellek şişmesine ve olası bir çökmede veri kaybına yol açmaktadır.

Yeni Yapı:

Veritabanı: SQLite (Hafif, dosya tabanlı, kurulum gerektirmez).

ORM: SQLAlchemy (Python standartı, ileride PostgreSQL'e geçişi kolaylaştırır).

Akış: Tarayıcılar buldukları zafiyetleri anlık olarak DB'ye yazar. Raporlayıcı DB'den okur.

2. ETKİLENECEK DOSYALAR VE YENİ MODÜLLER

A. Yeni Oluşturulacak Dosyalar

core/database.py

Veritabanı bağlantısı (engine), oturum yönetimi (SessionLocal) ve temel ayarlar.

core/models.py

Veritabanı tablolarının (Entities) tanımı.

Tablolar:

Scans: Tarama oturumu bilgileri (ID, Hedef, Başlangıç/Bitiş Zamanı, Durum).

Vulnerabilities: Tespit edilen zafiyetler (Tip, Şiddet, URL, Payload, Kanıt).

Logs: Sistem loglarının kalıcı tutulması (Opsiyonel, şimdilik dosya sisteminde kalabilir ama DB yapısı hazırlanacak).

B. Değiştirilecek Dosyalar

requirements_server.txt / requirements_full.txt

SQLAlchemy kütüphanesinin eklenmesi.

core/report_manager.py

add_vulnerability metodunun listeye eklemek yerine DB'ye insert yapacak şekilde güncellenmesi.

save_report metodunun veriyi DB'den çekecek şekilde revize edilmesi.

core/engine.py (veya main.py)

Uygulama başlangıcında init_db() çağrısının yapılması.

Tarama başlangıcında yeni bir Scan kaydı oluşturulması.

3. UYGULAMA ADIMLARI

ADIM 1: Bağımlılıkların Eklenmesi

requirements_server.txt dosyasına SQLAlchemy eklenecek.

ADIM 2: Veritabanı Altyapısı (Core)

core/database.py oluşturulacak. SQLite bağlantı zinciri (sqlite:///./pars_data.db) ayarlanacak.

core/models.py oluşturulacak. Base sınıfından türetilen modeller yazılacak.

ADIM 3: ReportManager Entegrasyonu (Migration)

ReportManager sınıfı, bellekteki listeler yerine Session nesnesini kullanacak hale getirilecek.

Mevcut JSON çıktı formatı korunacak (dışa aktarım için), ancak veri kaynağı DB olacak.

ADIM 4: Engine Entegrasyonu

ScanEngine başlatıldığında DB'de bir scan_id oluşturacak.

Tüm modüller bulguları bu scan_id ile ilişkilendirecek.

4. RİSK VE GÜVENLİK ANALİZİ

Risk: Eşzamanlı yazma (Concurrency) sorunları (SQLite kilitlenmesi).

Çözüm: SQLAlchemy scoped_session veya tekil ReportManager üzerinden yazma işlemi. FastAPI tarafında check_same_thread=False ayarı.

Risk: Performans düşüşü.

Çözüm: SQLite WAL (Write-Ahead Logging) modu aktif edilecek. Toplu yazma (batch commit) gerekirse uygulanacak.

Güvenlik: SQL Injection.

Çözüm: ORM kullanımı zaten SQLi koruması sağlar. Ham SQL sorgularından kaçınılacak.

5. GELECEK VİZYONU (Faz 46+ Hazırlığı)

Bu yapı kurulduğunda;

Dashboard: Geçmiş taramaları listeleyebilecek.

İstatistik: "En çok bulunan zafiyet", "Ortalama tarama süresi" gibi veriler sorgulanabilecek.

Resume: Yarım kalan taramalar kaldığı yerden