Reçete: Minimum Bozma ile SaaS Mimari Geçişi
Hedef: Mevcut Python kodunu (engine + scanners) bozmadan, queue tabanlı sisteme geç. Celery + Redis + FastAPI (mevcut backend'in) kullan – en uyumlu, en hızlı. Sunucu yükü: 20 kullanıcı aynı anda tarama yapsa bile queue sıraya koyar, worker'lar dağıtır → ezilme yok.
1. Önerilen Mimari (Celery + Redis + FastAPI)

Neden? Mevcut FastAPI'nı bozmadan entegre olur. Python tabanlı, öğrenmesi kolay (2-3 gün). 29 modülü etkilemez – engine.py'yi task yaparız.
Yapı:
FastAPI (API): Kullanıcı /scan isteği alır, queue'ya atar (task ID döner).
Celery (Queue): İstekleri sıraya koyar (Redis depolar).
Redis (Broker): Hafif veritabanı (queue + result saklama).
Worker'lar: Tarama işlerini koşar (Docker'da scale edilebilir).

Yasal Koruma: SAAS planlarında agresif modülleri filtrele (config/saas_limits.py'de). FULL_SCAN/SAAS_CORE sadece senin admin erişimine açık.

2. Dosya Sistemi Yapılandırması (Minimum Bozma)

Mevcut Klasörler Aynı Kalır: scanners/, core/ bozulmaz.
Yeni Eklemeler:
tasks/ klasörü: Tarama task'ları buraya (scan_task.py).
config/saas_limits.py: Plan bazlı modül kısıtlaması.
celery.py: Root'ta Celery app tanımı.
Dockerfile + docker-compose.yml: Worker scale için.

Toplam Değişim: 3-4 yeni dosya, engine.py'de 20-30 satır güncelleme.

3. Adım Adım Uygulama (Notlarına Kayıt Et)
Zorluk: Orta (Python biliyorsun, docs bol). Zaman: 3-4 hafta (yalnızsan). Maliyet: Başta $0 (local test), Render'da $50/ay (Redis + worker).

Hafta 1: Queue Kurulumu (Kolay, 3-5 gün)
pip install celery redis.
celery.py: App oluştur.
tasks/scan_task.py: engine.start_scan'ı task yap.
Redis local kur (docker run redis).

Hafta 2: FastAPI Entegrasyonu (Orta, 5-7 gün)
main.py'de /scan endpoint: task.delay(url, profile).
Sonuç: Celery result ile webhook/e-posta.

Hafta 3: Worker Scaling + Test (Orta, 1 hafta)
Dockerize: Dockerfile ile worker CMD celery worker.
Render deploy: Background Worker + Redis add-on.
Test: 20 paralel tarama (locust ile) – yük dağılımı kontrol et.

Hafta 4: Yasal Kısıtlama + Optimizasyon (Kolay, 3-5 gün)
saas_limits.py: Plan'a göre modül filtrele.
29 modülü test et – agresif olanları (RCE) SAAS_CORE'a kilitle.


4. 20 Kullanıcı Yükü?

Rahat Kaldırır: Queue ile 20 tarama sıraya girer, worker'lar (4-8) paralel koşar. CPU/RAM spike'ı yok.
Zorlama? Başta test fazı zorlar (bug avı), ama fiziksel deneyiminle hızlı geçersin. En kötü 1 ay gecikme.