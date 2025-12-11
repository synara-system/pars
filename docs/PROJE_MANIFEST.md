// path: docs/PROJE_MANIFEST.md

MESTEG TEKNOLOJİ | SYNARA AI SECURITY (PARS) - PROJE MANİFESTİ

PROJE KİMLİĞİ

Kod Adı: PARS (Enterprise Edition)
Tür: Cloud-Native Ofansif Güvenlik Platformu (SaaS)
Platform: Backend (Python FastAPI) + Frontend (Web Dashboard / Debug Client)
Hedef: 7/24 Kesintisiz Zafiyet Analizi ve API Tabanlı Yönetim.

1. MİMARİ

Yeni Mimari (v5.1): Dağıtık Mikroservis Yapısı.
İstemciler: [WEB DASHBOARD] <---> [API GATEWAY (FastAPI)] <---> [WORKER (Synara Engine)]

Roller:

API Layer (api_server.py): Dış dünyadan gelen emirleri karşılar.

Core Layer (core/): İş mantığını ve tarama modüllerini barındırır.

Web Frontend (web_dashboard.html): Nihai kullanıcı arayüzü (Müşteri Akışı).

Debug Client (Test/gui_main.py): RESMİ GELİŞTİRİCİ/DEBUG ARACI olarak kullanılır.

2. GÜVENLİK KURALLARI

API erişimi "API Key" veya "JWT Token" ile korunmalıdır.

Sunucu tarafında root yetkisiyle tarama çalıştırılmaz.

WAF Evasion ve Proxy Yönetimi sunucu tarafında merkezi olarak yönetilir.

Çekirdek Kural: Debug Client (gui_main.py) kullanıldığında, tüm AI Analiz ve Ağ istekleri (API Server'a gerek kalmadan) motorun Localhost'ta doğrudan çalışmasıyla sağlanır.

3. VERİ YAPILARI

Scan Object: Her tarama benzersiz bir scan_id (UUID) ile takip edilir.

Result Stream: Loglar ve bulgular stream (SSE/WebSocket) veya polling ile istemciye iletilir.

Persistence: Raporlar sunucuda /reports dizininde veya S3 bucket'ta saklanır.

4. DOSYA YAPISI HEDEFİ

Desktop/Cloud kopyaları temizlendi. Geliştirici ve Müşteri akışları ayrıldı.
.
├── api_server.py (API Sunucusu)
├── core/ (Motor Kodları)
├── reports/ (Raporlar)
├── Test/
│   └── gui_main.py (RESMİ DEBUG ARACI)
├── web_dashboard.html (MÜŞTERİ ARABİRİMİ)
├── debug_launcher.py (Geliştirici/Debug Başlatıcısı)
└── main.py (Müşteri Başlatıcısı)

5. YOL_HARİTASI / ROADMAP

[2025-12-10] MİMARİ TEMİZLİK (V5.1) TAMAMLANDI.
Desktop/Cloud arayüz karışıklığı çözüldü. Odak tamamen Web/API üzerine kaydırıldı. Desktop GUI artık sadece geliştirici aracıdır.

[Hedef] Docker Konteynerizasyonu.
[Hedef] PostgreSQL Veritabanı Entegrasyonu.
[Hedef] Nuclei Entegrasyonunun tam işlevselliği.