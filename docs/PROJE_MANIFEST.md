MESTEG TEKNOLOJİ | SYNARA AI SECURITY (PARS) - PROJE MANİFESTİ

PROJE KİMLİĞİ

Kod Adı: PARS (Enterprise Edition)
Tür: Cloud-Native Ofansif Güvenlik Platformu (SaaS)
Platform: Backend (Python FastAPI) + Frontend (CustomTkinter / Web Dashboard)
Hedef: 7/24 Kesintisiz Zafiyet Analizi ve API Tabanlı Yönetim.

MİMARİ (DÖNÜŞTÜRÜLDÜ)

Eski Mimari: Monolitik Masaüstü Uygulaması.
Yeni Mimari (v2.0): Dağıtık Mikroservis Yapısı.

[İSTEMCİLER] <---> [API GATEWAY (FastAPI)] <---> [WORKER (Synara Engine)]
^                       |                           |
|                       v                           v
(GUI/Web)              [DATABASE]                 [TARGET]

API Layer: api_server.py - Dış dünyadan gelen emirleri karşılar.

Core Layer: core/ - İş mantığını ve tarama modüllerini barındırır.

Headless Mode: Motor, GUI olmadan çalışabilir ve logları veritabanına/dosyaya yazar.

GÜVENLİK KURALLARI

API erişimi "API Key" veya "JWT Token" ile korunmalıdır.

Sunucu tarafında root yetkisiyle tarama çalıştırılmaz.

WAF Evasion ve Proxy Yönetimi sunucu tarafında merkezi olarak yönetilir.

VERİ YAPILARI

Scan Object: Her tarama benzersiz bir scan_id (UUID) ile takip edilir.

Result Stream: Loglar ve bulgular stream (SSE/WebSocket) veya polling ile istemciye iletilir.

Persistence: Raporlar sunucuda /reports dizininde veya S3 bucket'ta saklanır.

TEKNİK ÇEKİRDEK (SUNUCU)

Dil: Python 3.10+

Framework: FastAPI (Yüksek performanslı Asenkron API)

Server: Uvicorn / Gunicorn

Engine: Synara Async Engine (Mevcut yapı)

Queue: Background Tasks (İleri fazda Redis/Celery)

DOSYA YAPISI HEDEFİ

.
├── api_server.py (YENİ: Sunucu Giriş Noktası)
├── core/
│   ├── engine.py (Headless Destekli)
│   └── ... (Mevcut Modüller)
├── reports/
├── Dockerfile (Gelecek Faz)
└── gui_client/ (Eski gui_main.py buraya taşınacak - İstemci)

YOL_HARİTASI / ROADMAP

[2025-12-10] MİMARİ DÖNÜŞÜM BAŞLATILDI (Desktop -> Server).

FastAPI entegrasyonu.

Engine'in GUI bağımlılığının kaldırılması.

[Hedef] Docker Konteynerizasyonu.
[Hedef] PostgreSQL Veritabanı Entegrasyonu.