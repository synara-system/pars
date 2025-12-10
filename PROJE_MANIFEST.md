MESTEG TEKNOLOJİ | SYNARA AI SECURITY (PARS) - PROJE MANİFESTİ

PROJE KİMLİĞİ

Kod Adı: PARS = Pentest Autonomous Recon System

Tür: Ofansif Güvenlik ve Zafiyet Analiz Aracı

Platform: Desktop (Python + CustomTkinter)

Hedef: Web uygulamalarındaki güvenlik açıklarını (XSS, SQLi, LFI, vb.) tespit edip raporlamak.

1. MİMARİ

Synara Core Architecture (PARS): Modüler, asenkron motor tasarımıdır. Tüm modüller BaseScanner soyut sınıfından türetilmiştir. Hata yönetimi, Threading ve Asyncio ile ayrılmıştır.

2. GÜVENLİK KURALLARI

Synara, korunan alan adları listesini (.env.local) kontrol eder. CORE dosyalarında hardcoded secret kontrolü yapar. WAF'ları tespit ettiğinde hızı otomatik olarak düşürür ve evasion modunu aktifleştirir.

3. VERİ YAPILARI

Tüm keşif verileri (Endpointler, Parametreler), fuzzing modülleri arasında 'discovered_params' set'i aracılığıyla paylaşılır. Sonuçlar (Results) listesi, SRP (Synara Risk Puanı) ağırlıklandırmasını kullanır.

TEKNİK ÇEKİRDEK

Dil: Python 3.10+

GUI: CustomTkinter (Modern Dark UI)

Core: Modular Plugin System (Her zafiyet tipi ayrı modül olacak)

AsyncIO + Aiohttp (Yüksek hızlı asenkron tarama)

Veri: JSON tabanlı yerel loglama.

Raporlama: Jinja2 Template Engine (Dinamik HTML).

YENİ BAĞIMLILIKLAR (FAZ 8)

Selenium WebDriver (Gerçek Headless Tarama için)

Webdriver Manager (Sürücü yönetimi ve kurulum kolaylığı için)

DOSYA YAPISI HEDEFİ

.
├── main.py (Entry Point)
├── synara_gui.py (Arayüz)
├── core/
│   ├── engine.py (Tarama Motoru)
│   ├── reporter.py (Raporlama)
│   ├── dynamic_scanner.py (YENİ: Dinamik Tarama Çekirdeği)
│   └── scanners/ (Zafiyet Modülleri)
│       ├── xss.py
│       ├── sqli.py
│       ├── cloud_exploit.py (YENİ)
│       └── subdomain_scanner.py (GÜNCELLENDİ)
└── reports/ (Çıktılar)

DİNAMİK TARAMA MAPPING

Bu haritalama, core/dynamic_script_manager.py tarafından okunur ve
hedef URL'nin alan adına göre (örneğin, "programevi.com") hangi
hazır scriptin (login, setup vb.) kullanılacağını belirler.

DYNAMIC_SCRIPT_MAPPING = [
{
"target_url_fragment": "test.local",
"script_name": "GLOBAL_COMMON_LOGIN"
}
]

YOL_HARİTASI / ROADMAP

[2025-12-08] Cloud Exploit Modülü (Cloudstorm) -> AWS/GCP/Azure metadata ve S3 bucket tarayıcısı entegre edildi.

[2025-12-08] Subdomain Smart Retry & Fallback -> crt.sh timeout durumunda otomatik yedek kaynak ve retry mekanizması eklendi.

Sonraki Fikir: Rapor Görselli