// path: synara_ozellikler.md

SYNARA AI SECURITY // ADVANCED SECURITY INTELLIGENCE CORE

"Biz sadece kod yazmıyoruz, dijital güvenlik tarihini yazıyoruz." - Mesteg Teknoloji

Synara Security, modern web uygulamalarındaki güvenlik açıklarını tespit etmek, analiz etmek ve raporlamak için tasarlanmış, yapay zeka destekli ve modüler bir Ofansif Güvenlik Platformudur.

🚀 MOTOR MİMARİSİ VE GENEL ÖZELLİKLER

Özellik

Tanım

Fayda

Hibrit Tarama Motoru

Python tabanlı Asenkron Motor (Aiohttp) ve Harici Araç Entegrasyonu (Nuclei) birleşimi.

Yüksek hızda binlerce eş zamanlı istek gönderirken, üçüncü parti araçların derinlemesini analiz yeteneklerini kullanır.

Akıllı Puanlama (SRP)

CVSS v3.1 standartlarına göre ağırlıklandırılmış ve kalibre edilmiş Risk Puanlaması (SRP - Synara Reality Point).

Zafiyetlerin işletme üzerindeki gerçek etkisini yansıtan, güvenilir ve objektif risk skorlaması sağlar.

AI Analist (Bilinç)

Gemini AI entegrasyonu ile tarama sonuçlarını yorumlar, kritik bulgular için hacker bakış açısıyla aksiyon planı sunar.

Manuel analiz ihtiyacını azaltır ve riskleri önceliklendirir.

Canlı Exploit Simülasyonu

Tespit edilen kritik zafiyetler (SQLi, LFI, IDOR, XSS) için GUI üzerinden tek tıkla simülasyon/doğrulama yeteneği.

Yanlış pozitif oranını sıfırlar ve zafiyetin gerçek sömürülebilirliğini (exploitability) kanıtlar.

Dinamik Aksiyon (Selenium)

Headless Chrome (Selenium) kullanarak login gerektiren siteler için otomatik form doldurma ve navigasyon senaryolarını yürütebilir.

Kompleks SPA'lar (Single Page Applications) ve oturum korumalı alanların taranmasını sağlar.

Tamamen Bağımsız Dağıtım

PyInstaller ile tek bir çalıştırılabilir (Windows'ta .exe, macOS'ta .app) dosya olarak paketlenir.

Kolay taşınabilirlik ve hedef sistemde Python bağımlılığı gerektirmeme.

🧠 MODÜL MİMARİSİ (CORE SCANNERS)

Synara, core/scanners/ altında 18'den fazla zafiyet modülüne sahiptir. Her modül, BaseScanner sınıfından türetilmiştir ve özelleştirilmiş bir görevi yerine getirir.

I. KEŞİF ve ZEKÂ MODÜLLERİ

Modül Adı

Kod Adı

Açıklama

Dahili Sistem Tarayıcı

INTERNAL_SCAN

Synara'nın kendi çekirdek dosyalarını (.sys, MANIFEST, engine.py gibi) tarar. Hardcoded sırlar veya sistem bütünlüğünü bozan konfigürasyonları arar.

WAF Dedektörü

WAF_DETECT

Hedef önünde Cloudflare, AWS WAF, ModSecurity vb. güvenlik duvarı olup olmadığını tespit eder ve Evasion Modu'nu tetikler.

Subdomain Keşfi

SUBDOMAIN

crt.sh ve yedek (fallback) kaynaklar üzerinden pasif alt alan adı keşfi yapar. Akıllı retry mekanizması içerir.

Parametre Keşfi

PRE_SCAN

HTML ve JS dosyalarını analiz ederek gizli, isimsiz veya düşük güvenilirlikli parametreleri bulur ve bu parametreleri diğer saldırı modüllerine iletir.

Port Tarayıcı

PORT_SCAN

Kritik servis portlarını (FTP, SSH, MySQL, RDP, Telnet vb.) tarar ve Banner Grabbing ile servis versiyonunu tespit eder. Çoklu port açığa çıkması durumunda SRP cezasını katlar.

Heuristic Motoru

HEURISTIC

HTTP yanıt gövdelerini analiz ederek yansıma (reflection) noktalarını tespit eder, XSS tarayıcısına bağlamsal bilgi sağlar ve sunucu teknoloji/hata ifşalarını bulur.

JS Endpoint Extractor

JS_ENDPOINT

JavaScript dosyalarını indirir ve içindeki API uç noktalarını (/api/v1/...) çıkarıp diğer API tarayıcılarına iletir.

Cloud Exploit (Cloudstorm)

CLOUD_EXPLOIT

AWS/GCP/Azure metadata servislerine yönelik SSRF zafiyetlerini ve hedefle ilişkili olası açık S3 bucket (depolama) tespiti yapar.

II. SALDIRI ve FUZZING MODÜLLERİ

Modül Adı

Kod Adı

Açıklama

SQLi Tarayıcı

SQLI

Time-Based (Dinamik Eşikli), Boolean-Based ve Error-Based SQL Enjeksiyon zafiyetlerini tarar. Kalibrasyon verisini kullanarak False Positive'i minimuma indirir.

XSS Tarayıcı

XSS

Reflected ve DOM-Based XSS zafiyetlerini tarar. Heuristic Motor'dan gelen bağlam bilgisiyle (Context-Aware) akıllı Polyglot payload'lar üretir.

RCE / SSRF Tarayıcı

RCE_SSRF

Sunucu tarafı istek sahteciliği (SSRF) ve Uzaktan Kod Çalıştırma (RCE) potansiyelini arar. SSRF tespiti için boyut/entropy değişim analizi kullanır.

LFI Tarayıcısı

LFI

Yerel dosya dahil etme (/etc/passwd, win.ini vb.) açıklarını arar ve çift kodlama (double-encoding) ile bypass tekniklerini dener.

IDOR Tarayıcısı

IDOR

Sayısal ID'leri manipüle ederek yetkisiz erişimi kontrol eder. SimHash ve Entropy analizi ile True/False yanıtlarını karşılaştırır.

Auth Bypass

AUTH_BYPASS

Admin panelleri, hassas dizinler ve API uç noktalarına yetkisiz erişimi dener. Ghost Mode ile 403/401 yanıtlarında IP Spoofing (X-Forwarded-For) ve Metot Fuzzing dener.

JSON API Fuzzing

JSON_API

REST API uç noktalarına JSON formatında payload'lar (XSS/SQLi) ile fuzzing uygular ve sunucu hata sızıntılarını tespit eder.

GraphQL Tarayıcı

GRAPHQL

GraphQL endpoint'lerini keşfeder, Introspection (Şema İfşası) kontrolü yapar ve Injection (SQLi/NoSQLi) dener.

🛠️ KURULUM ve GEREKSİNİMLER

Synara, kritik işlevler için harici araçlara ihtiyaç duyar.

Gereksinim

Rolü

Bulunması Gereken Yer

Nuclei

Geniş kapsamlı zafiyet taraması (Harici araç).

nuclei ikili dosyası sistem PATH'inde veya belirlenen yolda.

wkhtmltopdf

HTML raporlarını PDF formatına çevirme.

Manuel olarak kurulmalı (C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe).

Google Chrome

Dinamik tarama (DOM XSS) ve script yürütme.

Sistemde kurulu olmalı.

API Anahtarı

Yapay Zeka Analiz (Gemini) entegrasyonu.

Projenin kök dizinindeki .env.local dosyası içinde tanımlı olmalı (GEMINI_API_KEY).