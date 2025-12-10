// path: docs/PROJECT_ROADMAP.md

SYNARA AI - AR-GE YOL HARİTASI

FAZ 1: TEMEL MİMARİ DÖNÜŞÜMÜ (Refactoring)
[X] synara_core.py dosyasının parçalanarak modüler yapıya geçilmesi.
[X] Tarama motorunun "Plugin" tabanlı hale getirilmesi.
[X] Loglama altyapısının GUI ile tam senkronize edilmesi.

FAZ 2: PERFORMANS VE ASENKRON YAPI
[X] requests kütüphanesinin aiohttp ile değiştirilmesi.
[X] Tarama hızının %300 artırılması (Concurrency).
[X] GUI'de "Canlı İlerleme Çubuğu" (Determinate Progress Bar).

FAZ 3: ZEKÂ KATMANI (AI Integration)
[X] Heuristic Analysis: HTTP yanıtlarının yapısına göre zafiyet tahmini.
[X] Payload Fuzzing: Sabit liste yerine dinamik payload üretimi.
[X] Yanlış Pozitif (False Positive) eleme algoritması.

FAZ 4: RAPORLAMA VE UX
[X] Jinja2 ile profesyonel HTML rapor şablonu.
[X] PDF çıktı desteği.
[X] Tarama geçmişi ve karşılaştırmalı analiz.

FAZ 5: GÖRSEL MİMARİ VE CANLI UX (V4.0 Yolu)
[X] Görsel Temel Atma: CustomTkinter içindeki temaları, Liquid Glass/Aero stili simulasyonu için mat ve şeffaf renk paletlerine dönüştürme.
[X] Gelişmiş Terminal: RichConsole widget'ını, gerçek konsol hissi için Liquid-Glass benzeri şeffaf bir çerçeve ile sarmalama.
[X] Canlı Rapor Karşılaştırması (UX): Karşılaştırma penceresindeki ham skor farklarını, kullanıcının kolayca anlayabileceği küçük grafikler ve renk kodlu uyarı kartları ile değiştirme.
[X] SQL Injection Tarayıcısı (Kapsam Genişletme): Yeni bir sqli.py modülü ekleyerek Fuzzing altyapısını SQL zafiyetlerine taşıma.
[X] UX Düzeltmesi: Rapor dosya adlarının, taranan hedef URL'ye göre dinamikleştirilmesi.

FAZ 6: VERİ ZEKASI VE İLERİ REFACTORING (V5.0/V6.0 Yolu)
[X] Yanlış Pozitif Düzeltme (Heuristic İyileştirme): HeuristicScanner'a sunucu yazılımı ifşasını (X-Powered-By) sadece INFO olarak değil, risk seviyesini azaltarak (örneğin: self._calculate_score_deduction("INFO") // 2) WARNING seviyesine düşürerek ekleme.
[X] LFI Tarayıcısı (Kapsam Genişletme): Yeni bir lfi.py modülü ekleyerek Local File Inclusion zafiyetlerini test etme.
[X] Tarama Hızı Metriği: SynaraReporter'da tarama süresini, toplam istek sayısına bölerek "Ortalama Yanıt Süresi (ms)" gibi bir performans metriği ekleme.
[X] Otomatik Güncelleme Mekanizması: Uygulama başlatıldığında, yeni modüller/payload'lar olup olmadığını kontrol eden bir sistem simülasyonu ekleme.
[X] Auth Bypass Tarayıcısı: Yeni bir auth_bypass.py modülü eklenerek, yaygın yönetim dizinlerine ve bypass tekniklerine karşı test yapılması.
[X] IDOR Tarayıcısı: Parametreler arası ilişkileri (örneğin user_id=1 yerine user_id=2 denemesi) test etmek için yeni bir idor.py modülü.
[X] Zayıf Oturum Yönetimi Analizi: Güvenlik başlıklarının (Set-Cookie) HttpOnly veya Secure bayraklarını kontrol etme.
[X] Gelişmiş Parametre Keşfi: Yalnızca URL sorgu parametrelerini değil, JavaScript veya HTML formları içindeki gizli/bilinmeyen girdi noktalarını keşfetmek için bir ön-tarama (Pre-Scan) modülü.
[X] SSRF/RCE Tarayıcısı (Kritik Genişletme): Sunucu tarafı istek sahteciliği (SSRF) ve Uzaktan Kod Çalıştırma (RCE) potansiyeli için yeni bir rce_ssrf.py modülü.

FAZ 7: DERİN MİMARİ VE YENİ TEKNİKLER (V7.0 Yolu)
[X] Payload Kalibrasyonu: Yanıt süresi metriğini kullanarak Time-Based zafiyetler için (SQLi) ideal gecikme süresini (threshold) dinamik olarak ayarlama mantığı.

FAZ 8: OTOMASYON VE DERİN ÖĞRENME
[X] Derin JavaScript Analizi: Keşfedilen parametrelerin statik analizi yerine, DOM XSS zafiyetlerini tespit etmek için gerçek zamanlı (headless browser ile) DOM analizi entegre edilmesi.

FAZ 9: ZAFİYET ZİNCİRLEME VE BAĞLAM ZEKÂSI
[X] Zafiyet Zincirleme Algoritması: Tespit edilen zafiyetleri (Örn: LFI, IDOR, SSRF) birleştirerek yeni saldırı vektörleri oluşturma.

FAZ 10: YAPILANDIRMA VE RİSK MODELİ
[X] Özelleştirilebilir Tarama Profilleri: Kullanıcının sadece belirli modülleri veya hassasiyet seviyelerini seçebileceği yapılandırma (config) mantığının entegrasyonu.
[X] CVSS Risk Hesaplaması: Basit puan düşüşü yerine, her zafiyet için endüstri standardı CVSS (Common Vulnerability Scoring System) puanı kullanarak raporlama kalitesini yükseltme.

FAZ 11: MAKİNE ÖĞRENİMİ VE OTOMATİK EXPLOIT ÜRETİMİ
[X] Makine Öğrenimi Destekli Yanlış Pozitif Eliminasyonu: Tespit edilen zafiyetleri, öğrenilmiş sunucu davranışlarına göre sınıflandıran ve hatalı raporları otomatik olarak düşüren bir ML katmanı ekleme (Opsiyonel: Exploit kodu önerileri).

FAZ 12: GELİŞMİŞ OTOMASYON VE SÜREÇ İYİLEŞTİRME
[X] Dinamik Tarama Kayıtları: Dinamik tarayıcı (Selenium) üzerinden otomatik login/form doldurma senaryoları için kayıt/kayıt oynatma yeteneği ekleme (Kompleks SPA'lar için kritik).

FAZ 13: CANLI EXPLOIT YÜRÜTME VE GERİ BİLDİRİM
[X] Canlı Exploit Yürütme: Exploit Manager'dan gelen önerileri konsol üzerinden tek tıkla yürütme ve sonuçlarını loglama yeteneği (Interactive GUI).

FAZ 14: AĞ İSTİHBARATI VE ALTYAPI ANALİZİ
[X] Port Scanner: Hedef sunucu üzerindeki kritik servis portlarını (FTP, SSH, SQL vb.) tarama ve servis versiyonu (Banner) tespit etme.

FAZ 15: SAVUNMA TESPİTİ VE ATLATMA (WAF)
[X] WAF Dedektörü: Hedef önünde Cloudflare veya ModSecurity gibi bir güvenlik duvarı olup olmadığını tespit etme ve PayloadGenerator'ı evasion moduna geçirme.

FAZ 16: VERİ GÖRSELLEŞTİRME VE ANALİTİK
[X] Dashboard Grafikleri: Tespit edilen zafiyetlerin risk dağılımını (Kritik/Yüksek/Orta) gösteren canlı pasta grafiği (matplotlib entegrasyonu).

FAZ 18: BULUT GÜVENLİĞİ VE İSTİHBARAT (Cloudstorm - V18.0)
[X] Cloud Exploit Modülü: AWS, GCP ve Azure metadata endpoint'lerine yönelik SSRF testleri ve hedefle ilişkili açık S3 bucket (depolama) tespiti.
[X] Subdomain Smart Retry & Fallback: crt.sh timeout durumunda pes etmeyen, otomatik retry yapan ve alternatif kaynaklara (Fallback) geçen akıllı keşif mekanizması.

FAZ 18.2: GHOST PROTOCOL (WAF Evasion)
[X] Proxy Rotasyonu: IP adresini dinamik olarak değiştirme.
[X] User-Agent Havuzu: 3000+ farklı cihaz kimliği simülasyonu.
[X] Stealth Mode: Rastgele jitter ve throttling ile WAF atlatma.

FAZ 20: AKTİF OPERASYONLAR (BUG BOUNTY)
[X] OPERATION: RAW FISH (Target: SushiSwap)
- Durum: BLOCKED (WAF - Cloudflare Aggressive Mode)

[X] OPERATION: LIQUID STAKE (Target: Lido Finance)
- Durum: PARTIAL SUCCESS / BLOCKED
- Bulgular: Auth Bypass (Ghost Key) + S3 Buckets (lido-dev)

[X] OPERATION: RAINBOW DASH (Target: Rainbow.me)
- Durum: PARTIAL SUCCESS / BLOCKED
- Bulgular: OOB SSRF Sinyalleri (HIGH), Potansiyel LFI (False Positive Şüphesi)
- Strateji: AI Taktik Analizi Başlatıldı.

[!] FAZ 23: NEURAL SİBER ZEKÂ (AI)
- Durum: AKTİF (Gemini 1.5 Flash ile entegrasyon tamamlandı.)
- NOT: Kritik hatalar için artık AI analizi yürütülecek.

[ ] FAZ 19: SALDIRI YÜZEYİ ANALİZİ VE OSINT
[ ] OSINT Modülü: Hedef hakkında pasif bilgi toplama (Whois, DNS, Email) yeteneği.