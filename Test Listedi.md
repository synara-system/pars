PARS Otonom Tarama Canlı Test Matrisi (Yasal Laboratuvarlar)

Bu matris, PARS motorunun modüllerini, kasıtlı olarak zafiyetli bırakılmış, yasal ve halka açık test ortamlarında (Lab'lar) nasıl kullanabileceğinizi göstermektedir.

UYARI: Bu platformlar dışında kalan gerçek siteleri, açık izin almadan veya bir Bug Bounty programının parçası olmadan taramak yasa dışıdır.

🎯 Test Hedefi / Tarayıcı Eşleştirmeleri

PARS Tarayıcı Modülü

Test Edilecek Zafiyet Tipi

Önerilen Platform

Erişim Linki / Yöntemi

SQLi (SQL Injection)

Veritabanı Enjeksiyonu

Acunetix PHP/ASP

http://testphp.vulnweb.com/

XSS (Cross-Site Scripting)

Yansıtılmış/Kalıcı Zafiyetler

OWASP Juice Shop

https://juice-shop.herokuapp.com

IDOR / AUTH_BYPASS

Yetki Atlama, API Mantık Hataları

OWASP Juice Shop / WebGoat

https://juice-shop.herokuapp.com

LLM_INJECTION

Prompt Enjeksiyonu, Güvenlik Kısıtlaması Atlama

OWASP Juice Shop

(Chatbot arayüzü varsa)

LFI / RCE / SSRF

İç Dosya Erişimi / Kod Çalıştırma / Sunucu Yanıltma

Webhook.site

https://webhook.site/ (Webhook URL'sini RCE/SSRF payload'larına enjekte et)

HTTP_SMUGGLING

HTTP İstek Kaçakçılığı

PortSwigger Web Sec Academy

(Özel olarak Smuggling lab'ları)

RACE_CONDITION

Yarış Koşulu (Stok/Kupon/Para Transferi)

Kendi Local Sunucunuz

http://127.0.0.1:5000 (En Etkili Test Yeri)

PRE_SCAN / JS_ENDPOINT

Endpoint/Secret Keşfi

Tümü

Ana URL'ler

🌐 Detaylı Platform Listesi

Platform Adı

Odak Noktası

URL

Notlar

OWASP Juice Shop

Modern uygulamalar (REST, JWT, Business Logic)

https://juice-shop.herokuapp.com

En güncel zafiyet türlerini barındırır.

Acunetix Test Siteleri

PHP/ASP.NET'e özgü zafiyetler

http://testphp.vulnweb.com/

PARS'ın dil spesifik taramalarını test edin.

OWASP WebGoat

Gelişmiş Eğitim Platformu

https://webgoat.cloud

Modül modül ilerler, taramadan önce oturum açma gerektirebilir.

PortSwigger Web Security Academy

Çok Gelişmiş Lab'lar

https://portswigger.net/web-security/all-labs

Her lab için dinamik URL üretir.

Google Gruyere

Basit XSS, CSRF, Bilgi Sızıntısı

https://google-gruyere.appspot.com/

Temel güvenlik ilkelerini test etmek için ideal.

Webhook.site

Geri Çağrı (Callback) Mekanizması

https://webhook.site/

PARS'ın OOB (Out-of-Band) SSRF/RCE sinyallerini test etmek için kullanılmalıdır.

HackTheBox Academy

Canlı ve Hukukî Hedefler

https://academy.hackthebox.com/

Genellikle VPN ile erişim gerektirir.