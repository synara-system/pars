PARS DOCKER & RENDER.COM KURULUM REHBERİ

1. Neden Docker?

PARS, sadece Python kodu değildir. Arka planda şunlara ihtiyaç duyar:

Nuclei: Zafiyet tarama motoru (Go ile yazılmış).

Chromium: Dinamik tarama için tarayıcı.

Wkhtmltopdf: Raporlama için.

Bu araçları her sunucuya tek tek kurmak zordur. Docker ile hepsini tek bir pakette topluyoruz.

2. Kurulum Adımları

Adım A: Dosyaları Hazırla

Synara Coder'ın oluşturduğu Dockerfile ve requirements_server.txt dosyalarını proje ana dizinine kaydedin.

Adım B: GitHub'a Yükle

Projeyi GitHub'da bir repository'ye (Private önerilir) yükleyin.

Adım C: Render.com Ayarları

Render.com hesabı açın.

"New +" butonuna basıp "Web Service" seçin.

"Build and deploy from a Git repository" seçeneğiyle GitHub repo'nuzu bağlayın.

Ayarlar:

Name: pars-security-api

Runtime: Docker

Instance Type: Free

Environment Variables: (Aşağıdaki anahtarı ekleyin)

GEMINI_API_KEY: [Senin API Anahtarın]

"Create Web Service" butonuna basın. Render, Dockerfile'ı okuyup sunucuyu kuracaktır (İlk kurulum 5-10 dk sürebilir).

3. Test

Kurulum bitince Render size bir URL verecek (örn: https://pars-api.onrender.com).
Tarayıcıdan https://pars-api.onrender.com/docs adresine giderek API dokümantasyonunu görebilirsin.