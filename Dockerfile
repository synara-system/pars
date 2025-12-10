# path: Dockerfile
# PARS Security - Enterprise Docker Image
# Ubuntu tabanlı Python imajı kullanıyoruz (Nuclei ve Chrome için en stabil ortam)

FROM python:3.10-slim-bullseye

# 1. Sistem Paketlerini Güncelle ve Gerekli Araçları Kur
# wget, gnupg: Nuclei ve Chrome indirmek için
# chromium, chromium-driver: Dinamik tarama için
# wkhtmltopdf: Raporlama için
RUN apt-get update && apt-get install -y \
    wget \
    gnupg \
    unzip \
    curl \
    chromium \
    chromium-driver \
    wkhtmltopdf \
    libglib2.0-0 \
    libnss3 \
    libgconf-2-4 \
    libfontconfig1 \
    && rm -rf /var/lib/apt/lists/*

# 2. Nuclei Kurulumu (Binary olarak indirip /usr/local/bin'e atıyoruz)
# Sürüm: v3.2.0 (Stabil)
RUN wget https://github.com/projectdiscovery/nuclei/releases/download/v3.2.0/nuclei_3.2.0_linux_amd64.zip \
    && unzip nuclei_3.2.0_linux_amd64.zip \
    && mv nuclei /usr/local/bin/ \
    && rm nuclei_3.2.0_linux_amd64.zip \
    && nuclei -version

# 3. Çalışma Dizinini Ayarla
WORKDIR /app

# 4. Python Bağımlılıklarını Kopyala ve Kur
COPY requirements_server.txt .
RUN pip install --no-cache-dir -r requirements_server.txt

# 5. Proje Kodlarını Kopyala
# .dockerignore dosyası olmadığı için her şeyi kopyalar
COPY . .

# 6. Ortam Değişkenleri
# Headless Chrome için gerekli
ENV CHROME_BIN=/usr/bin/chromium
ENV CHROMEDRIVER_PATH=/usr/bin/chromedriver
ENV PYTHONUNBUFFERED=1

# 7. Uygulamayı Başlat (Uvicorn ile)
# api_server.py dosyasındaki 'app' objesini çalıştırır
CMD ["uvicorn", "api_server:app", "--host", "0.0.0.0", "--port", "80"]