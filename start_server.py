# path: PARS Pentest Autonomous Recon System/start_server.py
import subprocess
import sys
import os
import time
import webbrowser

def install_dependencies():
    """Eksik kütüphaneleri otomatik yükler"""
    # FAZ 27 GÜNCELLEMESİ: SQLAlchemy eklendi
    required_packages = ["fastapi", "uvicorn", "python-dotenv", "selenium", "webdriver-manager", "jinja2", "pdfkit", "matplotlib", "wkhtmltopdf", "sqlalchemy"] 
    print("[*] Sunucu gereksinimleri kontrol ediliyor...")
    
    for package in required_packages:
        try:
            # python-dotenv -> dotenv, webdriver-manager -> webdriver_manager dönüşümü
            import_name = package.replace("-", "_")
            if package == "python-dotenv": import_name = "dotenv"
            
            # Eğer paket yüklüyse ve import edilebiliyorsa, atla
            __import__(import_name)
        except ImportError:
            print(f"[!] {package} eksik, yükleniyor...")
            try:
                # sys.executable, betiği çalıştıran Python'ı (genellikle sanal ortamdaki) kullanır.
                subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                print(f"[OK] {package} yüklendi.")
            except Exception as e:
                print(f"[HATA] {package} yüklenemedi: {e}")
                print("İpucu: Lütfen sanal ortamın aktif olduğundan emin olun.")
                input("Hata oluştu. Çıkmak için Enter'a basın.")
                sys.exit(1)
    print("[OK] Tüm kütüphaneler hazır.\n")

def run_server():
    """API Sunucusunu Başlatır"""
    print("="*50)
    print("PARS BULUT MOTORU (Cloud Engine Simulation)")
    print("="*50)
    print("[INFO] Sunucu başlatılıyor...")
    print("[INFO] Adres: http://127.0.0.1:8000")
    print("[INFO] Dokümantasyon: http://127.0.0.1:8000/docs")
    print("-" * 50)
    
    # Sunucu komutu: uvicorn api_server:app --reload
    # sys.executable, start_server.py'yi çalıştıran Python yorumlayıcısını (venv veya global) kullanır.
    cmd = [sys.executable, "-m", "uvicorn", "api_server:app", "--host", "127.0.0.1", "--port", "8000", "--reload"]
    
    try:
        # Tarayıcıda dokümantasyonu aç (opsiyonel)
        # time.sleep(2)
        # webbrowser.open("http://127.0.0.1:8000/docs")
        
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\n[STOP] Sunucu kapatıldı.")
    except Exception as e:
        print(f"\n[HATA] Sunucu başlatılamadı: {e}")
        input("Kapatmak için Enter...")

if __name__ == "__main__":
    # Çalışma dizinini, uvicorn'un 'api_server' modülünü bulabilmesi için ayarla
    project_root = os.path.dirname(os.path.abspath(__file__))
    os.chdir(project_root)
    
    install_dependencies()
    run_server()