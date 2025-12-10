import subprocess
import sys
import os
import time
import webbrowser

def install_dependencies():
    """Eksik kütüphaneleri otomatik yükler"""
    required_packages = ["fastapi", "uvicorn", "python-dotenv"]
    print("[*] Sunucu gereksinimleri kontrol ediliyor...")
    
    for package in required_packages:
        try:
            __import__(package.replace("-", "_")) # python-dotenv -> dotenv kontrolü
        except ImportError:
            print(f"[!] {package} eksik, yükleniyor...")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                print(f"[OK] {package} yüklendi.")
            except Exception as e:
                print(f"[HATA] {package} yüklenemedi: {e}")
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
    cmd = [sys.executable, "-m", "uvicorn", "api_server:app", "--host", "127.0.0.1", "--port", "8000", "--reload"]
    
    try:
        # Tarayıcıda dokümantasyonu aç (opsiyonel, sunucunun açılması için 2sn bekle)
        # time.sleep(2)
        # webbrowser.open("http://127.0.0.1:8000/docs")
        
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\n[STOP] Sunucu kapatıldı.")
    except Exception as e:
        print(f"\n[HATA] Sunucu başlatılamadı: {e}")
        input("Kapatmak için Enter...")

if __name__ == "__main__":
    # Çalışma dizinini ayarla
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    install_dependencies()
    run_server()