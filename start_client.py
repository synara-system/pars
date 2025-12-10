import subprocess
import sys
import os
import time

def install_dependencies():
    """Eksik GUI kütüphanelerini otomatik yükler"""
    required_packages = ["customtkinter", "pillow", "requests", "packaging"]
    print("[*] Arayüz gereksinimleri kontrol ediliyor...")
    
    for package in required_packages:
        try:
            # Pillow paketi 'PIL' olarak import edilir, diğerleri aynı isimle
            import_name = "PIL" if package == "pillow" else package
            __import__(import_name)
        except ImportError:
            print(f"[!] {package} eksik, yükleniyor...")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                print(f"[OK] {package} yüklendi.")
            except Exception as e:
                print(f"[HATA] {package} yüklenemedi: {e}")
                input("Hata oluştu. Çıkmak için Enter'a basın.")
                sys.exit(1)
    print("[OK] Arayüz hazır.\n")

def run_client():
    """GUI İstemcisini Başlatır"""
    print("="*50)
    print("PARS BULUT KOKPİTİ (Client Interface)")
    print("="*50)
    print("[INFO] Arayüz başlatılıyor...")
    
    # Dosya yolunu belirle
    client_script = os.path.join("Test", "gui_cloud.py")
    
    if not os.path.exists(client_script):
        print(f"[HATA] '{client_script}' dosyası bulunamadı!")
        print("Lütfen 'Test' klasörünün proje ana dizininde olduğundan emin olun.")
        input("Çıkış için Enter...")
        return

    # İstemci komutu
    cmd = [sys.executable, client_script]
    
    try:
        subprocess.run(cmd)
    except Exception as e:
        print(f"\n[HATA] Arayüz başlatılamadı: {e}")
        input("Kapatmak için Enter...")

if __name__ == "__main__":
    # Çalışma dizinini betiğin olduğu yer yap
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    install_dependencies()
    run_client()