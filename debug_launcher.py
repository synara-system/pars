# path: debug_launcher.py
# PARS Geliştirici / Debug Modu Başlatıcısı (Localhost/Desktop GUI)

import os
import sys
import traceback
import subprocess
import time

def install_deps():
    print("[*] Kütüphaneler kontrol ediliyor (Geliştirici Modu)...")
    # KRİTİK: Desktop GUI için gerekli tüm kütüphaneler kontrol edilir
    required_packages = ["customtkinter", "aiohttp", "selenium", "webdriver-manager", "jinja2", "pdfkit", "pillow", "matplotlib"]
    
    for package in required_packages:
        try:
            # Özel import isimlerini yönet
            import_name = package.replace("-", "_")
            if package == "pillow": import_name = "PIL"
            
            __import__(import_name)
        except ImportError as e:
            print(f"[UYARI] Eksik kütüphane tespit edildi: {e}")
            print("Lütfen terminalde 'pip install -r requirements_full.txt' komutunu çalıştırın.")
            input("Devam etmek için Enter'a basın (Yüklediyseniz)...")
            break # Hata bulunca kontrolü durdur

    print("[OK] Temel kütüphaneler mevcut/kontrol edildi.")

def main():
    # Çalışma dizinini betiğin olduğu yer yap (Path sorunlarını çözer)
    current_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(current_dir)
    
    # Python path'ine ekle
    if current_dir not in sys.path:
        sys.path.insert(0, current_dir)

    print(f"PARS Security Başlatıcı v2.0 (DEBUG MODE)")
    print(f"Çalışma Dizini: {current_dir}")
    print("-" * 40)

    # 1. Klasör Kontrolü
    required_dirs = ["reports", "core", "Test"]
    for d in required_dirs:
        if not os.path.exists(d):
            try:
                os.makedirs(d)
                print(f"[ONARIM] '{d}' klasörü oluşturuldu.")
            except Exception as e:
                print(f"[HATA] '{d}' klasörü oluşturulamadı: {e}")

    # 2. Uygulamayı Başlat (Desktop GUI)
    try:
        print("[1] Desktop GUI Modülleri yükleniyor (Debug Mode)...")
        # Desktop GUI dosyasına doğrudan referans veriyoruz
        from Test.gui_main import MestegApp 
        
        print("[2] Geliştirici Arayüzü başlatılıyor...")
        app = MestegApp()
        
        print("[3] PARS Aktif! (Localhost/Desktop Penceresi açılıyor...)")
        app.mainloop()
        
    except ImportError as e:
        print("\n" + "!"*50)
        print("[KRİTİK HATA] Desktop GUI modülü (gui_main.py) bulunamadı!")
        print("!"*50)
        print(f"Hata Detayı: {e}")
        print("\nOlası Çözümler:")
        print("1. 'pip install -r requirements_full.txt' komutunu çalıştırdınız mı?")
        print("2. 'Test/gui_main.py' dosyasının yerinde olduğundan emin olun.")
        input("\nÇıkış için Enter'a basın...")
        
    except Exception as e:
        print("\n" + "!"*50)
        print("[BEKLENMEDİK HATA] Uygulama çöktü.")
        print("!"*50)
        traceback.print_exc()
        input("\nÇıkış için Enter'a basın...")

if __name__ == "__main__":
    install_deps()
    main()