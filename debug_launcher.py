import os
import sys
import traceback
import subprocess
import time

def install_deps():
    print("[*] Kütüphaneler kontrol ediliyor...")
    try:
        import customtkinter
        import aiohttp
        import selenium
        import jinja2
        print("[OK] Temel kütüphaneler mevcut.")
    except ImportError as e:
        print(f"[UYARI] Eksik kütüphane tespit edildi: {e}")
        print("Lütfen terminalde şu komutu çalıştırın: pip install -r requirements_full.txt")
        input("Devam etmek için Enter'a basın (Yüklediyseniz)...")

def main():
    # Çalışma dizinini betiğin olduğu yer yap (Path sorunlarını çözer)
    current_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(current_dir)
    
    # Python path'ine ekle
    if current_dir not in sys.path:
        sys.path.insert(0, current_dir)

    print(f"PARS Security Başlatıcı v2.0")
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

    # 2. Uygulamayı Başlat
    try:
        print("[1] GUI Modülleri yükleniyor...")
        # sys.path ayarlandığı için artık Test.gui_main bulunabilir olmalı
        from Test.gui_main import MestegApp
        
        print("[2] Arayüz başlatılıyor...")
        app = MestegApp()
        
        print("[3] PARS Aktif! (Pencere açılıyor...)")
        app.mainloop()
        
    except ImportError as e:
        print("\n" + "!"*50)
        print("[KRİTİK HATA] Modül bulunamadı!")
        print("!"*50)
        print(f"Hata Detayı: {e}")
        print("\nOlası Çözümler:")
        print("1. 'pip install -r requirements_full.txt' komutunu çalıştırdınız mı?")
        print("2. Proje klasör yapısının bozulmadığından emin olun.")
        print(f"   (Beklenen yapı: {current_dir}\\Test\\gui_main.py)")
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