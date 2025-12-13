# path: PARS Pentest Autonomous Recon System/debug_launcher.py
# PARS - Geliştirici Hibrit Başlatıcısı (v3.0)
# Seçenek sunar: 1) Desktop GUI (Eski Debugger) 2) Web API Server (SaaS Modu)

import os
import sys
import time
import threading
import webbrowser
import subprocess

def install_deps(mode="full"):
    print(f"[*] Kütüphaneler kontrol ediliyor ({mode})...")
    required_packages = ["fastapi", "uvicorn", "python-dotenv", "requests"]
    
    if mode == "desktop":
        required_packages.extend(["customtkinter", "pillow", "matplotlib"])
    
    for package in required_packages:
        try:
            import_name = package.replace("-", "_")
            if package == "pillow": import_name = "PIL"
            if package == "python-dotenv": import_name = "dotenv"
            __import__(import_name)
        except ImportError:
            print(f"[!] Eksik: {package}. Yükleniyor...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])

def launch_desktop_gui():
    """Eski Desktop GUI'yi başlatır (Test/gui_main.py)"""
    print("\n[MOD 1] Desktop GUI Başlatılıyor...")
    install_deps("desktop")
    
    current_dir = os.path.dirname(os.path.abspath(__file__))
    if current_dir not in sys.path:
        sys.path.insert(0, current_dir)
        
    try:
        from Test.gui_main import MestegApp
        app = MestegApp()
        app.mainloop()
    except Exception as e:
        print(f"[HATA] GUI Başlatılamadı: {e}")
        input("Çıkış...")

def launch_web_api():
    """Yeni SaaS API Sunucusunu başlatır (api_server.py)"""
    print("\n[MOD 2] SaaS API Server Başlatılıyor...")
    install_deps("server")
    
    import uvicorn
    
    def open_browser():
        time.sleep(2)
        dashboard_path = os.path.abspath("web_dashboard.html")
        print(f"[INFO] Dashboard: file://{dashboard_path}")
        webbrowser.open(f"file://{dashboard_path}")
        webbrowser.open("http://127.0.0.1:8000/docs")

    threading.Thread(target=open_browser, daemon=True).start()
    
    # API Server'ı başlat
    try:
        # Mevcut dizini path'e ekle ki modüller bulunsun
        sys.path.append(os.path.dirname(os.path.abspath(__file__)))
        uvicorn.run("api_server:app", host="127.0.0.1", port=8000, reload=True)
    except Exception as e:
        print(f"[HATA] API Server Başlatılamadı: {e}")

if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    print("="*50)
    print("PARS GELİŞTİRİCİ KONSOLU (DEBUGGER)")
    print("="*50)
    print("1. Desktop GUI (Eski Geliştirici Arayüzü)")
    print("2. Web API Server (SaaS Backend Testi)")
    print("-" * 50)
    
    choice = input("Seçiminiz (1/2): ").strip()
    
    if choice == "1":
        launch_desktop_gui()
    elif choice == "2":
        launch_web_api()
    else:
        print("Geçersiz seçim. Varsayılan olarak Web API (2) başlatılıyor...")
        launch_web_api()