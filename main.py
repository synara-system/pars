# path: main.py
# Bu dosya, uygulamanın ana giriş noktasıdır.
# Müşteri/Son Kullanıcı akışı: Web Dashboard'u açar.

import os
import sys
import webbrowser

# Python PATH'ini ayarlama (Core modüllerini bulabilmesi için, hata önleme amaçlı tutuldu)
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)

# --- Artık Desktop GUI'ye ihtiyacımız yok, import'lar silindi ---

def open_web_dashboard():
    """
    Yerel makinedeki web_dashboard.html dosyasını varsayılan tarayıcıda açar.
    Kullanıcıya, önce API sunucusunu (start_server.py) çalıştırması gerektiğini hatırlatır.
    """
    current_dir = os.path.dirname(os.path.abspath(__file__))
    dashboard_path = os.path.join(current_dir, "web_dashboard.html")
    
    if os.path.exists(dashboard_path):
        url = 'file://' + os.path.abspath(dashboard_path)
        print("="*60)
        print("PARS WEB DASHBOARD BAŞLATILIYOR")
        print("="*60)
        print("[KRİTİK] Devam etmeden önce LÜTFEN start_server.py dosyasının çalıştığından emin olun.")
        print(f"[INFO] Dashboard adresi: {url}")
        print("-" * 60)
        webbrowser.open(url)
    else:
        print("[HATA] Web Dashboard dosyası bulunamadı!")
        sys.exit(1)


if __name__ == "__main__":
    open_web_dashboard()