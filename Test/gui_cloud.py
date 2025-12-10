# path: Test/gui_cloud.py
# PARS Cloud Cockpit - Bulut Tabanlı GUI
# Orijinal gui_main.py'den türetilmiştir, ancak motor yerine API Client kullanır.

import customtkinter as ctk
import tkinter as tk 
from tkinter import messagebox
import threading
import time
import os
import sys
import webbrowser

# Proje kök dizinini yola ekle
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.api_client import PARSClient
from Test.gui_dashboard import setup_dashboard_tab, RichConsole, initialize_cards
from Test.gui_reports import setup_reports_tab
from Test.gui_ai_analyst import setup_ai_analyst_tab, append_to_ai_console

# --- AYARLAR ---
# BURAYA KENDİ RENDER URL'Nİ YAZMALISIN!
RENDER_API_URL = "https://pars-security-api.onrender.com" 
# ---------------

class CloudMestegApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Tema Ayarları
        self.COLOR_BG = "#0b0c15"
        self.COLOR_SIDEBAR = "#141526"
        self.COLOR_ACCENT = "#fa1e4e"
        self.COLOR_CYAN = "#00fff5"
        self.COLOR_SUCCESS = "#00e676"
        self.COLOR_TERMINAL = "#0b0c15"
        self.COLOR_TERMINAL_FRAME = "#2d2e42" 
        self.COLOR_TEXT_SECONDARY = "#a0a0b5" 

        self.title("PARS CLOUD | Enterprise Security Operations Center")
        self.geometry("1300x800")
        self.configure(fg_color=self.COLOR_BG)
        
        # API İstemcisi
        self.api_client = PARSClient(RENDER_API_URL)
        
        # Durum Değişkenleri
        self.is_scanning = False
        self.last_log_content = ""
        self.scan_logs_history = []
        self.risk_counts = {"CRITICAL": 0, "HIGH": 0, "WARNING": 0, "INFO": 0}

        # Arayüz Kurulumu
        self.setup_ui()
        
        # Bağlantı Kontrolü
        self.after(1000, self.check_cloud_connection)

    def setup_ui(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        # Sidebar (Orijinal ile aynı ama basitleştirilmiş)
        self.setup_sidebar()
        
        # Ana Alan
        self.main_content_area = ctk.CTkFrame(self, fg_color="transparent")
        self.main_content_area.grid(row=0, column=1, sticky="nsew")
        self.main_content_area.grid_rowconfigure(0, weight=1)
        self.main_content_area.grid_columnconfigure(0, weight=1)

        # Tablar
        self.tab_dashboard = ctk.CTkFrame(self.main_content_area, fg_color="transparent")
        self.tab_reports = ctk.CTkFrame(self.main_content_area, fg_color="transparent")
        self.tab_ai_analyst = ctk.CTkFrame(self.main_content_area, fg_color="transparent")
        
        # İçerikler (Dashboard'u override edeceğiz)
        setup_dashboard_tab(self)
        # Buton komutunu API başlatıcıya yönlendir
        self.btn_scan.configure(command=self.start_cloud_scan, text="CONNECT TO CLOUD")
        
        setup_reports_tab(self)
        setup_ai_analyst_tab(self)
        
        self.select_tab("dashboard")

    def setup_sidebar(self):
        # Basit Sidebar
        sidebar = ctk.CTkFrame(self, width=240, corner_radius=0, fg_color=self.COLOR_SIDEBAR)
        sidebar.grid(row=0, column=0, sticky="nsew")
        
        ctk.CTkLabel(sidebar, text="PARS CLOUD", font=("Orbitron", 24, "bold"), text_color="white").pack(pady=(40, 10))
        ctk.CTkLabel(sidebar, text="CONNECTED", font=("Consolas", 12), text_color=self.COLOR_SUCCESS).pack()
        
        self.btn_nav_dashboard = ctk.CTkButton(sidebar, text="🛡️ DASHBOARD", command=lambda: self.select_tab("dashboard"), fg_color="transparent")
        self.btn_nav_dashboard.pack(pady=10, padx=20, fill="x")
        
        self.btn_nav_reports = ctk.CTkButton(sidebar, text="📊 REPORTS", command=lambda: self.select_tab("reports"), fg_color="transparent")
        self.btn_nav_reports.pack(pady=10, padx=20, fill="x")
        
        self.btn_nav_ai = ctk.CTkButton(sidebar, text="🧠 AI ANALYST", command=lambda: self.select_tab("ai"), fg_color="transparent")
        self.btn_nav_ai.pack(pady=10, padx=20, fill="x")

    def select_tab(self, name):
        self.tab_dashboard.grid_forget()
        self.tab_reports.grid_forget()
        self.tab_ai_analyst.grid_forget()
        
        if name == "dashboard": self.tab_dashboard.grid(sticky="nsew", padx=20, pady=20)
        if name == "reports": self.tab_reports.grid(sticky="nsew", padx=20, pady=20)
        if name == "ai": self.tab_ai_analyst.grid(sticky="nsew", padx=20, pady=20)

    def check_cloud_connection(self):
        """Sunucuya ping atar."""
        self.log_to_gui("[SYSTEM] Bulut sunucusuna bağlanılıyor...", "HEADER")
        
        def _check():
            if self.api_client.check_connection():
                self.log_to_gui("[SYSTEM] Bulut bağlantısı BAŞARILI. Sistem emre amade.", "SUCCESS")
                self.btn_scan.configure(text="ENGAGE SYSTEM", state="normal")
            else:
                self.log_to_gui("[SYSTEM] HATA: Bulut sunucusuna erişilemiyor. Lütfen interneti veya Render durumunu kontrol edin.", "CRITICAL")
                self.btn_scan.configure(text="OFFLINE", state="disabled")
                
        threading.Thread(target=_check, daemon=True).start()

    def start_cloud_scan(self):
        """API üzerinden taramayı başlatır."""
        url = self.entry_url.get().strip()
        if not url: return
        
        self.is_scanning = True
        self.btn_scan.configure(state="disabled", text="TRANSMITTING...", fg_color=self.COLOR_TERMINAL_FRAME)
        
        self.console.configure(state="normal")
        self.console.delete("1.0", "end")
        self.console.configure(state="disabled")
        
        self.log_to_gui(f"[CLOUD] Hedef ({url}) bulut motoruna iletiliyor...", "INFO")
        
        def _scan_thread():
            try:
                # 1. Taramayı Başlat
                scan_id = self.api_client.start_scan(url)
                self.log_to_gui(f"[CLOUD] Tarama Başlatıldı! ID: {scan_id}", "SUCCESS")
                self.log_to_gui(f"[CLOUD] Uzaktan izleme modu aktif.", "INFO")
                
                # 2. Polling Döngüsü (İzleme)
                while self.is_scanning:
                    status_data = self.api_client.get_status()
                    
                    if status_data:
                        status = status_data.get("status")
                        progress = status_data.get("progress", 0)
                        current_log = status_data.get("current_log", "")
                        score = status_data.get("score", 100)
                        
                        # Yeni log varsa ekrana bas
                        if current_log and current_log != self.last_log_content:
                            # Log formatını çözümle (örn: [INFO] Mesaj)
                            parts = current_log.split('] ', 1)
                            level = "INFO"
                            msg = current_log
                            if len(parts) > 1:
                                level = parts[0].replace('[', '')
                                msg = parts[1]
                            
                            self.log_to_gui(msg, level)
                            self.last_log_content = current_log
                            
                        # HUD Güncelle
                        if self.hud_panel:
                            # Not: Risk sayılarını API'den çekmek için get_results'a bakmak lazım
                            # Şimdilik skoru güncelleyelim
                            self.hud_panel.update_stats(score, self.risk_counts)
                        
                        if status in ["completed", "failed"]:
                            self.is_scanning = False
                            self.log_to_gui(f"[CLOUD] Tarama durumu: {status.upper()}", "SUCCESS" if status=="completed" else "CRITICAL")
                            break
                    
                    time.sleep(2) # 2 saniyede bir güncelle
                
                # Bitiş
                self.btn_scan.configure(state="normal", text="ENGAGE SYSTEM", fg_color=self.COLOR_ACCENT)
                
            except Exception as e:
                self.log_to_gui(f"[CLOUD ERROR] {e}", "CRITICAL")
                self.is_scanning = False
                self.btn_scan.configure(state="normal", text="ENGAGE SYSTEM")

        threading.Thread(target=_scan_thread, daemon=True).start()

    def log_to_gui(self, message, level="INFO"):
        if self.console:
            self.console.write_log(f"[{level}] {message}", level)
            
    # Placeholder metodlar (Orijinal dashboard bunlara ihtiyaç duyuyor)
    def log_welcome_message(self): pass
    def refresh_reports(self): pass
    def open_reports_folder(self): pass
    def update_risk_chart(self, l): pass
    def run_ai_chat_thread(self): pass
    def run_manual_analysis(self): pass

if __name__ == "__main__":
    app = CloudMestegApp()
    app.mainloop()