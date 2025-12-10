# path: Test/gui_cloud.py
# PARS Cloud Cockpit - V2.3 (AI Connected)

import customtkinter as ctk
import threading
import time
import os
import sys

# Proje kök dizinini yola ekle
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.api_client import PARSClient
from Test.gui_dashboard import setup_dashboard_tab, initialize_cards 
from Test.gui_reports import setup_reports_tab
from Test.ui_ai_analyst import setup_ai_analyst_tab, append_to_ai_console

# --- AYARLAR ---
RENDER_API_URL = "https://pars-security-api.onrender.com" 
# ---------------

class CloudMestegApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.COLOR_BG = "#0b0c15"
        self.COLOR_SIDEBAR = "#141526"
        self.COLOR_ACCENT = "#fa1e4e"
        self.COLOR_CYAN = "#00fff5"
        self.COLOR_SUCCESS = "#00e676"
        self.COLOR_TERMINAL = "#0b0c15"
        self.COLOR_TERMINAL_FRAME = "#2d2e42" 
        self.COLOR_TEXT_SECONDARY = "#a0a0b5" 
        self.COLOR_PURPLE = "#a855f7" 
        self.COLOR_WARNING = "#ffcc00"
        self.COLOR_ERROR = "#ff2a6d"

        self.title("PARS CLOUD | Enterprise Security Operations Center")
        self.geometry("1300x800")
        self.configure(fg_color=self.COLOR_BG)
        
        self.api_client = PARSClient(RENDER_API_URL)
        
        self.is_scanning = False
        self.processed_logs = set()
        self.risk_counts = {"CRITICAL": 0, "HIGH": 0, "WARNING": 0, "INFO": 0}
        
        self.console = None
        self.hud_panel = None
        self.entry_url = None
        self.entry_ai_chat = None
        self.btn_scan = None

        self.setup_ui()
        self.after(1000, self.check_cloud_connection)

    def setup_ui(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.setup_sidebar()
        
        self.main_content_area = ctk.CTkFrame(self, fg_color="transparent")
        self.main_content_area.grid(row=0, column=1, sticky="nsew")
        self.main_content_area.grid_rowconfigure(0, weight=1)
        self.main_content_area.grid_columnconfigure(0, weight=1)

        self.tab_dashboard = ctk.CTkFrame(self.main_content_area, fg_color="transparent")
        self.tab_reports = ctk.CTkFrame(self.main_content_area, fg_color="transparent")
        self.tab_ai_analyst = ctk.CTkFrame(self.main_content_area, fg_color="transparent")
        
        setup_dashboard_tab(self)
        self.btn_scan.configure(command=self.start_cloud_scan, text="CONNECT TO CLOUD")
        
        setup_reports_tab(self)
        setup_ai_analyst_tab(self)
        self.select_tab("dashboard")
        
        if hasattr(self, 'module_status_frame'):
            initialize_cards(self)

    def setup_sidebar(self):
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
        self.log_to_gui("[SYSTEM] Bulut sunucusuna bağlanılıyor...", "HEADER")
        def _check():
            if self.api_client.check_connection():
                self.log_to_gui("[SYSTEM] Bulut bağlantısı BAŞARILI. Sistem emre amade.", "SUCCESS")
                self.after(0, lambda: self.btn_scan.configure(text="ENGAGE SYSTEM", state="normal"))
            else:
                self.log_to_gui("[SYSTEM] HATA: Bulut sunucusuna erişilemiyor.", "CRITICAL")
                self.after(0, lambda: self.btn_scan.configure(text="OFFLINE", state="disabled"))
        threading.Thread(target=_check, daemon=True).start()

    def start_cloud_scan(self):
        url = self.entry_url.get().strip()
        if not url: return
        
        self.is_scanning = True
        self.processed_logs.clear()
        
        self.btn_scan.configure(state="disabled", text="TRANSMITTING...", fg_color=self.COLOR_TERMINAL_FRAME)
        self.console.configure(state="normal")
        self.console.delete("1.0", "end")
        self.console.configure(state="disabled")
        
        self.log_to_gui(f"[CLOUD] Hedef ({url}) bulut motoruna iletiliyor...", "INFO")
        
        def _scan_thread():
            try:
                scan_id = self.api_client.start_scan(url)
                self.log_to_gui(f"[CLOUD] Tarama Başlatıldı! ID: {scan_id}", "SUCCESS")
                
                while self.is_scanning:
                    status_data = self.api_client.get_status()
                    if status_data:
                        status = status_data.get("status")
                        score = status_data.get("score", 100)
                        logs_batch = status_data.get("logs", [])
                        
                        for log_line in logs_batch:
                            if log_line not in self.processed_logs:
                                parts = log_line.split('] ', 1)
                                level = "INFO"
                                msg = log_line
                                if len(parts) > 1:
                                    level = parts[0].replace('[', '')
                                    msg = parts[1]
                                self.log_to_gui(msg, level)
                                self.processed_logs.add(log_line)
                        
                        if self.hud_panel:
                            self.after(0, lambda s=score: self.hud_panel.update_stats(s, self.risk_counts))
                        
                        if status in ["completed", "failed"]:
                            self.is_scanning = False
                            final_msg = f"[CLOUD] Tarama durumu: {status.upper()}"
                            final_level = "SUCCESS" if status=="completed" else "CRITICAL"
                            self.log_to_gui(final_msg, final_level)
                            break
                    time.sleep(1.5)
                
                self.after(0, lambda: self.btn_scan.configure(state="normal", text="ENGAGE SYSTEM", fg_color=self.COLOR_ACCENT))
                
            except Exception as e:
                self.log_to_gui(f"[CLOUD ERROR] {e}", "CRITICAL")
                self.is_scanning = False
                self.after(0, lambda: self.btn_scan.configure(state="normal", text="ENGAGE SYSTEM"))

        threading.Thread(target=_scan_thread, daemon=True).start()

    def log_to_gui(self, message, level="INFO"):
        if self.console:
            self.after(0, lambda: self.console.write_log(message, level))
            
    # --- YENİ AI CHAT ENTEGRASYONU ---
    def run_ai_chat_thread(self):
        user_input = self.entry_ai_chat.get()
        if not user_input: return
        self.entry_ai_chat.delete(0, 'end')
        
        self.append_to_ai_console(user_input, "USER")
        self.append_to_ai_console("Bulut beyinle bağlantı kuruluyor...", "AI_INFO")
        
        def _reply():
            # API Client üzerinden AI'a sor
            # Eğer aktif bir tarama varsa onun ID'sini de gönder
            context_id = self.api_client.current_scan_id
            response = self.api_client.ask_ai(user_input, context_id)
            self.append_to_ai_console(response, "AI")
        
        threading.Thread(target=_reply, daemon=True).start()

    def append_to_ai_console(self, message, speaker):
        self.after(0, lambda: append_to_ai_console(self, message, speaker))
        
    # Placeholder metodlar
    def log_welcome_message(self): pass
    def refresh_reports(self): pass
    def open_reports_folder(self): pass
    def update_risk_chart(self, l): pass
    def run_manual_analysis(self): pass

if __name__ == "__main__":
    app = CloudMestegApp()
    app.mainloop()