# path: Test/gui_main.py
# Ana Synara GUI'sini (MestegApp) içerir. Diğer modülleri import eder.

import customtkinter as ctk
import tkinter as tk 
from tkinter import messagebox # simpledialog kaldırıldı, çünkü eski versiyonda yoktu
import threading
import os
import sys
import re
import datetime
import time
import math # Animasyon hesaplamaları için
# import queue # YENİ VERSİYONA AİT: KALDIRILDI
from PIL import Image, ImageTk # YENİ: Resim ve İkon işlemleri için ImageTk eklendi

# Global değişken: Gemini API anahtarını os.environ'dan kurtarır
_GEMINI_API_KEY = ""

# --- YENİ: .env YÜKLEME MANTIĞI (python-dotenv simülasyonu) ---
def load_env_file(filepath=".env.local"):
    global _GEMINI_API_KEY
    
    # KRİTİK: PyInstaller uyumlu yol çözümü
    if getattr(sys, 'frozen', False):
        # EXE içinde, sys._MEIPASS altındaki .env.local
        base_path = sys._MEIPASS
    else:
        base_path = os.getcwd()
        
    full_filepath = os.path.join(base_path, filepath)

    if not os.path.exists(full_filepath):
        return

    with open(full_filepath, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip().strip('\'"') # Tırnakları temizle
                if key == "GEMINI_API_KEY":
                    _GEMINI_API_KEY = value
                
                # Diğer ENV'leri os.environ'a yüklemeye devam et (bazı kütüphaneler hala bakabilir)
                if key:
                    os.environ[key] = value 
                    
# Uygulama başlamadan önce .env'yi yükle
load_env_file()
# ------------------------------------------------------------------

# Proje çekirdek modüllerini import et
from core.engine import SCAN_PROFILES, SynaraScannerEngine 
# YENİ: Dinamik Script Yöneticisini import et
from core.dynamic_script_manager import DynamicScriptManager 
# YENİ: AI Analist modülünü import et
from core.ai_analyst import AIAnalyst 

# Alt modülleri import et
# DÜZELTME: create_risk_pie_chart kaldırıldı, çünkü artık HUD kullanılıyor.
from Test.gui_dashboard import setup_dashboard_tab, RichConsole, initialize_cards 
from Test.gui_reports import setup_reports_tab 
# YENİ: AI Analist Sekmesini import et
from Test.gui_ai_analyst import setup_ai_analyst_tab, append_to_ai_console 

# Global değişken: NeonLoader'ın animasyon ID'si
NEON_LOADER_ANIMATION_ID = None 

class NeonLoader(ctk.CTkFrame):
    """
    [REVİZE EDİLDİ] Fütüristik Cyber Progress Bar.
    Artık sadece animasyon değil, gerçek ilerleme yüzdesini gösterir.
    """
    def __init__(self, master, width=600, height=50, color1="#fa1e4e", color2="#00fff5", bg_color="#0b0c15"):
        super().__init__(master, width=width, height=height, fg_color="transparent")
        self.canvas = tk.Canvas(self, width=width, height=height, bg=bg_color, highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)
        
        self.color1 = color1
        self.color2 = color2
        self.width = width
        self.height = height
        self.is_running = False
        self.progress_val = 0.0 # 0.0 ile 1.0 arası
        self.scan_phase_text = "SYSTEM IDLE"
        self.particles = [] # Efekt parçacıkları
        
    def start(self):
        global NEON_LOADER_ANIMATION_ID
        self.is_running = True
        self.progress_val = 0.0
        self.particles = []
        self.animate()
        
    def stop(self):
        global NEON_LOADER_ANIMATION_ID
        self.is_running = False
        if NEON_LOADER_ANIMATION_ID:
            self.after_cancel(NEON_LOADER_ANIMATION_ID)
            NEON_LOADER_ANIMATION_ID = None
        self.canvas.delete("all")
        
    def update_progress(self, ratio, phase_text=None):
        """İlerlemeyi günceller (0.0 - 1.0 arası)"""
        self.progress_val = max(0.0, min(1.0, ratio))
        if phase_text:
            self.scan_phase_text = phase_text
            
    def animate(self):
        global NEON_LOADER_ANIMATION_ID
        if not self.is_running: return
        
        self.canvas.delete("all")
        
        w = self.width
        h = self.canvas.winfo_height() # Düzeltme: winfo_height() kullan
        if w < 10: w = 600
        if h < 10: h = 50
        
        cy = h / 2
        
        # --- 1. ARKA PLAN RAYI (RAIL) ---
        padding = 20
        bar_w = w - (padding * 2)
        bar_h = 6
        x_start = padding
        x_end = w - padding
        
        # Koyu gri arka plan çizgisi
        self.canvas.create_line(x_start, cy, x_end, cy, width=bar_h, fill="#1a1b26", capstyle="round")
        
        # --- 2. İLERLEME BARI (GLOWING BAR) ---
        fill_width = bar_w * self.progress_val
        if fill_width > 0:
            # Ana dolgu
            self.canvas.create_line(x_start, cy, x_start + fill_width, cy, width=bar_h, fill=self.color2, capstyle="round")
            # Glow efekti (daha ince, daha parlak üst çizgi)
            self.canvas.create_line(x_start, cy, x_start + fill_width, cy, width=2, fill="white", capstyle="round")
            
            # Barın ucundaki "kafa" (Scanner Head)
            head_x = x_start + fill_width
            self.canvas.create_oval(head_x - 5, cy - 5, head_x + 5, cy + 5, fill=self.color1, outline=self.color1)
            
            # --- 3. PARÇACIK EFEKTİ (PARTICLES) ---
            if self.is_running and len(self.particles) < 10 and self.progress_val < 1.0:
                if int(time.time() * 100) % 5 == 0:
                    self.particles.append({'x': head_x, 'y': cy, 'vx': -2 - (self.progress_val * 5), 'life': 1.0})
        
        # Parçacıkları çiz ve güncelle
        new_particles = []
        for p in self.particles:
            alpha = int(p['life'] * 255)
            size = 2 * p['life']
            self.canvas.create_oval(p['x']-size, p['y']-size, p['x']+size, p['y']+size, fill=self.color2, outline="")
            p['x'] += p['vx']
            p['life'] -= 0.1
            if p['life'] > 0:
                new_particles.append(p)
        self.particles = new_particles

        # --- 4. YÜZDE VE DURUM METNİ ---
        percent_text = f"{int(self.progress_val * 100)}%"
        
        # Yüzde (Sağ Taraf)
        self.canvas.create_text(x_end, cy - 15, text=percent_text, fill=self.color2, font=("Consolas", 14, "bold"), anchor="e")
        
        # Faz Bilgisi (Sol Taraf) - Büyük harf ve net font
        self.canvas.create_text(x_start, cy - 15, text=str(self.scan_phase_text).upper(), fill="white", font=("Orbitron", 10, "bold"), anchor="w")

        NEON_LOADER_ANIMATION_ID = self.after(30, self.animate)


class MestegApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # KRİTİK ENCODING DÜZELTMESİ
        try:
            self.tk.call('encoding', 'system', 'utf-8')
        except Exception as e:
            print(f"UYARI: Tcl encoding ayar hatasi: {e}") 
            pass

        # --- PARS KURUMSAL TEMA ---
        self.COLOR_BG = "#0b0c15"       # Deep Space Dark
        self.COLOR_SIDEBAR = "#141526"      # Nebula Dark
        self.COLOR_ACCENT = "#fa1e4e"       # Alert Red
        self.COLOR_CYAN = "#00fff5"      # Cyber Cyan
        self.COLOR_PURPLE = "#a855f7"       # Neon Purple
        self.COLOR_SUCCESS = "#00e676"      # Success Green
        self.COLOR_ERROR = "#ff2a6d"        # Error Red
        self.COLOR_WARNING = "#ffcc00"      # Warning Yellow
        self.COLOR_TERMINAL = "#0b0c15"     # Terminal BG
        self.COLOR_TERMINAL_FRAME = "#2d2e42" 
        self.COLOR_TEXT_SECONDARY = "#a0a0b5" 
        self.COLOR_HIGH_CVSS = "#ff6b00"    # Orange
        self.COLOR_FLOW = "#00fff5"      # Flow
        # -----------------------------------------------------------

        self.console = None 
        self.progress_lock = threading.Lock()
        
        # YENİ VERSİYONA AİT: KALDIRILDI
        # self.log_queue = queue.Queue()
        # self._process_log_queue_id = None
        
        # --- MODÜL EŞLEŞTİRME HARİTASI KALDIRILDI ---
        # Basit versiyonda kullanılmaz.
        
        self.scanner_status_cards = {}
        self.module_status_frame = None 
        self.active_module_key = None 
        
        self.risk_counts = {"CRITICAL": 0, "HIGH": 0, "WARNING": 0, "INFO": 0}
        self.chart_frame = None
        self.hud_panel = None 
        
        self.lbl_status_dot = None 
        self.glow_animation_id = None
        self.glow_phase = 0 
        self.is_scanning = False
        
        self.loader_animation = None
        
        self.script_select_var = ctk.StringVar(value="NO_AUTH")
        self.script_select_menu = None
        
        self.ai_console = None
        
        # AI Analyst'i başlatırken anahtar vermeye gerek yok
        self.ai_analyst = AIAnalyst(logger=self.log_to_gui) 

        # [MARKALAMA] Pencere Başlığı
        self.title("PARS | Pentest Autonomous Recon System") # Başlık eski versiyona göre düzeltildi
        self.geometry("1300x800")
        self.configure(fg_color=self.COLOR_BG) 
        
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

        # BURADAN BAŞLIYOR: Motoru yerel modda başlat (API client yok)
        self.scanner = SynaraScannerEngine(
            logger_callback=self.log_to_gui, 
            progress_callback=self.log_progress_to_gui, 
            config_profile=SynaraScannerEngine.DEFAULT_PROFILE 
        )
        
        # --- ANA DÜZEN ---
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # 1. SOL MENÜ (Sidebar)
        self.setup_sidebar()

        # 2. ANA İÇERİK ALANI
        self.main_content_area = ctk.CTkFrame(self, fg_color="transparent")
        self.main_content_area.grid(row=0, column=1, padx=0, pady=0, sticky="nsew")
        self.main_content_area.grid_rowconfigure(0, weight=1)
        self.main_content_area.grid_columnconfigure(0, weight=1)

        self.tab_dashboard = ctk.CTkFrame(self.main_content_area, fg_color="transparent")
        self.tab_reports = ctk.CTkFrame(self.main_content_area, fg_color="transparent")
        self.tab_ai_analyst = ctk.CTkFrame(self.main_content_area, fg_color="transparent")

        # Şimdi içerikleri doldur
        setup_dashboard_tab(self) 
        
        # KRİTİK DÜZELTME: Butonu KİLİTLE ve perform_self_test'ten sonra AÇ
        if hasattr(self, 'btn_scan'):
             self.btn_scan.configure(state="disabled", text="SYSTEM CHECK...")
             self.btn_scan.configure(command=self.start_scan_thread) # Komutun doğru ayarlandığından emin ol
             
        setup_reports_tab(self) 
        setup_ai_analyst_tab(self) 
        
        self.select_tab("dashboard")
        self.setup_dynamic_script_selector() 
        
        threading.Thread(target=self._check_for_updates, daemon=True).start()
        
        # YENİ: Log kuyruk işlemcisi kaldırıldı
        # self._process_log_queue()
        
        # KRİTİK: Test akışını başlat (Butonu en sonunda enable yapacak)
        self.after(100, self.perform_self_test) # 100ms sonra başlat

    def select_tab(self, tab_name):
        self.tab_dashboard.grid_forget()
        self.tab_reports.grid_forget()
        self.tab_ai_analyst.grid_forget()

        self.btn_nav_dashboard.configure(fg_color="transparent", text_color=self.COLOR_TEXT_SECONDARY, border_width=0)
        self.btn_nav_reports.configure(fg_color="transparent", text_color=self.COLOR_TEXT_SECONDARY, border_width=0)
        self.btn_nav_ai.configure(fg_color="transparent", text_color=self.COLOR_TEXT_SECONDARY, border_width=0)

        if tab_name == "dashboard":
            self.tab_dashboard.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
            self.btn_nav_dashboard.configure(fg_color=self.COLOR_TERMINAL_FRAME, text_color="white", border_color=self.COLOR_ACCENT, border_width=1)
        
        elif tab_name == "reports":
            self.tab_reports.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
            self.btn_nav_reports.configure(fg_color=self.COLOR_TERMINAL_FRAME, text_color="white", border_color=self.COLOR_ACCENT, border_width=1)
            self.refresh_reports() 
            
        elif tab_name == "ai":
            self.tab_ai_analyst.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
            self.btn_nav_ai.configure(fg_color=self.COLOR_TERMINAL_FRAME, text_color="white", border_color=self.COLOR_ACCENT, border_width=1)


    def setup_dynamic_script_selector(self):
        script_options = list(DynamicScriptManager.SCRIPT_PROFILES.keys())
        
        if not hasattr(self, 'input_frame'):
            input_container = self.tab_dashboard 
        else:
            input_container = self.input_bar
        
        if not hasattr(self, 'input_bar'):
             return 

        ctk.CTkLabel(self.input_bar, text="Action Profile:", font=ctk.CTkFont(size=11), text_color=self.COLOR_TEXT_SECONDARY).grid(row=0, column=4, padx=(20, 5), pady=15, sticky="e")
        
        self.script_select_menu = ctk.CTkOptionMenu(
            self.input_bar, 
            values=script_options, 
            variable=self.script_select_var,
            dropdown_fg_color=self.COLOR_SIDEBAR,
            fg_color=self.COLOR_TERMINAL_FRAME,
            button_color=self.COLOR_TERMINAL_FRAME,
            button_hover_color=self.COLOR_BG,
            text_color=self.COLOR_CYAN,
            width=200 
        )
        self.script_select_var.set("NO_AUTH") 
        self.script_select_menu.grid(row=0, column=5, padx=(0, 20), pady=15, sticky="w")
        
        # [MANUEL EXPLOIT BUTONU KALDIRILDI] - Eski versiyona sadık kalındı
        # ctk.CTkButton(self.input_bar, text="MANUEL EXPLOIT", height=40, width=150, 
        #               font=ctk.CTkFont(weight="bold", size=14), fg_color=self.COLOR_PURPLE, 
        #               hover_color=self.COLOR_CYAN, text_color="white", corner_radius=6, 
        #               command=self.run_manual_exploit_dialog).grid(row=0, column=6, padx=(10, 20), pady=15)


    def _resource_path(self, relative_path):
        """
        PyInstaller ile paketlenmiş uygulamalar için kaynak dosyaların tam yolunu döndürür.
        """
        # KRİTİK: Eğer program EXE içine paketlenmişse (frozen), sys._MEIPASS'i kullan.
        # resources'ı doğru bir şekilde bulmak için sys._MEIPASS'e join yapıyoruz.
        if getattr(sys, 'frozen', False):
            return os.path.join(sys._MEIPASS, relative_path)
        
        # Normal Python ortamı (Test/gui_main.py'den iki klasör yukarı çıkmak gerekiyor)
        base_path = os.path.dirname(os.path.abspath(__file__))
        app_root = os.path.dirname(base_path) # Test'ten kök dizine çık
        return os.path.join(app_root, relative_path)


    def setup_sidebar(self):
        sidebar = ctk.CTkFrame(self, width=240, corner_radius=0, fg_color=self.COLOR_SIDEBAR, border_width=0, border_color=self.COLOR_TERMINAL_FRAME) 
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_rowconfigure(8, weight=1) 
        sidebar.grid_columnconfigure(0, weight=1)

        # --- LOGO ALANI ---
        logo_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        logo_frame.grid(row=0, column=0, padx=20, pady=(30, 5)) 
        
        # --- PYINSTALLER UYUMLU LOGO YÜKLEME ---
        try:
            # KRİTİK DÜZELTME: Logo yolunu çözümlemek için _resource_path kullanılıyor.
            image_path = self._resource_path("assets/synara_logo.png")
            
            # Görüntüyü yükle
            pil_image = Image.open(image_path)
            
            try:
                icon_photo = ImageTk.PhotoImage(pil_image)
                self.iconphoto(False, icon_photo)
            except Exception as e:
                print(f"İkon güncelleme hatası: {e}")
            
            self.logo_image = ctk.CTkImage(light_image=pil_image,
                                           dark_image=pil_image,
                                           size=(120, 120)) # Boyut optimize edildi
            
            ctk.CTkLabel(logo_frame, text="", image=self.logo_image).pack(anchor="center")
            
        except FileNotFoundError:
            print(f"UYARI: Logo bulunamadı: {image_path}")
            # Logo yoksa metin göster
            ctk.CTkLabel(logo_frame, text="PARS", font=ctk.CTkFont(family="Orbitron", size=32, weight="bold"), 
                              text_color=self.COLOR_ACCENT).pack(anchor="center")
        except Exception as e:
            print(f"HATA: {e}")
            ctk.CTkLabel(logo_frame, text="PARS", font=ctk.CTkFont(family="Orbitron", size=32, weight="bold"), 
                              text_color=self.COLOR_ACCENT).pack(anchor="center")
        # --- LOGO YÜKLEME SONU ---

        # [MARKALAMA] Logo altı metinleri - BÜYÜK ve NET
        ctk.CTkLabel(logo_frame, text="PARS", font=ctk.CTkFont(family="Orbitron", size=28, weight="bold"), 
                             text_color="white").pack(anchor="center", pady=(5, 0))
                             
        ctk.CTkLabel(logo_frame, text="SECURITY SYSTEM", font=ctk.CTkFont(family="Orbitron", size=12, weight="normal"), 
                             text_color=self.COLOR_ACCENT).pack(anchor="center", pady=(0, 5))

        # Versiyon
        ctk.CTkLabel(sidebar, text="v1.0 ENTERPRISE", font=ctk.CTkFont(family="Consolas", size=10), 
                             text_color=self.COLOR_TEXT_SECONDARY).grid(row=1, column=0, pady=(5, 20))
        
        # Durum Kutusu
        info_box = ctk.CTkFrame(sidebar, fg_color=self.COLOR_BG, corner_radius=8, border_width=1, border_color=self.COLOR_TERMINAL_FRAME)
        info_box.grid(row=3, column=0, padx=15, pady=20, sticky="ew") 
        
        ctk.CTkLabel(info_box, text="SYSTEM STATUS", font=ctk.CTkFont(size=11, weight="bold"), text_color=self.COLOR_TEXT_SECONDARY).pack(pady=(10,5))
        
        self.lbl_status_dot = ctk.CTkLabel(info_box, text="● ONLINE", font=ctk.CTkFont(size=12, weight="bold"), text_color=self.COLOR_SUCCESS)
        self.lbl_status_dot.pack(pady=(0,10))

        # Navigasyon
        nav_label = ctk.CTkLabel(sidebar, text="MODULES", font=ctk.CTkFont(size=10, weight="bold"), text_color=self.COLOR_TEXT_SECONDARY, anchor="w")
        nav_label.grid(row=4, column=0, padx=20, pady=(20, 5), sticky="w") 

        self.btn_nav_dashboard = ctk.CTkButton(sidebar, text="🛡️ DASHBOARD", height=35, corner_radius=6,
                                              font=ctk.CTkFont(size=12, weight="bold"),
                                              fg_color="transparent", text_color=self.COLOR_TEXT_SECONDARY,
                                              hover_color=self.COLOR_TERMINAL_FRAME, anchor="w",
                                              command=lambda: self.select_tab("dashboard"))
        self.btn_nav_dashboard.grid(row=5, column=0, padx=15, pady=2, sticky="ew")

        self.btn_nav_reports = ctk.CTkButton(sidebar, text="📊 REPORTS", height=35, corner_radius=6,
                                            font=ctk.CTkFont(size=12, weight="bold"),
                                            fg_color="transparent", text_color=self.COLOR_TEXT_SECONDARY,
                                            hover_color=self.COLOR_TERMINAL_FRAME, anchor="w",
                                            command=lambda: self.select_tab("reports"))
        self.btn_nav_reports.grid(row=6, column=0, padx=15, pady=2, sticky="ew") 

        # [MARKALAMA DÜZELTMESİ] PARS AI -> SYNARA AI
        self.btn_nav_ai = ctk.CTkButton(sidebar, text="🧠 SYNARA AI", height=35, corner_radius=6,
                                        font=ctk.CTkFont(size=12, weight="bold"),
                                        fg_color="transparent", text_color=self.COLOR_TEXT_SECONDARY,
                                        hover_color=self.COLOR_TERMINAL_FRAME, anchor="w",
                                        command=lambda: self.select_tab("ai"))
        self.btn_nav_ai.grid(row=7, column=0, padx=15, pady=2, sticky="ew")
        
        ctk.CTkFrame(sidebar, fg_color="transparent", height=0).grid(row=8, column=0, sticky="nsew") 

        # [MARKALAMA] Alt İmza - Kurumsal
        ctk.CTkLabel(sidebar, text="SYNARA AI INTELLIGENCE\nGROUP", font=ctk.CTkFont(family="Orbitron", size=9), 
                             text_color=self.COLOR_TEXT_SECONDARY).grid(row=9, column=0, pady=20)

    # --- HELPER METHODS ---
    
    def log_to_gui(self, message, level="INFO"):
        """
        [ESKİ VERSİYON] Logları doğrudan UI thread'inde yazar (Daha az karmaşık).
        """
        if self.console is None:
            return
        self.after(0, lambda: self.console.write_log(message, level))
        
    # YENİ VERSİYONA AİT: KALDIRILDI
    # def _process_log_queue(self):
    #     pass

    # YENİ VERSİYONA AİT: KALDIRILDI
    # def _update_module_status_from_log(self, msg):
    #     pass

    def append_to_ai_console(self, message: str, speaker: str):
        if self.ai_console:
            self.after(0, lambda: append_to_ai_console(self, message, speaker))
        else:
            self.log_to_gui(f"[AI Chat UYARI] {message}", "WARNING")

    def log_welcome_message(self):
        # [MARKALAMA] Tamamen Kurumsal Açılış Mesajı
        self.log_to_gui("PARS SECURITY CORE INITIALIZED...", "HEADER")
        self.log_to_gui(f"Version: v1.0 Enterprise Edition", "INFO")
        self.log_to_gui(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "INFO")
        self.log_to_gui("System Integrity Check: PASS", "SUCCESS")
        self.log_to_gui("-" * 60, "INFO")
        
        # KRİTİK DÜZELTMESİ: os.environ yerine global değişkeni kontrol et
        global _GEMINI_API_KEY
        if _GEMINI_API_KEY:
             self.log_to_gui("API Credentials Loaded (Secure Env).", "SUCCESS")
        
        self.log_to_gui("System Ready. Awaiting Target Input...", "SUCCESS")
        self.log_to_gui("-" * 60, "INFO")
        
    def _initialize_status_cards(self):
        initialize_cards(self) 
        
        # Basit versiyonda Mapping gerekmez, doğrudan kartlar yüklenir.
        
        self.log_to_gui("Modules reset. Matrix loaded.", "INFO")
        self.risk_counts = {"CRITICAL": 0, "HIGH": 0, "WARNING": 0, "INFO": 0}
        
        if self.hud_panel:
            self.hud_panel.update_stats(100.0, self.risk_counts)
        
    def refresh_reports(self):
        pass 

    def start_comparison(self):
        self.log_to_gui("Report Comparison Module Initialized...", "INFO")
        messagebox.showinfo("PARS Security", "Module under development.")

    def _check_for_updates(self):
        self.log_to_gui("Checking for updates...", "INFO")
        time.sleep(1.5) 
        self.log_to_gui("System is up-to-date.", "SUCCESS")
    
    def log_progress_to_gui(self, ratio):
        """
        [YENİ] Motordan gelen ilerleme verisini (0.0 - 1.0) NeonLoader'a aktarır.
        """
        if self.loader_animation:
            # Phase text'i ilerlemeye göre dinamik belirle
            phase_text = "SCANNING..."
            if ratio < 0.1: phase_text = "INITIALIZING..."
            elif ratio < 0.3: phase_text = "RECONNAISSANCE..."
            elif ratio < 0.7: phase_text = "VULNERABILITY ASSESSMENT..."
            elif ratio < 0.9: phase_text = "ANALYZING RESULTS..."
            elif ratio >= 1.0: phase_text = "FINALIZING..."
            
            self.after(0, lambda: self.loader_animation.update_progress(ratio, phase_text))

    def monitor_progress(self):
        # Basit versiyonda log kuyruğu olmadığı için, ilerleme kontrolünü doğrudan yapabiliriz.
        if not self.is_scanning:
            return

        # Motorun iç durumundan ilerlemeyi oku
        if self.scanner and self.scanner.total_scanners > 0:
            ratio = self.scanner.scanners_completed / self.scanner.total_scanners
            self.log_progress_to_gui(ratio)
        
        # 500ms sonra tekrar kontrol et
        self.after(500, self.monitor_progress)

    def animate_terminal_glow(self):
        if not self.is_scanning:
            if hasattr(self, 'terminal_outer_frame'):
                self.terminal_outer_frame.configure(border_color=self.COLOR_TERMINAL_FRAME)
            self.glow_animation_id = None
            return

        speed = 2 
        if self.glow_phase < 10: self.glow_phase += speed
        else: self.glow_phase = 0 

        def _hex_to_rgb(hex_color):
            hex_color = hex_color.lstrip('#')
            return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
        
        def _rgb_to_hex(rgb_tuple):
            return f'#{int(rgb_tuple[0]):02x}{int(rgb_tuple[1]):02x}{int(rgb_tuple[2]):02x}'

        R_START, G_START, B_START = _hex_to_rgb(self.COLOR_TERMINAL_FRAME) 
        R_END, G_END, B_END = _hex_to_rgb(self.COLOR_ACCENT)
        ratio = self.glow_phase / 10.0 
        R = max(0, min(255, R_START + int((R_END - R_START) * ratio)))
        G = max(0, min(255, G_START + int((G_END - G_START) * ratio)))
        B = max(0, min(255, B_START + int((B_END - B_START) * ratio)))

        new_color = _rgb_to_hex((R, G, B))
        if hasattr(self, 'terminal_outer_frame'):
            self.terminal_outer_frame.configure(border_color=new_color)
        self.glow_animation_id = self.after(100, self.animate_terminal_glow)
        
    # run_manual_exploit_dialog metodu eski versiyonda yok, kaldırıldı.
    # def run_manual_exploit_dialog(self):
    #     pass

    def start_scan_thread(self):
        url = self.entry_url.get().strip()
        if not url: return
        if not url.startswith("http"):
            url = "http://" + url
            self.entry_url.delete(0, "end")
            self.entry_url.insert(0, url)

        selected_profile = self.profile_select.get()
        
        self.btn_scan.configure(
            state="normal", 
            text="STOP OPERATION", 
            fg_color=self.COLOR_ERROR, 
            command=self.stop_scan_process  
        )
        
        DynamicScriptManager.OVERRIDE_MAPPING = [] 
        selected_script_name = self.script_select_var.get()
        
        if selected_script_name != "NO_AUTH":
            DynamicScriptManager.OVERRIDE_MAPPING = [
                {
                    "target_url_fragment": url,
                    "script_name": selected_script_name 
                }
            ]
            
        if hasattr(self, 'progress'): 
            self.progress.grid_forget() 
            
        if not hasattr(self, 'loader_animation') or self.loader_animation is None:
            # GÜNCELLENDİ: Loader boyutu ve konumu
            self.loader_animation = NeonLoader(self.tab_dashboard, width=600, height=50, 
                                               color1=self.COLOR_ACCENT, color2=self.COLOR_CYAN, bg_color=self.COLOR_BG)
            self.loader_animation.grid(row=2, column=0, columnspan=3, pady=(0, 10))
        
        self.loader_animation.start()

        self._initialize_status_cards()
        self.console.configure(state="normal")
        self.console.delete("1.0", "end")
        self.console.configure(state="disabled")

        self.is_scanning = True
        self.animate_terminal_glow()
        
        # [YENİ] Progress Monitörü başlat
        self.monitor_progress()

        # KRİTİK: Doğrudan Engine'i çağırıyoruz (API Client yok)
        threading.Thread(target=self.run_scan, args=(url, selected_profile,), daemon=True).start()

    def run_scan(self, url, profile):
        score = self.scanner.start_scan(url, profile) 
        
        ai_analysis = None
        
        html_file, pdf_file = self.scanner.save_report() 
        self.after(0, lambda: self.finish_scan(score, html_file, pdf_file, ai_analysis)) 

    def stop_scan_process(self):
        if self.scanner:
            self.log_to_gui("[SYSTEM] Manual Stop Initiated...", "WARNING")
            self.scanner.stop_scan() 
            
            self.btn_scan.configure(state="disabled", text="ABORTING...", fg_color=self.COLOR_TERMINAL_FRAME)

    def finish_scan(self, score, html_file, pdf_file, ai_analysis: str):
        global NEON_LOADER_ANIMATION_ID
        
        self.is_scanning = False 
        if self.glow_animation_id: self.after_cancel(self.glow_animation_id)
        
        if self.loader_animation:
            self.loader_animation.stop()
            self.loader_animation.grid_forget() 
            self.loader_animation = None
            
        self.btn_scan.configure(
            state="normal", 
            text="INITIALIZE SCAN", 
            fg_color=self.COLOR_ACCENT, 
            command=self.start_scan_thread
        )
        
        self.lbl_status_dot.configure(text="● COMPLETED", text_color=self.COLOR_SUCCESS)
        
        self.log_to_gui(" ", "INFO")
        self.log_to_gui("  ╔════════════════════════════════════════════════╗", "SUCCESS")
        self.log_to_gui("  ║        SCAN SUCCESSFULLY COMPLETED             ║", "SUCCESS")
        self.log_to_gui(f"  ║       Final Security Score: {score:.1f}/100          ║", "SUCCESS")
        self.log_to_gui("  ╚════════════════════════════════════════════════╝", "SUCCESS")
        self.log_to_gui(" ", "INFO")
        
        msg = f"Scan Completed.\nSecurity Score: {score:.1f}/100"
        
        # GÜVENLİ RAPORT YOLU KONTROLÜ (FIX)
        if html_file:
            self.log_to_gui(f"HTML Report generated: {os.path.basename(html_file)}", "INFO")
        else:
            self.log_to_gui("HTML Report generation failed.", "WARNING")

        if pdf_file:
            self.log_to_gui(f"PDF Report generated: {os.path.basename(pdf_file)}", "INFO")
        else:
            self.log_to_gui("PDF Report generation failed (wkhtmltopdf error).", "WARNING")
        
        if ai_analysis:
            # KRİTİK DÜZELTME: self.scanner.score kullan
            self.append_to_ai_console(f"--- ANALYZED RESULT: {self.scanner.target_url} ---\nScore: {self.scanner.score:.1f}/100\n{ai_analysis}", "AI_INFO")
        else:
             # [MARKALAMA DÜZELTMESİ] PARS AI -> SYNARA AI
             self.append_to_ai_console(f"--- TARAMA TAMAMLANDI ---\nSkor: {score:.1f}/100\nAnaliz için 'SYNARA AI' sekmesindeki 'RAPORU YORUMLA' butonunu kullanın.", "AI_INFO")
              
        if self.hud_panel:
            self.hud_panel.update_stats(self.scanner.score, self.risk_counts)
        
        if html_file or pdf_file: self.refresh_reports()
              
        messagebox.showinfo("PARS Security", msg)

    def run_manual_analysis(self):
        if not self.scanner or not self.scanner.results:
            self.append_to_ai_console("ERROR: No scan results found. Please initiate a scan first.", "CRITICAL")
            return
            
        self.append_to_ai_console("Analyzing results...", "AI_INFO")
        
        # KRİTİK DÜZELTMESİ: Global API anahtarını geçir
        global _GEMINI_API_KEY
        score = self.scanner.score # Skoru doğrudan motordan çek
        
        # KRİTİK DÜZELTMESİ: API çağrısı Thread içinde yapılmalı (GUI'yi bloklamamak için)
        def _analyze_task():
             # KRİTİK: Burada AI Analizini senkron çağırıyoruz (requests kullanıyor)
             ai_response = self.ai_analyst.analyze_results(self.scanner.results, score, api_key=_GEMINI_API_KEY)
             
             # Sonucu GUI thread'ine geri gönder
             self.after(0, lambda: self.append_to_ai_console(f"--- MANUAL ANALYSIS: {self.scanner.target_url} ---\nScore: {score:.1f}/100\n{ai_response}", "AI_INFO"))

        threading.Thread(target=_analyze_task, daemon=True).start()

    def delete_report(self, file_path):
        self.log_to_gui(f"[REPORTS] Deleting report: {os.path.basename(file_path)}", "INFO")
        if messagebox.askyesno("Confirm", f"Delete this report?\n{os.path.basename(file_path)}"):
            try:
                base_name, ext = os.path.splitext(file_path)
                files_to_delete = [file_path]
                if ext == ".html" and os.path.exists(base_name + ".pdf"):
                    files_to_delete.append(base_name + ".pdf")
                elif ext == ".pdf" and os.path.exists(base_name + ".html"):
                    files_to_delete.append(base_name + ".html")

                for fpath in files_to_delete:
                    if os.path.exists(fpath):
                        os.remove(fpath)
                
                self.log_to_gui("[REPORTS] Report deleted successfully.", "SUCCESS")
                self.refresh_reports()

            except OSError as e:
                self.log_to_gui(f"[REPORTS] ERROR: Could not delete report: {e}", "CRITICAL")
                messagebox.showerror("Error", f"Could not delete: {e}")
                
    def update_risk_chart(self, level):
        if level in self.risk_counts:
            self.risk_counts[level] += 1

    def open_reports_folder(self):
        import webbrowser
        base_path = os.getcwd()
        report_dir = os.path.join(base_path, "reports")
        if os.path.exists(report_dir):
            os.startfile(report_dir)
        else:
            messagebox.showinfo("Info", "No reports generated yet.")

    def on_closing(self):
        print("Uygulama kapatılıyor, temizlik işlemi başlatıldı...")
        try:
            if self.scanner and self.scanner.dynamic_scanner:
                self.scanner.dynamic_scanner.stop_dynamic_scan()
        except Exception as e:
            print(f"Kapanış hatası: {e}")
        
        self.quit()
        self.destroy() 
        
    def run_ai_chat_thread(self):
        user_input = self.entry_ai_chat.get().strip()
        self.entry_ai_chat.delete(0, "end")
        
        # KRİTİK DÜZELTMESİ: Global API anahtarını kontrol et
        global _GEMINI_API_KEY
        if not _GEMINI_API_KEY:
            self.append_to_ai_console("HATA: Gemini API Key, .env.local dosyası içinde tanımlı değil. Lütfen dosyayı kontrol edin.", "CRITICAL")
            return
        
        if not user_input:
            self.append_to_ai_console("Lütfen bir soru veya fikir yazın.", "AI_INFO")
            return
            
        self.append_to_ai_console(user_input, "USER")
        
        # [MARKALAMA DÜZELTMESİ] AI Persona: Synara AI
        chat_prompt = f"Kullanıcı sorusu: {user_input}\n\nSen Synara AI, profesyonel bir siber güvenlik analistisin. Cevapların teknik, net ve çözüm odaklı olsun. Sadece güvenlik ve analiz üzerine konuş."
        
        self.btn_scan.configure(state="disabled")
        self.entry_ai_chat.configure(state="disabled")

        # KRİTİK DÜZELTMESİ: API çağrısı Thread içinde yapılmalı
        def _chat_task():
            # KRİTİK: Burada AI Analizini senkron çağırıyoruz (requests kullanıyor)
            ai_response = self.ai_analyst.analyze_results(
                 results=[{"category": "CHAT", "level": "INFO", "cvss_score": 0.0, "message": chat_prompt}], 
                 final_score=self.scanner.score,
                 api_key=_GEMINI_API_KEY
            )
            
            self.after(0, lambda: self._complete_chat_gui(ai_response))
            
        threading.Thread(target=_chat_task, daemon=True).start()

    def _complete_chat_gui(self, ai_response):
         # GUI thread'inde çalışır
         self.append_to_ai_console(ai_response, "AI")
         self.btn_scan.configure(state="normal")
         self.entry_ai_chat.configure(state="normal")
        
    def perform_self_test(self):
        self.log_to_gui("Initiating Module Diagnostics...", "HEADER")
        
        def _test_sequence():
            # initialize_cards'ın çağrılması için GUI'nin hazır olması beklenir.
            if not self.scanner_status_cards:
                self.after(50, self._initialize_status_cards)
                time.sleep(0.1)

            if not self.scanner_status_cards:
                return

            for key, card in self.scanner_status_cards.items():
                time.sleep(0.15) 
                
                # Önce Sarı (Checking)
                card['dot'].configure(text="●", text_color=self.COLOR_WARNING)
                card['frame'].configure(border_color=self.COLOR_WARNING)
                
                time.sleep(0.15)
                
                # Sonra Yeşil (Online)
                card['dot'].configure(text="●", text_color=self.COLOR_SUCCESS)
                card['frame'].configure(border_color=self.COLOR_TERMINAL_FRAME) 
                
                self.log_to_gui(f"Module loaded: {key} ... [OK]", "INFO")
                
            # KRİTİK DÜZELTME: Test bittiğinde butonu aktif et
            if hasattr(self, 'btn_scan'):
                self.after(0, lambda: self.btn_scan.configure(
                    state="normal", 
                    text="INITIALIZE SCAN",
                    fg_color=self.COLOR_ACCENT # Rengi geri yükle
                ))

            self.log_to_gui("All modules operational. Systems Nominal.", "SUCCESS")

        threading.Thread(target=_test_sequence, daemon=True).start()

if __name__ == "__main__":
    app = MestegApp()
    app.mainloop()