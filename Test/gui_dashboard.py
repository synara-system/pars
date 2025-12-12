# path: Synara AI Security Test/Test/gui_dashboard.py

import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox
import re
import datetime
import uuid
import math

# FAZ 16: Grafik çizimi için matplotlib (Artık kullanılmayacak ama import kalsın)
try:
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    from matplotlib.figure import Figure
    from matplotlib.patches import Circle
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

# --- FAZ 42 KRİTİK: TÜM SABİTLERİ STATİK BİR SINIF İÇİNE TAŞI ---
class UI_CONSTANTS:
    COLOR_BG = "#0b0c15"            # Deep Space Dark
    COLOR_SIDEBAR = "#141526"       # Nebula Dark
    COLOR_ACCENT = "#fa1e4e"        # GX Red
    COLOR_CYAN = "#00fff5"          # Cyber Cyan
    COLOR_PURPLE = "#a855f7"        # Neon Purple
    COLOR_SUCCESS = "#00e676"       # Neon Green
    COLOR_ERROR = "#ff2a6d"         # Glitch Red
    COLOR_WARNING = "#ffcc00"       # Cyber Yellow
    COLOR_TERMINAL = "#0f111a"      # Terminal Arka Planı
    COLOR_TERMINAL_FRAME = "#2d2e42" 
    COLOR_TEXT_PRIMARY = "#ffffff"
    COLOR_TEXT_SECONDARY = "#a0a0b5"
    COLOR_CARD_IDLE = "#1e202e"
    COLOR_HIGH_CVSS = "#ff6b00"     # Orange (COLOR_HIGH_CVSS hatasının kaynağı)

# --- TARAMA PROFİLLERİ (Engine bağımlılığını kaldırmak için buraya taşındı) ---
SCAN_PROFILES = {
    "FULL_SCAN": "Tüm modüller (Hafiften Kapsamlı Fuzzing'e kadar). En yavaş ve en derin tarama.",
    "BUG_BOUNTY_CORE": "BBH (Bug Bounty Hunter - SADECE KAZANÇ): Yüksek Ödüllü Kritik Zafiyetler ve Gelişmiş Keşif için optimize edilmiştir.",
    "LIGHT": "Sadece Temel Analiz ve Zeka (Headers, Files, Heuristic). Çok hızlı.",
    "FUZZING_ONLY": "Sadece Fuzzing Modülleri (XSS, SQLi, LFI, RCE).",
    "INTERNAL_MISSION": "Sadece Synara'nın çekirdeğini (Codebase, Manifest, Sırlar) analiz eder."
}

class ModuleStatusCard(ctk.CTkFrame):
    """
    Her tarama modülü için yüksek kaliteli, durum göstergeli kart.
    FAZ 41: Varsayılan sönük rengi kaldırdık.
    """
    def __init__(self, master, module_name, module_key, app_instance):
        super().__init__(master, 
                          fg_color="transparent", 
                          corner_radius=6, 
                          border_width=1, 
                          border_color=UI_CONSTANTS.COLOR_TERMINAL_FRAME, 
                          height=45) 
        
        self.grid_propagate(False) 
        self.columnconfigure(0, weight=1) # İsim
        self.columnconfigure(1, weight=0) # Durum Yazısı
        # KRİTİK YAZIM HATASI DÜZELTİLDİ: self45 -> self
        self.columnconfigure(2, weight=0) # İkon
        
        self.app_instance = app_instance
        self.module_key = module_key
        
        # Modül Adı
        self.name_label = ctk.CTkLabel(self, text=module_name, 
                                       font=ctk.CTkFont(family="Orbitron", size=11, weight="bold"), 
                                       anchor="w", text_color=UI_CONSTANTS.COLOR_TEXT_SECONDARY)
        self.name_label.grid(row=0, column=0, padx=(12, 5), pady=0, sticky="w")
        self.name_label.place(relx=0.05, rely=0.5, anchor="w")

        # Durum Metni (▶ / ✓)
        self.info_label = ctk.CTkLabel(self, text="", 
                                       font=ctk.CTkFont(family="Consolas", size=14, weight="bold"), 
                                       text_color=UI_CONSTANTS.COLOR_TEXT_SECONDARY) 
        self.info_label.place(relx=0.85, rely=0.5, anchor="center")

        # Durum İkonu (En Sağda)
        # FAZ 41: Varsayılan İkonu daha görünür yapıyoruz
        self.status_dot = ctk.CTkLabel(self, text="●", font=ctk.CTkFont(size=12), text_color="#475569")
        self.status_dot.place(relx=0.95, rely=0.5, anchor="center")
        
    def set_status(self, status, message=""):
        """
        Bu fonksiyon, gui_main.py'nin update_card_visual metoduna devredilmiştir.
        Burada sadece basit durum görselleştirmesi kalmıştır.
        """
        if status == "active":
            # Ana rengi koru, sadece bordürü canlandır
            self.configure(border_color=UI_CONSTANTS.COLOR_CYAN, border_width=1)
            self.name_label.configure(text_color="white")
        elif status == "finished":
            self.configure(border_color=UI_CONSTANTS.COLOR_TERMINAL_FRAME, border_width=1)
            self.name_label.configure(text_color=UI_CONSTANTS.COLOR_TEXT_SECONDARY)
        elif status == "waiting":
            self.configure(border_color=UI_CONSTANTS.COLOR_TERMINAL_FRAME, border_width=1)
            self.name_label.configure(text_color=UI_CONSTANTS.COLOR_TEXT_SECONDARY)

class ThreatFeedCard(ctk.CTkFrame):
    """Sağ panelde akan canlı tehdit kartı."""
    def __init__(self, master, category, level, message):
        color = UI_CONSTANTS.COLOR_PURPLE 
        if level == "CRITICAL": color = UI_CONSTANTS.COLOR_ERROR
        elif level == "HIGH": color = UI_CONSTANTS.COLOR_HIGH_CVSS
        elif level == "WARNING": color = UI_CONSTANTS.COLOR_WARNING
        elif level == "SUCCESS": color = UI_CONSTANTS.COLOR_SUCCESS
        
        super().__init__(master, fg_color="#11131c", corner_radius=4, border_width=0, height=50)
        self.pack_propagate(False)
        
        self.strip = ctk.CTkFrame(self, width=3, fg_color=color, corner_radius=0)
        self.strip.pack(side="left", fill="y")
        
        self.content = ctk.CTkFrame(self, fg_color="transparent")
        self.content.pack(side="left", fill="both", expand=True, padx=8, pady=4)
        
        ctk.CTkLabel(self.content, text=f"{category}", 
                     font=ctk.CTkFont(family="Orbitron", size=10, weight="bold"), 
                     text_color=color, anchor="w").pack(fill="x")
                     
        clean_msg = message.replace('\n', ' ').strip()
        short_msg = (clean_msg[:40] + '..') if len(clean_msg) > 40 else clean_msg
        ctk.CTkLabel(self.content, text=short_msg, 
                     font=ctk.CTkFont(family="Consolas", size=9), 
                     text_color=UI_CONSTANTS.COLOR_TEXT_SECONDARY, anchor="w").pack(fill="x")

class AIThreatVisualizer(ctk.CTkFrame):
    """
    FAZ 25.1: Fütüristik, canlı ve 'Hacker Filmi' tarzı tehdit görselleştirme radarı.
    SecurityShieldHUD'ın yerini alır ve çok daha dinamik bir deneyim sunar.
    """
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.canvas = tk.Canvas(self, bg=UI_CONSTANTS.COLOR_SIDEBAR, highlightthickness=0, width=220, height=220)
        self.canvas.pack(fill="both", expand=True, padx=0, pady=0)
        
        self.score = 100.0
        self.risk_counts = {"CRITICAL": 0, "HIGH": 0, "WARNING": 0, "INFO": 0} # INFO eklendi
        self.angle = 0
        self.blips = [] # (angle, distance, color, size)
        
        # Animasyon Döngüsü
        self.animate()
        self.bind("<Configure>", lambda e: self.draw_static_elements())

    def update_stats(self, score, risks):
        self.score = score
        self.risk_counts = risks
        self._generate_blips()

    def _generate_blips(self):
        """Risk sayılarına göre radar üzerinde noktalar (blips) oluşturur."""
        self.blips = []
        import random
        
        # Kritik Riskler (Kırmızı, Merkeze Yakın, Büyük)
        for _ in range(self.risk_counts.get("CRITICAL", 0)):
            self.blips.append({
                "angle": random.randint(0, 360),
                "dist": random.uniform(0.2, 0.4), # Merkeze yakın
                "color": UI_CONSTANTS.COLOR_ERROR,
                "size": random.randint(6, 9)
            })
            
        # Yüksek Riskler (Turuncu, Orta Mesafe)
        for _ in range(self.risk_counts.get("HIGH", 0)):
            self.blips.append({
                "angle": random.randint(0, 360),
                "dist": random.uniform(0.45, 0.7),
                "color": UI_CONSTANTS.COLOR_HIGH_CVSS,
                "size": random.randint(4, 7)
            })
            
        # Uyarılar (Sarı, Dış Halka)
        for _ in range(self.risk_counts.get("WARNING", 0)):
             # Çok fazla uyarı varsa hepsini çizme (performans)
            if len(self.blips) > 30: break
            self.blips.append({
                "angle": random.randint(0, 360),
                "dist": random.uniform(0.75, 0.9),
                "color": UI_CONSTANTS.COLOR_WARNING,
                "size": random.randint(3, 5)
            })

    def draw_static_elements(self):
        # Statik öğeler animate döngüsü içinde her karede çiziliyor,
        # bu metod sadece resize eventi için placeholder.
        pass

    def animate(self):
        self.canvas.delete("all")
        
        w = self.canvas.winfo_width()
        h = self.canvas.winfo_height()
        if w < 10: w = 220
        if h < 10: h = 220
        
        cx, cy = w / 2, h / 2
        radius = min(w, h) / 2 - 15
        
        # 1. Radar Halkaları (Statik + Hafif Yanıp Sönme)
        for i in range(1, 4):
            r = radius * (i / 3)
            alpha = int(40 + 20 * math.sin(math.radians(self.angle * 2))) # Nefes alma efekti
            outline_col = UI_CONSTANTS.COLOR_TERMINAL_FRAME
            if i == 3: outline_col = UI_CONSTANTS.COLOR_ACCENT # Dış halka
            
            self.canvas.create_oval(cx-r, cy-r, cx+r, cy+r, outline=outline_col, width=1)

        # 2. Dönen Tarayıcı (Scanner Sweep)
        scan_angle_rad = math.radians(self.angle)
        scan_x = cx + radius * math.cos(scan_angle_rad)
        scan_y = cy + radius * math.sin(scan_angle_rad)
        
        # Radar çizgisi
        self.canvas.create_line(cx, cy, scan_x, scan_y, fill=UI_CONSTANTS.COLOR_CYAN, width=2)
        
        # Radar izi (Trail) - Simüle edilmiş
        for i in range(1, 20):
            trail_angle = self.angle - i
            trail_rad = math.radians(trail_angle)
            tx = cx + radius * math.cos(trail_rad)
            ty = cy + radius * math.sin(trail_rad)
            # Renk gittikçe koyulaşmalı (Simüle)
            if i < 5: color = "#00e5ff"
            elif i < 10: color = "#00acc1"
            else: color = "#006064"
            self.canvas.create_line(cx, cy, tx, ty, fill=color, width=1)

        # 3. Tehdit Noktaları (Blips)
        for blip in self.blips:
            # Noktanın konumu
            b_rad = math.radians(blip['angle'])
            bx = cx + (radius * blip['dist']) * math.cos(b_rad)
            by = cy + (radius * blip['dist']) * math.sin(b_rad)
            
            # Tarayıcı çizgisinin üzerinden geçtiği anı yakala (Basit çarpışma)
            # Açılar arasındaki farkı bul
            diff = abs(self.angle % 360 - blip['angle'] % 360)
            if diff < 15 or diff > 345:
                # Parlama efekti (Highlight)
                self.canvas.create_oval(bx-blip['size']-2, by-blip['size']-2, 
                                         bx+blip['size']+2, by+blip['size']+2, 
                                         outline="white", width=1)
                
            self.canvas.create_oval(bx-blip['size']/2, by-blip['size']/2, 
                                     bx+blip['size']/2, by+blip['size']/2, 
                                     fill=blip['color'], outline="")

        # 4. Merkez Skor (HUD)
        # Ortada şeffaf/koyu bir daire
        inner_r = radius * 0.35
        self.canvas.create_oval(cx-inner_r, cy-inner_r, cx+inner_r, cy+inner_r, fill=UI_CONSTANTS.COLOR_BG, outline=UI_CONSTANTS.COLOR_CYAN)
        
        score_color = UI_CONSTANTS.COLOR_SUCCESS
        if self.score < 50: score_color = UI_CONSTANTS.COLOR_ERROR
        elif self.score < 80: score_color = UI_CONSTANTS.COLOR_WARNING
        
        self.canvas.create_text(cx, cy, text=f"{int(self.score)}", fill=score_color, font=("Orbitron", 24, "bold"))

        # Animasyon döngüsü (Hız: 5 derece/frame)
        self.angle = (self.angle + 4) % 360
        self.after(50, self.animate)

class RichConsole(ctk.CTkFrame):
    """Entegre scrollbar'lı Terminal Widget'ı."""
    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color=UI_CONSTANTS.COLOR_TERMINAL, corner_radius=6, border_width=1, border_color=UI_CONSTANTS.COLOR_TERMINAL_FRAME)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.scrollbar = ctk.CTkScrollbar(self, orientation="vertical", width=10, fg_color="transparent", button_color="#334155", button_hover_color=UI_CONSTANTS.COLOR_ACCENT)
        self.scrollbar.grid(row=0, column=1, sticky="ns", padx=(0, 2), pady=2)

        self.text_area = tk.Text(self, bg=UI_CONSTANTS.COLOR_TERMINAL, fg=UI_CONSTANTS.COLOR_TEXT_PRIMARY, bd=0, padx=15, pady=15, 
                                 font=("Consolas", 10), selectbackground=UI_CONSTANTS.COLOR_ACCENT, selectforeground="white",
                                 highlightthickness=0, yscrollcommand=self.scrollbar.set)
        self.text_area.grid(row=0, column=0, sticky="nsew", padx=2, pady=2)
        
        self.scrollbar.configure(command=self.text_area.yview)

        # Renkler
        self.text_area.tag_config("HEADER", foreground=UI_CONSTANTS.COLOR_PURPLE, font=("Consolas", 11, "bold"))
        self.text_area.tag_config("INFO", foreground=UI_CONSTANTS.COLOR_TEXT_SECONDARY) 
        self.text_area.tag_config("SUCCESS", foreground=UI_CONSTANTS.COLOR_SUCCESS, font=("Consolas", 10, "bold"))
        self.text_area.tag_config("WARNING", foreground=UI_CONSTANTS.COLOR_WARNING)
        self.text_area.tag_config("CRITICAL", foreground=UI_CONSTANTS.COLOR_ERROR, font=("Consolas", 11, "bold"))
        self.text_area.tag_config("CMD", foreground=UI_CONSTANTS.COLOR_CYAN, font=("Consolas", 10, "bold"))
        self.text_area.tag_config("EXPLOIT_RUN", foreground="#0b0c15", background=UI_CONSTANTS.COLOR_ACCENT, font=("Consolas", 10, "bold"))
        
        self.text_area.tag_bind("EXPLOIT_RUN", "<Button-1>", self._on_exploit_run_click)
        self.text_area.tag_bind("EXPLOIT_RUN", "<Enter>", lambda e: self.text_area.configure(cursor="hand2"))
        self.text_area.tag_bind("EXPLOIT_RUN", "<Leave>", lambda e: self.text_area.configure(cursor="arrow"))
        self.exploit_data_map = {}
        self.EXPLOIT_PATTERN = re.compile(r'Exploit Önerisi:\s*(.*?)(?:\]|$)', re.DOTALL | re.IGNORECASE)

    def configure(self, **kwargs):
        text_kwargs = {}
        if 'state' in kwargs: text_kwargs['state'] = kwargs.pop('state')
        if 'cursor' in kwargs: text_kwargs['cursor'] = kwargs.pop('cursor')
        if text_kwargs: self.text_area.configure(**text_kwargs)
        if kwargs: super().configure(**kwargs)

    def delete(self, *args, **kwargs): self.text_area.delete(*args, **kwargs)
    def insert(self, *args, **kwargs): self.text_area.insert(*args, **kwargs)
    def see(self, index): self.text_area.see(index)
    def index(self, index): return self.text_area.index(index)
    def tag_names(self, index): return self.text_area.tag_names(index)
    def tag_config(self, tagName, **kwargs): self.text_area.tag_config(tagName, **kwargs)
    def tag_bind(self, tagName, sequence, func, add=None): self.text_area.tag_bind(tagName, sequence, func, add)

    def _on_exploit_run_click(self, event):
        index = self.text_area.index(f"@{event.x},{event.y}")
        tags = self.text_area.tag_names(index)
        for tag in tags:
            if tag.startswith("run_"):
                exploit_id = tag.split('_')[-1]
                exploit_data = self.exploit_data_map.get(exploit_id)
                app = self.master.winfo_toplevel()
                # GUI Cloud modunda çalışırken yerel exploit çalıştırma desteklenmez
                # Ancak ileride API üzerinden exploit isteği gönderilebilir
                if hasattr(app, 'run_manual_exploit_dialog'): 
                     messagebox.showinfo("Info", "Cloud Mode: Manuel exploit için lütfen panel butonunu kullanın.")
                return

    def write_log(self, message, level):
        try: message = message.encode('utf-8', 'ignore').decode('utf-8')
        except: message = ''.join(c for c in message if c.isascii())
        message = message.replace('\r', '')

        self.text_area.configure(state="normal")
        header_match = re.match(r'\[([^\]]+)\] (.*)', message, re.DOTALL)
        prefix = ""
        log_content = message
        cat_tag = level
        
        app = self.master.winfo_toplevel() 
        
        if header_match:
            prefix = header_match.group(1) + " │ " 
            log_content = header_match.group(2)
            
            # --- MODÜL DURUMU GÜNCELLEME ---
            raw_category = header_match.group(1).split('|')[0].strip()
            CATEGORY_MAP = {
                "SYSTEM": "PORT_SCAN",
                "PRE-SCAN": "PRE_SCAN",
                "JS_ENDPOINT": "JS_ENDPOINT",
                "SSRF_RCE": "RCE_SSRF"
            }
            target_key = CATEGORY_MAP.get(raw_category, raw_category)
            
            if hasattr(app, 'scanner_status_cards'):
                # Sadece ilgili modül kartını bul
                card_key = target_key.upper()
                if card_key in app.scanner_status_cards:
                     app.update_card_visual(card_key, level)
                # Subdomain/RCE türevlerini ana modüle eşitle
                elif 'SUBDOMAIN' in card_key or 'RCE' in card_key:
                     if 'TAKEOVER' in card_key: app.update_card_visual('SUBDOMAIN', level)
                     elif 'SSRF' in card_key: app.update_card_visual('RCE_SSRF', level)
                
            # --- TEHDİT AKIŞINA EKLEME ---
            if level in ["CRITICAL", "HIGH", "WARNING", "SUCCESS"] and hasattr(app, 'add_threat_feed_item'):
                 app.add_threat_feed_item(raw_category, level, log_content)
            
            if "CRITICAL" in level: cat_tag = "CRITICAL"
            elif "WARNING" in level: cat_tag = "WARNING"
            elif "SUCCESS" in level: cat_tag = "SUCCESS"
            elif "CMD" in level: cat_tag = "CMD"
            else: cat_tag = "CMD" 

        # Scan Completed kontrolü cloud modunda farklı işlenir, burada sadece görsel
        if "Scan Completed" in message or "Tarama Bitti" in message:
             if hasattr(app, 'scanner_status_cards'):
                 for mod_key, card_data in app.scanner_status_cards.items():
                     app.update_card_visual(mod_key, "SUCCESS")

        timestamp = datetime.datetime.now().strftime('%H:%M:%S') 
        self.text_area.insert("end", f"{timestamp} ", "INFO")
        
        if prefix: self.text_area.insert("end", prefix, cat_tag)

        exploit_match = self.EXPLOIT_PATTERN.search(log_content)
        if exploit_match:
            exploit_data = exploit_match.group(1).strip()
            clean_msg = re.sub(r'\[?Exploit Önerisi:.*?\]?', '', log_content, flags=re.IGNORECASE | re.DOTALL).strip()
            self.text_area.insert("end", clean_msg + "\n", level)
            
            exploit_id = str(uuid.uuid4())[:8]
            self.exploit_data_map[exploit_id] = exploit_data
            run_tag_name = f"run_{exploit_id}"
            self.text_area.tag_config(run_tag_name, foreground="#0b0c15", background=UI_CONSTANTS.COLOR_ACCENT, font=("Consolas", 9, "bold"))
            self.text_area.tag_bind(run_tag_name, "<Button-1>", self._on_exploit_run_click)
            self.text_area.tag_bind(run_tag_name, "<Enter>", lambda e: self.text_area.configure(cursor="hand2"))
            self.text_area.tag_bind(run_tag_name, "<Leave>", lambda e: self.text_area.configure(cursor="arrow"))

            self.text_area.insert("end", "       >>> ", "CMD")
            self.text_area.insert("end", "[ Simülasyon ]", run_tag_name)
            self.text_area.insert("end", f" {exploit_data[:70]}...\n", "INFO") 
        else:
            self.text_area.insert("end", f"{log_content}\n", level)
        
        self.text_area.see("end")
        self.text_area.configure(state="disabled")
        
        if hasattr(app, 'update_risk_chart'): app.update_risk_chart(level)
        if hasattr(app, 'lbl_status_dot') and app.lbl_status_dot:
             status_text = "SCANNING" if "BAŞLATILIYOR" in message else "ACTIVE"
             if "TAMAMLANDI" in message or "Scan Completed" in message: status_text = "IDLE"
             app.lbl_status_dot.configure(text=f"● {status_text}", text_color=UI_CONSTANTS.COLOR_CYAN)

def add_threat_feed_item_func(app, category, level, message):
    if not hasattr(app, 'threat_feed_scroll'): return
    card = ThreatFeedCard(app.threat_feed_scroll, category, level, message)
    card.pack(fill="x", pady=3, padx=5)
    try: app.threat_feed_scroll._parent_canvas.yview_moveto(1.0)
    except: pass

def initialize_cards(app):
    """
    FAZ 41: Toplam 26 Modülün hepsini doğru sırada ve doğru görünürlükte ekler.
    """
    for widget in app.module_status_frame.winfo_children():
        widget.destroy()
    app.scanner_status_cards = {}
    
    # Faz 41: Tüm 26 Modülün Listesi (Log kayıtlarına göre güncellenmiş)
    # Bu listenin doğru olduğunu varsayıyoruz (Çünkü engine'de 26 modül var)
    full_module_keys = [
        'WAF_DETECT', 'SUBDOMAIN', 'SUBDOMAIN_TAKEOVER', 'PRE_SCAN', 'HEADERS', 'FILES', 
        'PORT_SCAN', 'HEURISTIC', 'AUTH_BYPASS', 'LFI', 'XSS', 'SQLI', 'IDOR', 'RCE_SSRF', 
        'JSON_API', 'CLOUD_EXPLOIT', 'REACT_EXPLOIT', 'NUCLEI', 'INTERNAL_SCAN', 
        'JS_ENDPOINT', 'GRAPHQL', 'CLIENT_LOGIC', 'HTTP_SMUGGLING', 'BUSINESS_LOGIC',
        'OSINT', 'LEAKAGE' 
    ]
    
    display_names = {
        'WAF_DETECT': 'WAF / FIREWALL',
        'SUBDOMAIN': 'SUBDOMAIN RECON',
        'SUBDOMAIN_TAKEOVER': 'SUBDOMAIN TAKEOVER',
        'PRE_SCAN': 'PARAM DISCOVERY',
        'HEADERS': 'HTTP HEADERS',
        'FILES': 'SENSITIVE FILES',
        'PORT_SCAN': 'PORT SCANNER',
        'HEURISTIC': 'HEURISTIC ENGINE',
        'AUTH_BYPASS': 'AUTH BYPASS',
        'LFI': 'LFI SCANNER',
        'XSS': 'XSS SCANNER',
        'SQLI': 'SQLI SCANNER',
        'IDOR': 'IDOR SCANNER',
        'RCE_SSRF': 'RCE / SSRF',
        'JSON_API': 'API FUZZER',
        'CLOUD_EXPLOIT': 'CLOUDSTORM',
        'REACT_EXPLOIT': 'REACT EXPLOIT',
        'NUCLEI': 'NUCLEI ENGINE', 
        'INTERNAL_SCAN': 'SYSTEM CORE',
        'JS_ENDPOINT': 'JS ENDPOINTS',
        'GRAPHQL': 'GRAPHQL SECURITY',
        'CLIENT_LOGIC': 'CLIENT LOGIC', 
        'HTTP_SMUGGLING': 'HTTP SMUGGLING',
        'BUSINESS_LOGIC': 'BUSINESS LOGIC',
        'OSINT': 'OSINT', 
        'LEAKAGE': 'DATA LEAKAGE' 
    }
    
    row_idx = 0
    for mod_key in full_module_keys:
        display_name = display_names.get(mod_key, mod_key.replace('_', ' '))
        # FAZ 41: ModuleStatusCard'a modül anahtarını da gönderiyoruz
        card_instance = ModuleStatusCard(app.module_status_frame, display_name, mod_key, app)
        # Kartın yerleşimindeki kaymayı engellemek için sadece 0. sütun kullan
        card_instance.grid(row=row_idx, column=0, sticky="ew", pady=(4, 0), padx=2)
        
        # FAZ 41: STATUS KARTININ İÇİNDEKİ WIDGET'LARI REFERANS AL
        app.scanner_status_cards[mod_key] = {
            'frame': card_instance,
            'dot': card_instance.status_dot, # status_dot
            'info': card_instance.info_label, # info_label
            'max_cvss': 0.0
        }
        row_idx += 1

def setup_dashboard_tab(app):
    tab = app.tab_dashboard
    tab.grid_columnconfigure(0, weight=0) 
    tab.grid_columnconfigure(1, weight=1) 
    tab.grid_columnconfigure(2, weight=0) 
    tab.grid_rowconfigure(3, weight=1) 
    
    # KRİTİK DÜZELTME: app.add_threat_feed_item için lambda fonksiyonu
    app.add_threat_feed_item = lambda c, l, m: add_threat_feed_item_func(app, c, l, m)
    app.last_active_card = None

    # HEADER (GÜNCELLENDİ: PARS MARKA KİMLİĞİ)
    header = ctk.CTkFrame(tab, fg_color="transparent")
    header.grid(row=0, column=0, columnspan=3, sticky="ew", pady=(15, 10), padx=20)
    # SYNARA SYSTEM -> PARS DASHBOARD
    ctk.CTkLabel(header, text=" PARS", font=ctk.CTkFont(family="Orbitron", size=32, weight="bold"), text_color=UI_CONSTANTS.COLOR_ACCENT).pack(side="left")
    # ULTIMATE SECURITY CORE -> SECURITY OPERATIONS CENTER
    ctk.CTkLabel(header, text="Pentest Autonomous Recon System", font=ctk.CTkFont(family="Consolas", size=14), text_color=UI_CONSTANTS.COLOR_CYAN).pack(side="left", padx=15, pady=12)

    # INPUT BAR
    input_bar = ctk.CTkFrame(tab, fg_color=UI_CONSTANTS.COLOR_SIDEBAR, corner_radius=8, border_width=1, border_color=UI_CONSTANTS.COLOR_TERMINAL_FRAME)
    input_bar.grid(row=1, column=0, columnspan=3, sticky="ew", padx=20, pady=(0, 20))
    input_bar.grid_columnconfigure(1, weight=1)
    app.input_bar = input_bar 

    ctk.CTkLabel(input_bar, text="TARGET:", font=ctk.CTkFont(weight="bold", size=13), text_color=UI_CONSTANTS.COLOR_CYAN).grid(row=0, column=0, padx=20, pady=15)
    app.entry_url = ctk.CTkEntry(input_bar, placeholder_text="https://target.com", height=40, width=300, border_color=UI_CONSTANTS.COLOR_TERMINAL_FRAME, fg_color=UI_CONSTANTS.COLOR_BG, text_color="white", font=("Consolas", 13))
    app.entry_url.grid(row=0, column=1, padx=10, pady=15, sticky="ew")
    app.entry_url.insert(0, "https://google-gruyere.appspot.com") 

    profile_names = list(SCAN_PROFILES.keys())
    app.profile_select = ctk.CTkOptionMenu(input_bar, values=profile_names, width=140, height=40, fg_color=UI_CONSTANTS.COLOR_BG, button_color=UI_CONSTANTS.COLOR_TERMINAL_FRAME, button_hover_color=UI_CONSTANTS.COLOR_ACCENT, text_color="white", dropdown_fg_color=UI_CONSTANTS.COLOR_SIDEBAR, font=("Roboto", 12))
    app.profile_select.set("BUG_BOUNTY_CORE") 
    app.profile_select.grid(row=0, column=2, padx=10, pady=15)

    app.btn_scan = ctk.CTkButton(input_bar, text="ENGAGE SYSTEM", height=40, width=150, font=ctk.CTkFont(weight="bold", size=14), fg_color=UI_CONSTANTS.COLOR_ACCENT, hover_color="#c71f45", corner_radius=6)
    app.btn_scan.grid(row=0, column=3, padx=20, pady=15)
    
    # LEFT PANEL (Modules)
    left_panel = ctk.CTkFrame(tab, fg_color="transparent", width=260, corner_radius=0)
    left_panel.grid(row=3, column=0, sticky="nsew", padx=(20, 10), pady=(0, 20))
    left_panel.grid_rowconfigure(1, weight=1)
    left_panel.grid_columnconfigure(0, weight=1)
    
    status_header = ctk.CTkFrame(left_panel, fg_color=UI_CONSTANTS.COLOR_SIDEBAR, corner_radius=6, height=35)
    status_header.grid(row=0, column=0, sticky="ew", pady=(0, 10))
    ctk.CTkLabel(status_header, text="MODULES STATUS", text_color=UI_CONSTANTS.COLOR_TEXT_SECONDARY, font=ctk.CTkFont(size=12, weight="bold")).pack(pady=8)
    
    app.module_status_frame = ctk.CTkScrollableFrame(left_panel, fg_color="transparent", corner_radius=0, width=240, scrollbar_button_color=UI_CONSTANTS.COLOR_TERMINAL_FRAME, scrollbar_button_hover_color=UI_CONSTANTS.COLOR_ACCENT)
    app.module_status_frame.grid(row=1, column=0, sticky="nsew")
    
    # CENTER PANEL (Terminal)
    app.terminal_outer_frame = ctk.CTkFrame(tab, fg_color=UI_CONSTANTS.COLOR_TERMINAL, corner_radius=8, border_width=1, border_color=UI_CONSTANTS.COLOR_ACCENT)
    app.terminal_outer_frame.grid(row=3, column=1, sticky="nsew", padx=5, pady=(0, 20))
    app.terminal_outer_frame.grid_rowconfigure(1, weight=1)
    app.terminal_outer_frame.grid_columnconfigure(0, weight=1)
    
    term_header = ctk.CTkFrame(app.terminal_outer_frame, height=30, fg_color=UI_CONSTANTS.COLOR_ACCENT, corner_radius=0)
    term_header.grid(row=0, column=0, sticky="ew")
    # SYSTEM CONSOLE -> PARS_CLI
    ctk.CTkLabel(term_header, text=" >_ PARS_CLI CONSOLE", font=ctk.CTkFont(family="Consolas", size=12, weight="bold"), text_color="#0b0c15").pack(side="left", padx=10)
    
    # KRİTİK DÜZELTME: RichConsole artık UI_CONSTANTS'ı kullanıyor
    app.console = RichConsole(app.terminal_outer_frame)
    app.console.grid(row=1, column=0, sticky="nsew", padx=2, pady=2)
    
    # RIGHT PANEL (Chart & Feed)
    right_panel = ctk.CTkFrame(tab, fg_color="transparent", width=260, corner_radius=0)
    right_panel.grid(row=3, column=2, sticky="nsew", padx=(10, 20), pady=(0, 20))
    right_panel.grid_rowconfigure(2, weight=1) 
    right_panel.grid_columnconfigure(0, weight=1)
    
    # HUD Frame (GÜNCELLENDİ: SecurityShieldHUD -> AIThreatVisualizer)
    app.chart_frame = ctk.CTkFrame(right_panel, fg_color=UI_CONSTANTS.COLOR_SIDEBAR, width=240, height=220, corner_radius=8, border_width=1, border_color=UI_CONSTANTS.COLOR_TERMINAL_FRAME)
    app.chart_frame.grid(row=0, column=0, sticky="ew", pady=(0, 15))
    app.chart_frame.pack_propagate(False) # Boyut sabitle
    
    # Canvas HUD (Değişiklik Burada)
    app.hud_panel = AIThreatVisualizer(app.chart_frame) # SecurityShieldHUD yerine AIThreatVisualizer
    app.hud_panel.pack(fill="both", expand=True)

    # Feed
    feed_header = ctk.CTkFrame(right_panel, fg_color=UI_CONSTANTS.COLOR_SIDEBAR, corner_radius=6, height=35)
    feed_header.grid(row=1, column=0, sticky="ew", pady=(0, 5))
    ctk.CTkLabel(feed_header, text="LIVE INTEL FEED", text_color=UI_CONSTANTS.COLOR_CYAN, font=ctk.CTkFont(size=11, weight="bold")).pack(pady=8)
    
    app.threat_feed_scroll = ctk.CTkScrollableFrame(right_panel, fg_color=UI_CONSTANTS.COLOR_TERMINAL, corner_radius=6, width=240, scrollbar_button_color=UI_CONSTANTS.COLOR_TERMINAL_FRAME, scrollbar_button_hover_color=UI_CONSTANTS.COLOR_ACCENT)
    app.threat_feed_scroll.grid(row=2, column=0, sticky="nsew")

    # Cloud modunda bu metodu çağırmaya gerek yok, log_welcome_message gui_cloud'da yok
    if hasattr(app, 'log_welcome_message'):
          app.log_welcome_message()
          
    initialize_cards(app)