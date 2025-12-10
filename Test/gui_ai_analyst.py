# path: Test/ui_ai_analyst.py
# Synara AI Bilinci (AI Analyst) arayüzünü tanımlar.

import customtkinter as ctk
import threading
from typing import TYPE_CHECKING, Dict, Any
import datetime # Timestamp için eklendi

if TYPE_CHECKING:
    from .gui_main import MestegApp # Tip ipucu için

class AIAnalystConsole(ctk.CTkTextbox):
    """AI Analiz sonuçlarının gösterildiği terminal tarzı çıktı alanı."""
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        
        # Varsayılan renk
        bg_color = "#0b0c15"
        
        # Renk hatasını önlemek için güvenli erişim
        try:
             app = master.winfo_toplevel()
             if hasattr(app, 'COLOR_TERMINAL'):
                 bg_color = app.COLOR_TERMINAL
        except:
            pass

        self.configure(
            state="disabled",
            wrap="word",
            text_color="white",
            fg_color=bg_color,
            font=("Consolas", 12)
        )

def setup_ai_analyst_tab(app):
    """
    GUI'deki AI Analiz sekmesini ayarlar.
    Hem Cloud (Frame bazlı) hem Desktop (Tabview bazlı) uyumludur.
    """
    
    # --- KRİTİK DÜZELTME: Hibrit Sekme Yönetimi ---
    # CloudMestegApp (Bulut) -> app.tab_ai_analyst (Frame) kullanır.
    # MestegApp (Masaüstü) -> app.tab_view (Tabview) kullanır.
    
    tab = None

    # 1. Cloud Modu Kontrolü (Senin gui_cloud.py yapın)
    if hasattr(app, 'tab_ai_analyst') and app.tab_ai_analyst is not None:
        tab = app.tab_ai_analyst
    
    # 2. Desktop Modu Kontrolü (Eski gui_main.py yapısı)
    elif hasattr(app, 'tab_view') and app.tab_view is not None:
        try:
            tab = app.tab_view.add("🧠 BİLİNÇ ANALİZİ")
        except ValueError:
            # Sekme zaten varsa onu getir
            tab = app.tab_view.tab("🧠 BİLİNÇ ANALİZİ")
            
    # 3. Fallback (Hata Önleyici - Hiçbiri yoksa)
    if tab is None:
        if hasattr(app, 'main_content_area'):
             tab = ctk.CTkFrame(app.main_content_area)
             tab.pack(fill="both", expand=True)
        else:
             # En kötü ihtimalle ana pencereye ekle
             tab = ctk.CTkFrame(app)
             tab.pack(fill="both", expand=True)

    # Grid yapılandırması
    tab.grid_columnconfigure(0, weight=1)
    tab.grid_rowconfigure(1, weight=1)
    
    # 2. Üst Kontrol Çerçevesi (Chat Arayüzü/Başlık)
    control_frame = ctk.CTkFrame(tab, fg_color=app.COLOR_SIDEBAR, corner_radius=8)
    control_frame.grid(row=0, column=0, padx=10, pady=(10, 5), sticky="ew")
    control_frame.grid_columnconfigure(0, weight=1)
    
    # Başlık
    ctk.CTkLabel(
        control_frame, 
        text="SYNARA AKIL HOCASI (Gemini Destekli)", 
        font=ctk.CTkFont(size=14, weight="bold"),
        text_color=app.COLOR_CYAN
    ).grid(row=0, column=0, padx=15, pady=10, sticky="w")
    
    # 3. Yorum Konsolu (AI Çıktısı)
    app.ai_console = AIAnalystConsole(tab)
    app.ai_console.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="nsew")

    # 4. Giriş Çubuğu (Kullanıcı Sohbeti)
    input_frame = ctk.CTkFrame(tab, fg_color="transparent")
    input_frame.grid(row=2, column=0, padx=10, pady=(0, 10), sticky="ew")
    input_frame.grid_columnconfigure(0, weight=1)
    
    app.entry_ai_chat = ctk.CTkEntry(
        input_frame, 
        placeholder_text="Sistemin bilinç seviyesiyle sohbet et...",
        fg_color=app.COLOR_TERMINAL_FRAME,
        border_color=app.COLOR_TERMINAL_FRAME,
        text_color="white",
        font=("Consolas", 12)
    )
    app.entry_ai_chat.grid(row=0, column=0, padx=(0, 10), sticky="ew")
    
    btn_send = ctk.CTkButton(
        input_frame, 
        text="GÖNDER", 
        command=lambda: threading.Thread(target=app.run_ai_chat_thread, daemon=True).start(),
        fg_color=app.COLOR_ACCENT,
        hover_color="#c71f45",
        width=100
    )
    btn_send.grid(row=0, column=1, sticky="e")
    
    app.entry_ai_chat.bind('<Return>', lambda event: threading.Thread(target=app.run_ai_chat_thread, daemon=True).start())
    
    # Başlangıç mesajını göster
    initial_msg = "Merhaba Kaptan. Synara'nın Bilinci aktif. Soru veya analiz isteği için hazırım. Puanlama yorumu almak için taramayı başlatın veya buraya bir fikir yazın."
    
    # Güvenli çağrı: app'in append_to_ai_console metodu varsa onu kullan
    if hasattr(app, 'append_to_ai_console'):
         # Metod ise self otomatik gider
         app.after(100, lambda: app.append_to_ai_console(initial_msg, "AI_INFO"))
    else:
         # Fonksiyon ise app parametresi verilir
         app.after(100, lambda: append_to_ai_console(app, initial_msg, "AI_INFO"))

# --- Konsol Çıktı Yardımcı Metotları ---

def append_to_ai_console(app, message: str, speaker: str):
    """AI konsoluna renkli metin ekler."""
    if not hasattr(app, 'ai_console') or app.ai_console is None:
        return

    # Scroll'u tutmak için geçici olarak devreye al
    app.ai_console.configure(state="normal")
    
    # Zaman damgası (Hata korumalı)
    timestamp = "00:00:00"
    
    # Scanner varsa onun zamanını, yoksa şimdiki zamanı al (Cloud modunda scanner olmayabilir)
    if hasattr(app, 'scanner') and app.scanner and hasattr(app.scanner, 'start_time') and app.scanner.start_time:
        try:
            timestamp = app.scanner.start_time.strftime('%H:%M:%S')
        except:
            timestamp = datetime.datetime.now().strftime('%H:%M:%S')
    else:
        timestamp = datetime.datetime.now().strftime('%H:%M:%S')

    # Konuşmacı Rengi
    if speaker == "USER":
        tag = "user_tag"
        prefix = f"\n[{timestamp}] KAPTAN:\n"
    elif speaker == "AI_INFO":
        tag = "info_tag"
        prefix = f"\n[{timestamp}] BİLİNÇ >:\n"
    else: # AI RESPONSE
        tag = "ai_tag"
        prefix = f"\n[{timestamp}] SYNARA >:\n"
        
    # Renkleri tanımla
    try:
        app.ai_console.tag_config("user_tag", foreground=app.COLOR_PURPLE)
        app.ai_console.tag_config("ai_tag", foreground=app.COLOR_CYAN)
        app.ai_console.tag_config("info_tag", foreground=app.COLOR_TEXT_SECONDARY)
    except:
        pass
        
    app.ai_console.insert("end", prefix, tag)
    app.ai_console.insert("end", message + "\n", tag)
    
    # Aşağı kaydır ve devre dışı bırak
    app.ai_console.see("end")
    app.ai_console.configure(state="disabled")