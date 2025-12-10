# path: Test/gui_ai_analyst.py
# Synara AI Bilinci (AI Analyst) arayüzünü tanımlar.

import customtkinter as ctk
import threading
from typing import TYPE_CHECKING, Dict, Any

if TYPE_CHECKING:
    from .gui_main import MestegApp # Tip ipucu için

class AIAnalystConsole(ctk.CTkTextbox):
    """AI Analiz sonuçlarının gösterildiği terminal tarzı çıktı alanı."""
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.configure(
            state="disabled",
            wrap="word",
            text_color="white",
            fg_color=master.master.master.COLOR_TERMINAL,
            font=("Consolas", 12)
        )

def setup_ai_analyst_tab(app: "MestegApp"):
    """
    GUI'deki AI Analiz sekmesini ayarlar.
    """
    
    # 1. Ana Düzen
    tab = app.tab_view.add("🧠 BİLİNÇ ANALİZİ")
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
    app.after(100, lambda: app.append_to_ai_console("Merhaba Kaptan. Synara'nın Bilinci aktif. Soru veya analiz isteği için hazırım. Puanlama yorumu almak için taramayı başlatın veya buraya bir fikir yazın.", "AI_INFO"))

# --- Konsol Çıktı Yardımcı Metotları ---

def append_to_ai_console(app: "MestegApp", message: str, speaker: str):
    """AI konsoluna renkli metin ekler."""
    
    # Scroll'u tutmak için geçici olarak devreye al
    app.ai_console.configure(state="normal")
    
    # Konuşmacı Rengi
    if speaker == "USER":
        tag = "user_tag"
        prefix = f"\n[{app.scanner.start_time.strftime('%H:%M:%S')}] KAPTAN:\n"
    elif speaker == "AI_INFO":
        tag = "info_tag"
        prefix = f"\n[{app.scanner.start_time.strftime('%H:%M:%S')}] BİLİNÇ >:\n"
    else: # AI RESPONSE
        tag = "ai_tag"
        prefix = f"\n[{app.scanner.start_time.strftime('%H:%M:%S')}] SYNARA >:\n"
        
    # Renkleri tanımla (tekrar tekrar tanımlamamak için try/except)
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