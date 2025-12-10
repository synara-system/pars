# path: Test/gui_ai_analyst.py
# Synara AI Bilinci (AI Analyst) arayüzünü tanımlar.

import customtkinter as ctk
import threading
from typing import TYPE_CHECKING, Dict, Any
import tkinter as tk # tk.Text'in temelini kullandığı için
import datetime 
import os # Dosya kaydetme işlemi için eklendi

from core.scanners.base_scanner import BaseScanner 

if TYPE_CHECKING:
    from .gui_main import MestegApp # Tip ipucu için

# [YENİ]: AI Sistemi Persona dosya yolu
AI_SYSTEM_PERSONA_PATH = "core/ai_system_persona.txt"

def load_ai_system_persona() -> str:
    """AI'ın derin persona talimatlarını dosyadan yükler."""
    try:
        if not os.path.exists(AI_SYSTEM_PERSONA_PATH):
            return "Sistem talimatları dosyası bulunamadı. Lütfen AI'a genel bir danışman olarak cevap ver."
        with open(AI_SYSTEM_PERSONA_PATH, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        return f"Sistem talimatları yüklenirken hata oluştu: {e}. Lütfen AI'a genel bir danışman olarak cevap ver."

class AIAnalystConsole(ctk.CTkTextbox):
    """AI Analiz sonuçlarının gösterildiği terminal tarzı çıktı alanı."""
    def __init__(self, master, **kwargs):
        app = kwargs.pop('app', master.winfo_toplevel()) 
        super().__init__(master, **kwargs) 
        
        self.configure(
            state="disabled",
            wrap="word",
            text_color="#e2e8f0", # Daha yumuşak beyaz (Slate-200)
            font=("Consolas", 14) 
        )
        
        try:
            # Renkler kurumsal temaya uygun hale getirildi
            self.tag_config("user_tag", foreground=app.COLOR_ACCENT) # Operatör (Kırmızı/Accent)
            self.tag_config("ai_tag", foreground=app.COLOR_CYAN)     # AI (Cyan)
            self.tag_config("info_tag", foreground=app.COLOR_TEXT_SECONDARY) # Sistem (Gri)
            self.tag_config("critical_tag", foreground=app.COLOR_ERROR, font=("Consolas", 14, "bold"))
            self.tag_config("warning_tag", foreground=app.COLOR_WARNING, font=("Consolas", 14, "bold")) # Eklenmişti
        except:
            pass

def save_chat_log(app):
    """
    Mevcut sohbet geçmişini dosyaya kaydeder.
    """
    try:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"AI_Consultation_Log_{timestamp}.txt"
        
        # Reports klasörünü kontrol et
        if not os.path.exists("reports"):
            os.makedirs("reports")
            
        filepath = os.path.join("reports", filename)
        
        # Textbox içeriğini al
        chat_content = app.ai_console.get("1.0", "end")
        
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("--- PARS SECURITY OPS | AI CONSULTATION LOG ---\n")
            f.write(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("-" * 50 + "\n\n")
            f.write(chat_content)
            
        append_to_ai_console(app, f"Görüşme kayıtları başarıyla dışa aktarıldı: {filename}", "AI_INFO")
        
    except Exception as e:
        append_to_ai_console(app, f"Kayıt hatası: {str(e)}", "CRITICAL")

def clear_ai_consoles(app):
    """
    Hem ana sohbet konsolunu hem de özet konsolunu temizler.
    """
    if hasattr(app, 'ai_console') and app.ai_console:
        app.ai_console.configure(state="normal")
        app.ai_console.delete("1.0", "end")
        app.ai_console.configure(state="disabled")
    
    if hasattr(app, 'ai_summary_console') and app.ai_summary_console:
        app.ai_summary_console.configure(state="normal")
        app.ai_summary_console.delete("1.0", "end")
        app.ai_summary_console.configure(state="disabled")
        
    append_to_ai_console(app, "Konsol temizlendi. Yeni analiz oturumu başlatıldı.", "AI_INFO")
    
    # Konsol temizlendikten sonra sağ panele tekrar başlangıç mesajını ekle
    set_initial_summary_message(app)

def set_initial_summary_message(app):
    """Sağ panelin başlangıç mesajını ayarlar."""
    app.ai_summary_console.configure(state="normal")
    app.ai_summary_console.delete("1.0", "end")
    app.ai_summary_console.insert("end", "[BİLGİ] Otomatik Analiz Yönetim Paneli Aktif\n", "info_tag")
    app.ai_summary_console.insert("end", "\nBu panel, 'ANALİZ BAŞLAT' butonuna basıldıktan sonra, yürütülen siber güvenlik taramasının en kritik 5 bulgusunun özetini ve CVSS puanlarını gerçek zamanlı olarak gösterir.\n\nSYNARA AI'dan anlık durum bilgisi almak için lütfen sol paneldeki sohbeti kullanın.", "ai_tag")
    app.ai_summary_console.configure(state="disabled")


def setup_ai_analyst_tab(app: "MestegApp"):
    """
    GUI'deki AI Analiz sekmesini dashboard stili bir düzene (Chat + Özet) göre ayarlar.
    """
    
    tab = app.tab_ai_analyst 
    
    tab.grid_columnconfigure(0, weight=2) 
    tab.grid_columnconfigure(1, weight=1) 
    tab.grid_rowconfigure(1, weight=1)
    
    # --- ÜST KONTROL PANELİ ---
    control_frame = ctk.CTkFrame(tab, fg_color=app.COLOR_SIDEBAR, corner_radius=8)
    control_frame.grid(row=0, column=0, columnspan=2, padx=10, pady=(10, 5), sticky="ew")
    control_frame.grid_columnconfigure(0, weight=1)
    control_frame.grid_columnconfigure(1, weight=0) 
    control_frame.grid_columnconfigure(2, weight=0) 
    control_frame.grid_columnconfigure(3, weight=0) # Yeni buton için

    # Başlık (GÜNCELLENDİ: Kurumsal İsim)
    ctk.CTkLabel(
        control_frame, 
        text="SYNARA AI (Siber Güvenlik Danışmanı)", 
        font=ctk.CTkFont(size=14, weight="bold"),
        text_color=app.COLOR_CYAN
    ).grid(row=0, column=0, padx=15, pady=10, sticky="w")
    
    # Buton 1: Raporu Yorumla
    ctk.CTkButton(
        control_frame, 
        text="ANALİZ BAŞLAT", 
        command=lambda: threading.Thread(target=app.run_manual_analysis, daemon=True).start(),
        fg_color=app.COLOR_ACCENT,
        hover_color="#c71f45",
        text_color="white",
        width=120,
        height=32,
        font=ctk.CTkFont(weight="bold")
    ).grid(row=0, column=1, padx=(5, 5), pady=10, sticky="e")
    
    # [YENİ BUTON]: Sohbeti Kaydet
    ctk.CTkButton(
        control_frame, 
        text="LOG KAYDET", 
        command=lambda: save_chat_log(app),
        fg_color=app.COLOR_TERMINAL_FRAME,
        hover_color=app.COLOR_BG,
        text_color="white", 
        width=100,
        height=32,
        border_width=1,
        border_color=app.COLOR_ACCENT
    ).grid(row=0, column=2, padx=(5, 5), pady=10, sticky="e")

    # Buton 3: Temizle
    ctk.CTkButton(
        control_frame, 
        text="TEMİZLE", 
        command=lambda: clear_ai_consoles(app),
        fg_color=app.COLOR_TERMINAL_FRAME,
        hover_color="#334155",
        text_color=app.COLOR_TEXT_SECONDARY,
        width=80,
        height=32
    ).grid(row=0, column=3, padx=(5, 15), pady=10, sticky="e")
    
    # --- SOL SÜTUN: CANLI CHAT KONSOLU ---
    chat_frame = ctk.CTkFrame(tab, fg_color="transparent")
    chat_frame.grid(row=1, column=0, padx=(10, 5), pady=(0, 10), sticky="nsew")
    chat_frame.grid_columnconfigure(0, weight=1)
    chat_frame.grid_rowconfigure(0, weight=1)

    app.ai_console = AIAnalystConsole(chat_frame, app=app, fg_color=app.COLOR_TERMINAL)
    app.ai_console.grid(row=0, column=0, sticky="nsew")

    # Giriş Çubuğu
    input_frame = ctk.CTkFrame(chat_frame, fg_color="transparent")
    input_frame.grid(row=1, column=0, pady=(10, 0), sticky="ew")
    input_frame.grid_columnconfigure(0, weight=1)
    
    app.entry_ai_chat = ctk.CTkEntry(
        input_frame, 
        placeholder_text="Operatör komutu girin veya güvenlik danışmanına soru sorun...",
        fg_color=app.COLOR_TERMINAL_FRAME,
        border_color=app.COLOR_TERMINAL_FRAME,
        text_color="white",
        font=("Consolas", 12),
        height=40
    )
    app.entry_ai_chat.grid(row=0, column=0, padx=(0, 10), sticky="ew")
    
    btn_send = ctk.CTkButton(
        input_frame, 
        text="GÖNDER", 
        command=lambda: threading.Thread(target=app.run_ai_chat_thread, daemon=True).start(),
        fg_color=app.COLOR_ACCENT,
        hover_color="#c71f45",
        width=100,
        height=40,
        font=ctk.CTkFont(weight="bold")
    )
    btn_send.grid(row=0, column=1, sticky="e")
    
    app.entry_ai_chat.bind('<Return>', lambda event: threading.Thread(target=app.run_ai_chat_thread, daemon=True).start())
    
    # --- SAĞ SÜTUN: KRİTİK ANALİZ ÖZETİ ---
    summary_frame = ctk.CTkFrame(tab, fg_color=app.COLOR_SIDEBAR, corner_radius=8, border_width=1, border_color=app.COLOR_TERMINAL_FRAME)
    summary_frame.grid(row=1, column=1, padx=(5, 10), pady=(0, 10), sticky="nsew")
    summary_frame.grid_columnconfigure(0, weight=1)
    summary_frame.grid_rowconfigure(1, weight=1)

    ctk.CTkLabel(
        summary_frame, 
        text="KRİTİK BULGU ÖZETİ", 
        font=ctk.CTkFont(size=12, weight="bold"),
        text_color=app.COLOR_WARNING
    ).grid(row=0, column=0, padx=15, pady=(15, 5), sticky="w")
    
    # AIAnalystConsole sınıfı kullanıldı
    app.ai_summary_console = AIAnalystConsole(
        summary_frame,
        app=app, # Renk etiketleri için app nesnesini geçir
        state="disabled",
        wrap="word",
        fg_color=app.COLOR_BG, 
        font=("Consolas", 12) 
    )
    app.ai_summary_console.grid(row=1, column=0, padx=10, pady=(5, 15), sticky="nsew")

    # Özet konsoluna başlangıç mesajı eklendi
    app.after(100, lambda: set_initial_summary_message(app))
    
    # Sol konsol için başlangıç mesajı
    initial_ai_message = "Synara AI Modülü Aktif. En üst düzey siber uzmanlık bilinciyle size hizmet etmek için buradayım.\nLütfen taranan hedefle ilgili sorularınızı iletin veya 'ANALİZ BAŞLAT' butonunu kullanın."
    app.after(100, lambda: append_to_ai_console(app, initial_ai_message, "AI_INFO"))

# --- Konsol Çıktı Yardımcı Metotları ---

def _perform_console_update(app: "MestegApp", message: str, speaker: str, timestamp: str):
    """
    [YENİ GÜVENLİK FONKSİYONU] Tüm GUI manipülasyonlarını içerir. SADECE app.after() ile çağrılmalıdır.
    """
    
    # 1. Ana konsola mesajı bas
    app.ai_console.configure(state="normal")
    
    # Konuşmacı Rengi
    tag = "ai_tag" # Varsayılan
    prefix = f"\n[{timestamp}] SYNARA AI >:\n"
    
    if speaker == "USER":
        tag = "user_tag"
        prefix = f"\n[{timestamp}] OPERATÖR KOMUTU:\n" 
    elif speaker == "AI_INFO":
        tag = "info_tag"
        prefix = f"\n[{timestamp}] SYNARA SİSTEM BİLGİSİ >:\n"
    elif speaker == "CRITICAL":
         tag = "critical_tag"
         prefix = f"\n[{timestamp}] SİSTEM UYARISI >:\n"
    # AI_RESPONSE varsayılan kalır
        
    app.ai_console.insert("end", prefix, tag)
    app.ai_console.insert("end", message + "\n", tag)
    
    app.ai_console.see("end")
    app.ai_console.configure(state="disabled")
    
    # 2. Analiz raporu geldiğinde sağ paneli de güncelle
    if speaker == "AI_RESPONSE" or speaker == "AI_INFO": 
        
        # Kontrol edilecek kesin başlıklar
        is_analysis_report = any(keyword in message for keyword in [
            "SYNARA AI TARAMA ANALİZİ", 
            "--- MANUAL ANALYSIS:", 
            "KRİTİK ZAFİYETLER" 
        ])
        
        if is_analysis_report:
            # Sadece scanner nesnesi, results niteliği varsa ve results list ise işlem yap
            if (hasattr(app, 'scanner') and app.scanner and 
                hasattr(app.scanner, 'results') and isinstance(app.scanner.results, list) and 
                len(app.scanner.results) > 0): # Katı kontrol
                
                app.ai_summary_console.configure(state="normal")
                app.ai_summary_console.delete("1.0", "end") 

                # Başlık
                app.ai_summary_console.insert("end", f"[{timestamp}] KRİTİK ANALİZ ÖZETİ\n", "info_tag")
                app.ai_summary_console.insert("end", "=" * 30 + "\n", "info_tag")

                # En kritik 5 bulguyu sırala ve al
                critical_findings = sorted(
                    [res for res in app.scanner.results if res.get('cvss_score', 0.0) >= 5.0], 
                    key=lambda x: x.get('cvss_score', 0.0), reverse=True
                )[:5] 

                if critical_findings:
                    app.ai_summary_console.insert("end", "\n*** EN KRİTİK 5 BULGU (CVSS 5.0+) ***\n", "critical_tag")
                    
                    for i, res in enumerate(critical_findings):
                        # CVSS puanını al, yoksa seviyeye göre varsayılanı kullan
                        cvss_score = res.get('cvss_score', BaseScanner.CVSS_SCORES.get(res.get('level', 'LOW'), 0.0))
                        
                        # Detay mesajını kısalt
                        clean_message = res['message'].split(' [Exploit')[0].strip()
                        if len(clean_message) > 100:
                            clean_message = clean_message[:100] + "..."
                        
                        # Risk seviyesine göre renk etiketi belirle
                        tag_summary = "critical_tag" if cvss_score >= 9.0 else "warning_tag" if cvss_score >= 7.0 else "ai_tag"
                        
                        app.ai_summary_console.insert("end", f"\n[{i+1}] {res['category']} (Puan: {cvss_score:.1f})\n", tag_summary)
                        app.ai_summary_console.insert("end", f"    Detay: {clean_message}\n", "info_tag")
                else:
                    app.ai_summary_console.insert("end", "\nAnaliz tamamlandı. Kritik (CVSS 5.0+) seviyesinde bulgu tespit edilmedi.\n", "ai_tag")
                
                app.ai_summary_console.see("end")
                app.ai_summary_console.configure(state="disabled")
            else:
                 # Eğer sonuçlar gelmediyse, bilgilendirme mesajı ver (Boş kalmasını önler)
                 app.ai_summary_console.configure(state="normal")
                 app.ai_summary_console.delete("1.0", "end")
                 app.ai_summary_console.insert("end", "\n[BİLGİ] Analiz metni geldi ancak işlenecek tarama sonuç verisi (app.scanner.results) boş veya geçersiz.\n", "info_tag")
                 app.ai_summary_console.configure(state="disabled")

def append_to_ai_console(app: "MestegApp", message: str, speaker: str):
    """
    [THREAD-SAFE] AI konsoluna renkli metin ekler. 
    Tüm GUI güncellemelerini ana iş parçacığına yönlendirir.
    """
    
    timestamp = datetime.datetime.now().strftime('%H:%M:%S')
    
    # Zaman damgasını anahtar bilgi olarak al
    if app.scanner and app.scanner.start_time:
         if isinstance(app.scanner.start_time, datetime.datetime):
             timestamp = app.scanner.start_time.strftime('%H:%M:%S')

    # GUI manipülasyonunu ana iş parçacığına gönder
    app.after(0, lambda: _perform_console_update(app, message, speaker, timestamp))