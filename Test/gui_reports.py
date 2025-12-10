# path: Test/gui_reports.py

import customtkinter as ctk
from tkinter import messagebox, simpledialog
import os
import glob
import webbrowser
from urllib.parse import urlparse
import re
import time
import threading

# --- SYNARA GX / NEON SPACE TEMASI ---
COLOR_BG = "#0b0c15"           
COLOR_SIDEBAR = "#141526"      
COLOR_ACCENT = "#fa1e4e"       
COLOR_CYAN = "#00fff5"         
COLOR_PURPLE = "#a855f7"       
COLOR_SUCCESS = "#00e676"      
COLOR_ERROR = "#ff2a6d"        
COLOR_WARNING = "#ffcc00"      
COLOR_TERMINAL = "#0b0c15"     
COLOR_TERMINAL_FRAME = "#2d2e42" 
COLOR_TEXT_PRIMARY = "#ffffff"
COLOR_TEXT_SECONDARY = "#a0a0b5" 

# --- PERFORMANS VE DURUM DEĞİŞKENLERİ ---
SEARCH_FILTER = ""
CURRENT_PAGE = 1
ITEMS_PER_PAGE = 8 # Kartlar büyüdüğü için sayfa başına adet düşürüldü
REPORT_CACHE = {}  # {filepath: {'mtime': float, 'data': dict}}
SORT_OPTION = "DATE (NEWEST)" # Varsayılan sıralama

def _get_risk_color(score):
    """Skora göre renk döndürür."""
    if score >= 9.0: return COLOR_ERROR
    if score >= 7.0: return "#ff6b00" # Orange
    if score >= 4.0: return COLOR_WARNING
    if score > 0.0: return COLOR_SUCCESS
    return COLOR_TEXT_SECONDARY

def _extract_report_data(file_path):
    """
    [CACHE DESTEKLİ] Rapor verilerini çıkarır. 
    Dosya değişmediyse diskten okumaz, hafızadan getirir.
    """
    global REPORT_CACHE
    
    if not os.path.exists(file_path):
        return None

    try:
        current_mtime = os.path.getmtime(file_path)
        
        # Cache kontrolü
        if file_path in REPORT_CACHE:
            cached = REPORT_CACHE[file_path]
            if cached['mtime'] == current_mtime:
                return cached['data']
        
        # Cache yoksa veya dosya değişmişse oku
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        score_match = re.search(r'<div class="score-circle"[^>]*>\s*(\d+)\s*</div>', content)
        if not score_match: 
             score_match = re.search(r'<div class="score-circle" id="security-score">\s*<span[^>]*>(\d+)</span>', content)
        score = int(score_match.group(1)) if score_match else 0
        
        results_match = re.search(r'TESPİT EDİLEN BULGULAR \((.*?)\)', content)
        if not results_match:
            results_match = re.search(r'Tespit Edilen Sonuçlar \((.*?)\ Adet\)', content)
        total_results = int(results_match.group(1)) if results_match and results_match.group(1).isdigit() else 0

        target_match = re.search(r'<span class="meta-label">TARGET</span>\s*<span class="meta-value">\s*(.*?)\s*</span>', content, re.DOTALL)
        if not target_match:
             target_match = re.search(r'Hedef: <strong>(.*?)</strong>', content)
        target_url = target_match.group(1).strip() if target_match else "Bilinmiyor"
        
        cvss_match = re.search(r'TOPLAM CVSS ETKİSİ</span>\s*<span[^>]*>\s*([\d\.]+)\s*</span>', content, re.DOTALL)
        if not cvss_match:
             cvss_match = re.search(r'Toplam CVSS Etkisi: \*\*([\d\.]+)\*\*</p>', content)
        total_cvss_score = float(cvss_match.group(1)) if cvss_match else 0.0

        data = {
            'score': score,
            'total_results': total_results,
            'target_url': target_url,
            'total_cvss_score': total_cvss_score
        }
        
        # Cache'e kaydet
        REPORT_CACHE[file_path] = {'mtime': current_mtime, 'data': data}
        return data

    except Exception:
        return None

def send_report_email(app, file_path, target_display):
    """Raporu müşteriye e-posta ile gönderme işlemini simüle eder."""
    dialog = ctk.CTkInputDialog(text=f"Sending report for: {target_display}\nEnter Client Email:", title="SECURE TRANSMISSION")
    email = dialog.get_input()
    
    if email:
        app.log_to_gui(f"[MAIL] Initiating encrypted transmission to {email}...", "INFO")
        
        def _send_process():
            time.sleep(1.5) 
            app.log_to_gui(f"[MAIL] Uploading {os.path.basename(file_path)}...", "INFO")
            time.sleep(1.5)
            app.log_to_gui(f"[MAIL] Transmission Complete. Report delivered to {email}.", "SUCCESS")
            messagebox.showinfo("Mission Success", f"Report successfully sent to {email}")
            
        threading.Thread(target=_send_process, daemon=True).start()

def delete_report_wrapper(app, file_path):
    """Silme işlemini yapar ve ARDINDAN listeyi zorla yeniler."""
    app.delete_report(file_path)
    # Cache'den de sil
    if file_path in REPORT_CACHE:
        del REPORT_CACHE[file_path]
    refresh_reports(app)

def create_report_card(app, file_path, report_data):
    """
    Tek bir rapor için GELİŞMİŞ NEON kart oluşturur.
    Özellikler: Progress Bar, Hover Efekti, Detaylı Metadatalar.
    """
    filename = os.path.basename(file_path)
    base_name = os.path.splitext(filename)[0]
    
    target_display = "UNKNOWN TARGET"
    risk_score = 0.0
    
    if report_data:
        if report_data.get('target_url') and report_data['target_url'] != "Bilinmiyor":
            parsed = urlparse(report_data['target_url'])
            target_display = parsed.netloc if parsed.netloc else report_data['target_url']
        
        if 'total_cvss_score' in report_data:
            risk_score = report_data['total_cvss_score']
    else:
        try:
            parts = base_name.split('_')
            if len(parts) > 2:
                target_display = ".".join(parts[:-2])
        except: pass

    # Tarih Formatlama
    parts = base_name.split('_')
    formatted_date = "N/A"
    if len(parts) >= 2:
        timestamp_part = parts[-1] 
        date_part = parts[-2]
        if len(timestamp_part) == 6 and len(date_part) == 8:
            formatted_date = f"{date_part[6:8]}.{date_part[4:6]}.{date_part[0:4]} | {timestamp_part[0:2]}:{timestamp_part[2:4]}"
    
    report_type = "PDF" if filename.endswith(".pdf") else "HTML"
    risk_color = _get_risk_color(risk_score)
    border_col = risk_color if report_type == "HTML" else COLOR_CYAN
    
    # --- KART ÇERÇEVESİ ---
    card = ctk.CTkFrame(app.reports_scroll, fg_color=COLOR_SIDEBAR, corner_radius=8, 
                        border_width=2, border_color=COLOR_TERMINAL_FRAME) # Varsayılan border gri
    card.pack(fill="x", pady=6, padx=8)
    
    # HOVER EFFECT LOGIC
    def on_enter(e):
        card.configure(border_color=border_col)
    def on_leave(e):
        card.configure(border_color=COLOR_TERMINAL_FRAME)
    
    card.bind("<Enter>", on_enter)
    card.bind("<Leave>", on_leave)
    
    # --- SOL: İKON ---
    icon_text = "🌐" if report_type == "HTML" else "📄"
    icon_lbl = ctk.CTkLabel(card, text=icon_text, font=ctk.CTkFont(size=28), text_color=border_col)
    icon_lbl.pack(side="left", padx=20, pady=15)
    # Icon'a da hover bind edelim ki kaybolmasın
    icon_lbl.bind("<Enter>", on_enter)
    icon_lbl.bind("<Leave>", on_leave)

    # --- ORTA: BİLGİ VE PROGRESS BAR ---
    info_frame = ctk.CTkFrame(card, fg_color="transparent")
    info_frame.pack(side="left", fill="both", expand=True, pady=10)
    info_frame.bind("<Enter>", on_enter)
    info_frame.bind("<Leave>", on_leave)

    ctk.CTkLabel(info_frame, text=target_display.upper(), 
                 font=ctk.CTkFont(family="Orbitron", size=14, weight="bold"), text_color="white").pack(anchor="w")
    
    meta_text = f"TYPE: {report_type}  |  DATE: {formatted_date}"
    ctk.CTkLabel(info_frame, text=meta_text, font=ctk.CTkFont(family="Consolas", size=11), text_color=COLOR_TEXT_SECONDARY).pack(anchor="w", pady=(2, 5))

    # [YENİ] Risk Progress Bar
    if risk_score > 0:
        progress_val = min(risk_score / 10.0, 1.0)
        progress_bar = ctk.CTkProgressBar(info_frame, width=200, height=6, progress_color=risk_color, fg_color="#1a1b26")
        progress_bar.set(progress_val)
        progress_bar.pack(anchor="w", pady=(2, 0))

    # --- SAĞ: RİSK ROZETİ VE BUTONLAR ---
    right_frame = ctk.CTkFrame(card, fg_color="transparent")
    right_frame.pack(side="right", padx=10)
    right_frame.bind("<Enter>", on_enter)
    right_frame.bind("<Leave>", on_leave)

    if risk_score > 0:
        badge = ctk.CTkFrame(right_frame, fg_color=risk_color, corner_radius=12, height=24)
        badge.pack(side="top", anchor="e", pady=(0, 5))
        ctk.CTkLabel(badge, text=f"RISK: {risk_score:.1f}", font=ctk.CTkFont(family="Roboto", size=11, weight="bold"), 
                     text_color="black").pack(padx=10, pady=2)

    btn_frame = ctk.CTkFrame(right_frame, fg_color="transparent")
    btn_frame.pack(side="bottom", anchor="e")

    # Butonlara hover eklemeye gerek yok, kendi hoverları var
    ctk.CTkButton(btn_frame, text="✉", width=35, height=30, 
                  fg_color=COLOR_TERMINAL_FRAME, hover_color=COLOR_PURPLE,
                  command=lambda: send_report_email(app, file_path, target_display)).pack(side="left", padx=2)

    ctk.CTkButton(btn_frame, text="OPEN", width=60, height=30, 
                  fg_color=COLOR_ACCENT if report_type=="HTML" else COLOR_CYAN, 
                  hover_color="white", text_color="black", font=ctk.CTkFont(weight="bold"),
                  command=lambda p=file_path: webbrowser.open(f"file://{p}")).pack(side="left", padx=2)
    
    ctk.CTkButton(btn_frame, text="🗑", width=35, height=30, 
                  fg_color=COLOR_TERMINAL_FRAME, hover_color=COLOR_ERROR, text_color=COLOR_ERROR,
                  command=lambda p=file_path: delete_report_wrapper(app, p)).pack(side="left", padx=2)

    return 1 

def update_stats_dashboard(app, total_files, avg_score, total_vulns):
    if hasattr(app, 'lbl_stat_total'):
        app.lbl_stat_total.configure(text=str(total_files))
        app.lbl_stat_score.configure(text=f"{avg_score:.1f}")
        app.lbl_stat_vulns.configure(text=str(total_vulns))

def change_page(app, delta):
    global CURRENT_PAGE
    CURRENT_PAGE += delta
    if CURRENT_PAGE < 1: CURRENT_PAGE = 1
    refresh_reports(app)

def on_sort_change(choice):
    """Sıralama değiştiğinde tetiklenir."""
    global SORT_OPTION, CURRENT_PAGE
    SORT_OPTION = choice
    CURRENT_PAGE = 1 # Sıralama değişince başa dön
    # App referansına doğrudan erişemediğimiz için trick yapmıyoruz,
    # Dropdown command parametresi sadece string döndürür.
    # Bu yüzden refresh_reports'u app üzerinden çağırmamız lazım.
    # Global bir event sistemi olmadığı için bu fonksiyonu setup içinde lambda ile bağlayacağız.
    pass 

def refresh_reports(app):
    """
    Rapor listesini yeniler. (PERFORMANS + SORTING + PAGINATION)
    """
    global CURRENT_PAGE, SORT_OPTION
    
    if hasattr(app, 'reports_scroll'):
        for widget in app.reports_scroll.winfo_children():
            widget.destroy()

    report_dir = os.path.join(os.getcwd(), "reports")
    if not os.path.exists(report_dir):
        os.makedirs(report_dir)

    html_files = glob.glob(os.path.join(report_dir, "*.html"))
    pdf_files = glob.glob(os.path.join(report_dir, "*.pdf"))
    all_files = html_files + pdf_files

    # 1. Veri Çıkarma & Filtreleme
    valid_items = [] # (file_path, report_data)
    
    total_score_sum = 0
    score_count = 0
    total_vulns_sum = 0
    
    report_names = ["SELECT DATA SOURCE"]
    unique_base_names = set()

    for file_path in all_files:
        data = None
        display_name = os.path.basename(file_path)
        
        if file_path.endswith(".html"):
            data = _extract_report_data(file_path) # CACHED READ
            if data:
                total_score_sum += data['score']
                score_count += 1
                total_vulns_sum += data['total_results']
                if data.get('target_url') and data['target_url'] != "Bilinmiyor":
                    try:
                        display_name = urlparse(data['target_url']).netloc or data['target_url']
                    except: pass
        
        if SEARCH_FILTER:
            if SEARCH_FILTER.lower() not in display_name.lower() and SEARCH_FILTER.lower() not in os.path.basename(file_path).lower():
                continue
                
        valid_items.append((file_path, data))
        
        # Dropdown listesi
        base_name = os.path.splitext(os.path.basename(file_path))[0]
        try:
             parts = base_name.split('_')
             if len(parts) > 2:
                 dd_name = f"{parts[-2]} - {'.'.join(parts[:-2])}"
             else:
                 dd_name = base_name
             if dd_name not in unique_base_names:
                unique_base_names.add(dd_name)
        except: pass

    # 2. SIRALAMA (SORTING) MANTIĞI [YENİ]
    if SORT_OPTION == "DATE (NEWEST)":
        valid_items.sort(key=lambda x: os.path.getmtime(x[0]), reverse=True)
    elif SORT_OPTION == "DATE (OLDEST)":
        valid_items.sort(key=lambda x: os.path.getmtime(x[0]), reverse=False)
    elif SORT_OPTION == "RISK (HIGHEST)":
        # Data varsa skora göre, yoksa 0
        valid_items.sort(key=lambda x: x[1]['total_cvss_score'] if x[1] else 0, reverse=True)
    elif SORT_OPTION == "RISK (LOWEST)":
        valid_items.sort(key=lambda x: x[1]['total_cvss_score'] if x[1] else 0, reverse=False)
    elif SORT_OPTION == "NAME (A-Z)":
        valid_items.sort(key=lambda x: os.path.basename(x[0]), reverse=False)

    # 3. İstatistikleri Güncelle
    avg_score = total_score_sum / score_count if score_count > 0 else 0
    update_stats_dashboard(app, score_count, avg_score, total_vulns_sum)
    
    # 4. Sayfalama
    total_items = len(valid_items)
    max_pages = (total_items // ITEMS_PER_PAGE) + (1 if total_items % ITEMS_PER_PAGE > 0 else 0)
    if max_pages == 0: max_pages = 1
    
    if CURRENT_PAGE > max_pages: CURRENT_PAGE = max_pages
    if CURRENT_PAGE < 1: CURRENT_PAGE = 1
    
    start_idx = (CURRENT_PAGE - 1) * ITEMS_PER_PAGE
    end_idx = start_idx + ITEMS_PER_PAGE
    
    page_items = valid_items[start_idx:end_idx]
    
    # 5. Kartları Oluştur
    if hasattr(app, 'reports_scroll'):
        for f_path, r_data in page_items:
            create_report_card(app, f_path, r_data)
            
        if not page_items:
             msg = "NO MATCHING INTEL FOUND" if SEARCH_FILTER else "NO ARCHIVED INTELLIGENCE FOUND"
             ctk.CTkLabel(app.reports_scroll, text=msg, text_color=COLOR_TEXT_SECONDARY, font=ctk.CTkFont(family="Orbitron", size=14)).pack(pady=60)

    # 6. Kontrolleri Güncelle
    if hasattr(app, 'lbl_page_info'):
        app.lbl_page_info.configure(text=f"PAGE {CURRENT_PAGE} / {max_pages}")
        
    if hasattr(app, 'btn_prev'):
        app.btn_prev.configure(state="normal" if CURRENT_PAGE > 1 else "disabled")
    
    if hasattr(app, 'btn_next'):
        app.btn_next.configure(state="normal" if CURRENT_PAGE < max_pages else "disabled")

    if hasattr(app, 'report_select_1') and hasattr(app, 'report_select_2'):
        report_names.extend(sorted(list(unique_base_names), reverse=True))
        app.report_select_1.configure(values=report_names)
        app.report_select_2.configure(values=report_names)

def on_search_change(app, event=None):
    global SEARCH_FILTER, CURRENT_PAGE
    SEARCH_FILTER = app.search_entry.get()
    CURRENT_PAGE = 1 
    refresh_reports(app)

def setup_reports_tab(app):
    """Rapor Geçmişi sekmesini kurar (Neon Portal Layout V3 - Ultimate)."""
    app.refresh_reports = lambda: refresh_reports(app)

    tab = app.tab_reports
    tab.grid_columnconfigure(0, weight=1)
    tab.grid_rowconfigure(2, weight=1) 
    tab.grid_rowconfigure(3, weight=0)

    # --- ROW 0: STATS ---
    stats_frame = ctk.CTkFrame(tab, fg_color=COLOR_SIDEBAR, corner_radius=12, border_width=1, border_color=COLOR_TERMINAL_FRAME)
    stats_frame.grid(row=0, column=0, sticky="ew", pady=(15, 15), padx=15)
    
    stats = [("TOTAL SCANS", COLOR_CYAN, 'lbl_stat_total'), ("AVG RISK SCORE", COLOR_ACCENT, 'lbl_stat_score'), ("DETECTED THREATS", COLOR_WARNING, 'lbl_stat_vulns')]
    for title, color, attr_name in stats:
        box = ctk.CTkFrame(stats_frame, fg_color=COLOR_BG, corner_radius=8, border_width=1, border_color="#1a1b26")
        box.pack(side="left", padx=20, pady=15, expand=True, fill="both")
        ctk.CTkLabel(box, text=title, font=ctk.CTkFont(family="Roboto", size=10, weight="bold"), text_color=COLOR_TEXT_SECONDARY).pack(pady=(10,0))
        lbl = ctk.CTkLabel(box, text="0", font=ctk.CTkFont(family="Orbitron", size=28, weight="bold"), text_color=color)
        lbl.pack(pady=(0,10))
        setattr(app, attr_name, lbl)

    # --- ROW 1: SEARCH & SORT ---
    action_frame = ctk.CTkFrame(tab, fg_color="transparent")
    action_frame.grid(row=1, column=0, sticky="ew", pady=(0, 15), padx=15)

    # Search
    search_icon_lbl = ctk.CTkLabel(action_frame, text="🔍", font=ctk.CTkFont(size=16))
    search_icon_lbl.pack(side="left", padx=(5,5))

    app.search_entry = ctk.CTkEntry(action_frame, placeholder_text="Search Reports...", width=250, height=40,
                                    border_color=COLOR_TERMINAL_FRAME, fg_color=COLOR_SIDEBAR, text_color="white", corner_radius=20)
    app.search_entry.pack(side="left", padx=(0, 15))
    app.search_entry.bind("<KeyRelease>", lambda event: on_search_change(app, event))

    # [YENİ] Sort Dropdown
    sort_options = ["DATE (NEWEST)", "DATE (OLDEST)", "RISK (HIGHEST)", "RISK (LOWEST)", "NAME (A-Z)"]
    
    def _update_sort(choice):
        global SORT_OPTION, CURRENT_PAGE
        SORT_OPTION = choice
        CURRENT_PAGE = 1
        refresh_reports(app)

    sort_menu = ctk.CTkOptionMenu(action_frame, values=sort_options, width=160, height=35,
                                  fg_color=COLOR_SIDEBAR, button_color=COLOR_TERMINAL_FRAME,
                                  button_hover_color=COLOR_ACCENT, text_color="white",
                                  command=_update_sort)
    sort_menu.pack(side="left", padx=5)
    sort_menu.set("DATE (NEWEST)")

    # Right Buttons
    ctk.CTkButton(action_frame, text="📂 FOLDER", width=100, height=35, fg_color=COLOR_SIDEBAR, border_color=COLOR_PURPLE, border_width=1,
                     font=ctk.CTkFont(weight="bold"), hover_color="#4a148c", text_color=COLOR_PURPLE,
                     command=app.open_reports_folder).pack(side="right", padx=5)

    ctk.CTkButton(action_frame, text="↻ REFRESH", width=100, height=35, fg_color=COLOR_SIDEBAR, border_color=COLOR_CYAN, border_width=1,
                     font=ctk.CTkFont(weight="bold"), hover_color="#006064", text_color=COLOR_CYAN,
                     command=lambda: refresh_reports(app)).pack(side="right", padx=5)

    # --- ROW 2: LIST ---
    app.reports_scroll = ctk.CTkScrollableFrame(tab, fg_color="transparent", scrollbar_button_color=COLOR_TERMINAL_FRAME, scrollbar_button_hover_color=COLOR_ACCENT)
    app.reports_scroll.grid(row=2, column=0, sticky="nsew", padx=10, pady=(0, 10)) 
    
    # --- ROW 3: PAGINATION ---
    pag_frame = ctk.CTkFrame(tab, fg_color="transparent", height=40)
    pag_frame.grid(row=3, column=0, sticky="ew", pady=(0, 15), padx=15)
    
    app.btn_prev = ctk.CTkButton(pag_frame, text="< PREV", width=80, height=30, fg_color=COLOR_TERMINAL_FRAME, 
                                 command=lambda: change_page(app, -1))
    app.btn_prev.pack(side="left", padx=10)
    
    app.lbl_page_info = ctk.CTkLabel(pag_frame, text="PAGE 1 / 1", font=ctk.CTkFont(family="Consolas", weight="bold"), text_color=COLOR_CYAN)
    app.lbl_page_info.pack(side="left", expand=True) 
    
    app.btn_next = ctk.CTkButton(pag_frame, text="NEXT >", width=80, height=30, fg_color=COLOR_TERMINAL_FRAME, 
                                 command=lambda: change_page(app, 1))
    app.btn_next.pack(side="right", padx=10)

    refresh_reports(app)