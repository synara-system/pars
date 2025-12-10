# path: core/report_manager.py

import customtkinter as ctk
import os
import re
import tkinter as tk # tk.Text widget'ları için
from urllib.parse import urlparse
from colorsys import rgb_to_hsv, hsv_to_rgb # Renk geçişleri için eklendi

# Renk Paleti (Liquid Glass/Aero Simulasyonu) - synara_gui_v2.py ile senkronize edildi
COLOR_BG = "#0D1117"        # Vanta Black / Derin Arka Plan
COLOR_SIDEBAR = "#1F2937"   # Mat Slate (Liquid Glass Yüzeyi)
COLOR_ACCENT = "#3b82f6"    # Blue 500 (Vurgu)
COLOR_SUCCESS = "#22c55e"   # Green 500
COLOR_ERROR = "#ef4444"     # Red 500
COLOR_WARNING = "#eab308"   # Yellow 500
COLOR_TEXT_SECONDARY = "#94a3b8" # Gri-Mavi

class ReportManager:
    """
    GUI'den çağrılan, rapor dosyalarından veri çekme ve karşılaştırma penceresi
    gibi rapor yönetimi işlevlerini barındırır.
    """
    
    @staticmethod
    def extract_report_data(report_base_name):
        """
        Verilen temel rapor adından (Synara_Scan_YYYYMMDD_HHMMSS) HTML dosyasını okur ve
        skor, toplam sonuç ve hedef URL gibi kritik verileri çıkarır.
        """
        report_dir = os.path.join(os.getcwd(), "reports")
        html_path = os.path.join(report_dir, f"{report_base_name}.html")

        if not os.path.exists(html_path):
            return None

        try:
            with open(html_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 1. Skor Çıkarma
            score_match = re.search(r'<div class="score-circle" id="security-score">(\d+)</div>', content)
            score = int(score_match.group(1)) if score_match else 0
            
            # 2. Toplam Sonuç Sayısı Çıkarma
            results_match = re.search(r'Tespit Edilen Sonuçlar \((.*?)\ Adet\)', content)
            total_results = int(results_match.group(1)) if results_match and results_match.group(1).isdigit() else 0

            # 3. Target URL Çıkarma
            target_match = re.search(r'Hedef: <strong>(.*?)</strong>', content)
            target_url = target_match.group(1) if target_match else "Bilinmiyor"

            return {
                'score': score,
                'total_results': total_results,
                'target_url': target_url
            }

        except Exception:
            # Rapor okunamadı veya regex başarısız oldu
            return None

def _hex_to_rgb(hex_color):
    """Hex kodu (ör: #ff00ff) RGB tuple'ına çevirir."""
    hex_color = hex_color.lstrip('#')
    return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))

def _rgb_to_hex(rgb_tuple):
    """RGB tuple'ını Hex koduna çevirir."""
    return f'#{int(rgb_tuple[0]):02x}{int(rgb_tuple[1]):02x}{int(rgb_tuple[2]):02x}'

def _interpolate_color(color1_hex, color2_hex, factor):
    """İki renk arasında interpolasyon yapar (factor 0.0'dan 1.0'a)."""
    rgb1 = _hex_to_rgb(color1_hex)
    rgb2 = _hex_to_rgb(color2_hex)
    
    r = int(rgb1[0] + (rgb2[0] - rgb1[0]) * factor)
    g = int(rgb1[1] + (rgb2[1] - rgb1[1]) * factor)
    b = int(rgb1[2] + (rgb2[2] - rgb1[2]) * factor)
    
    return _rgb_to_hex((r, g, b))

class ComparisonWindow(ctk.CTkToplevel):
    """
    İki raporun karşılaştırma sonuçlarını gösteren yeni pencere.
    (UX Odaklı Görselleştirme eklendi)
    """
    def __init__(self, master, report_data_1, report_data_2, report_name_1, report_name_2):
        super().__init__(master)
        self.title("Synara AI | Rapor Karşılaştırması")
        self.geometry("850x600") # Boyut genişletildi
        self.configure(fg_color=COLOR_BG) 
        self.grab_set() 

        self.grid_columnconfigure((0, 1, 2), weight=1) 
        self.grid_rowconfigure(2, weight=1)

        # Başlık
        ctk.CTkLabel(self, text="Güvenlik Raporu Karşılaştırması", 
                     font=ctk.CTkFont(size=24, weight="bold"), 
                     text_color=COLOR_ACCENT).grid(row=0, column=0, columnspan=3, pady=(20, 10))
        
        ctk.CTkLabel(self, text="İki Tarama Arasındaki Değişim Analizi", 
                     text_color=COLOR_WARNING).grid(row=1, column=0, columnspan=3, pady=(0, 20))

        # Ana Karşılaştırma Çerçevesi
        main_frame = ctk.CTkFrame(self, fg_color=COLOR_SIDEBAR, corner_radius=10) 
        main_frame.grid(row=2, column=0, columnspan=3, sticky="nsew", padx=20, pady=20)
        main_frame.grid_columnconfigure((0, 1, 2), weight=1)
        main_frame.grid_rowconfigure(2, weight=1) # Farklılık tablosu için

        # Rapor Başlıkları
        ctk.CTkLabel(main_frame, text=f"RAPOR 1: {report_name_1}", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, padx=10, pady=10)
        ctk.CTkLabel(main_frame, text="FARKLAR", font=ctk.CTkFont(size=16, weight="bold")).grid(row=0, column=1, padx=10, pady=10)
        ctk.CTkLabel(main_frame, text=f"RAPOR 2: {report_name_2}", font=ctk.CTkFont(weight="bold")).grid(row=0, column=2, padx=10, pady=10)
        
        ctk.CTkProgressBar(main_frame, height=1, fg_color="#334155", progress_color="#334155").grid(row=1, column=0, columnspan=3, sticky="ew", padx=10)

        # --- YENİ UX KARTLARI ---
        
        # 1. Skor Karşılaştırma Kartı (Merkez)
        self._setup_score_card(main_frame, report_data_1['score'], report_data_2['score'])

        # 2. Sonuç Farkı Kartları (Yeni Riskler vs. Kapanan Riskler)
        self._setup_results_diff_cards(main_frame, report_data_1['total_results'], report_data_2['total_results'])
        
        # 3. Kapatma Butonu
        ctk.CTkButton(self, text="Kapat", command=self.destroy, width=150).grid(row=3, column=0, columnspan=3, pady=20)

    
    def _setup_score_card(self, master, score1, score2):
        """Puan farkını görselleştiren merkezi kartı kurar."""
        
        score_diff = score2 - score1
        
        # Puan Skalasına Göre Renk Ataması
        # Kötüleşme için Kırmızıdan Sarıya (max diff -100)
        # İyileşme için Yeşilden Sarıya (max diff +100)

        arrow = "●"
        color = COLOR_WARNING
        status_text = "Durağan"
        
        if score_diff > 0:
            arrow = "▲"
            # Yeşil (İyileşme)
            color_factor = min(1.0, score_diff / 50.0) # Maksimum 50 puan farkını baz alarak
            color = _interpolate_color(COLOR_WARNING, COLOR_SUCCESS, color_factor)
            status_text = "GÜVENLİK İYİLEŞMESİ"
            
        elif score_diff < 0:
            arrow = "▼"
            # Kırmızı (Kötüleşme)
            color_factor = min(1.0, abs(score_diff) / 50.0)
            color = _interpolate_color(COLOR_WARNING, COLOR_ERROR, color_factor)
            status_text = "KRİTİK KÖTÜLEŞME"
        
        # Ana Konteyner
        score_container = ctk.CTkFrame(master, fg_color="transparent")
        score_container.grid(row=2, column=0, columnspan=3, pady=(20, 10), sticky="ew")
        score_container.grid_columnconfigure((0, 1, 2), weight=1)

        # Puan 1
        self._create_score_label(score_container, 0, score1).grid(row=0, column=0)
        
        # Fark Kartı (Ortadaki Büyük Gösterge)
        diff_card = ctk.CTkFrame(score_container, fg_color=COLOR_SIDEBAR, corner_radius=10, 
                                 border_width=2, border_color=color)
        diff_card.grid(row=0, column=1, padx=20, pady=10, sticky="nsew")

        ctk.CTkLabel(diff_card, text=f"{arrow}", font=ctk.CTkFont(size=30, weight="bold"), 
                     text_color=color).pack(pady=(10, 0))
                     
        ctk.CTkLabel(diff_card, text=f"{abs(score_diff)} Puan", 
                     font=ctk.CTkFont(size=36, weight="bold"), text_color=color).pack(pady=0)
        
        ctk.CTkLabel(diff_card, text=status_text, 
                     font=ctk.CTkFont(size=12), text_color=COLOR_TEXT_SECONDARY).pack(pady=(0, 10))
        
        # Puan 2
        self._create_score_label(score_container, 2, score2).grid(row=0, column=2)
        
        # Genel Mesaj
        ctk.CTkLabel(master, 
                     text=f"Genel Değişim: Güvenlik skoru {abs(score_diff)} puan {('iyileşti' if score_diff > 0 else 'kötüleşti' if score_diff < 0 else 'değişmedi')}.",
                     text_color=COLOR_TEXT_SECONDARY).grid(row=3, column=0, columnspan=3, pady=10)


    def _create_score_label(self, master, column, score):
        """Tek bir raporun puanını gösteren kutuyu döndürür."""
        
        # Puanı renklendirme (0-50 Kötü, 50-80 Uyarı, 80-100 İyi)
        score_color = COLOR_SUCCESS
        if score < 50:
            score_color = COLOR_ERROR
        elif score < 80:
            score_color = COLOR_WARNING

        frame = ctk.CTkFrame(master, fg_color=COLOR_BG, corner_radius=10, border_width=1, border_color=score_color)
        
        ctk.CTkLabel(frame, text="GÜVENLİK SKORU", font=ctk.CTkFont(size=12, weight="bold"), 
                     text_color=COLOR_TEXT_SECONDARY).pack(pady=(15, 0))
                     
        ctk.CTkLabel(frame, text=f"{score}", font=ctk.CTkFont(size=40, weight="bold"), 
                     text_color=score_color).pack(pady=(0, 15))
                     
        return frame


    def _setup_results_diff_cards(self, master, results1, results2):
        """Yeni ve kapanan riskleri gösteren alt kartları kurar."""
        
        new_risks = max(0, results2 - results1)
        closed_risks = max(0, results1 - results2)
        
        # Ana Konteyner
        results_container = ctk.CTkFrame(master, fg_color="transparent")
        results_container.grid(row=4, column=0, columnspan=3, pady=(20, 10), sticky="ew")
        results_container.grid_columnconfigure((0, 1, 2), weight=1)
        
        # Yeni Riskler Kartı (Kötü - Kırmızı)
        self._create_risk_card(results_container, 0, "⚠️ Yeni Riskler", 
                               new_risks, COLOR_ERROR, "▲").grid(row=0, column=0, padx=10, sticky="ew")
        
        # Kapanan Riskler Kartı (İyi - Yeşil)
        self._create_risk_card(results_container, 1, "✅ Kapanan Riskler", 
                               closed_risks, COLOR_SUCCESS, "▼").grid(row=0, column=1, padx=10, sticky="ew")

        # Toplam Risk Durumu
        ctk.CTkLabel(results_container, text=f"Toplam Zafiyet: Rapor 1 ({results1}) / Rapor 2 ({results2})",
                     text_color=COLOR_TEXT_SECONDARY).grid(row=0, column=2, padx=10, sticky="w")


    def _create_risk_card(self, master, column, title, count, color, icon):
        """Yeni/Kapanan riskler için küçük bir bilgi kartı oluşturur."""
        
        card = ctk.CTkFrame(master, fg_color=COLOR_SIDEBAR, corner_radius=10)
        
        ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=14, weight="bold"), 
                     text_color=COLOR_TEXT_SECONDARY).pack(pady=(10, 0))
        
        ctk.CTkLabel(card, text=f"{icon} {count} Adet", font=ctk.CTkFont(size=24, weight="bold"), 
                     text_color=color).pack(pady=(0, 10))
                     
        return card

# Yardımcı renk fonksiyonları artık global olarak tanımlanmıştır.