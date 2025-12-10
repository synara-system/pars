# path: core/reporter.py

import datetime
import os
import sys
import webbrowser
import jinja2
import pdfkit # PDF oluşturma kütüphanesi eklendi
from urllib.parse import urlparse # YENİ EKLENDİ: URL ayrıştırma için
import re # Hostname temizliği için eklendi

# --- KRİTİK AYAR: wkhtmltopdf YOLU ---
# pdfkit'in wkhtmltopdf aracını bulması için manuel yolu belirtme (wkhtmltopdf PATH'e ekli değilse gerekli)
# Lütfen bu yolu kendi sisteminizdeki KURULUM YOLU ile değiştirin!
# KRİTİK DÜZELTME: Bu path, Python kodu içinde yer alamaz. PyInstaller, harici binary'leri (wkhtmltopdf gibi)
# .exe içinde taşımaz, bu yüzden yerel sistemdeki yolu kullanmaya devam etmeliyiz.
# Eğer kullanıcı wkhtmltopdf'i PATH'e eklemediyse, bu yolu manuel olarak düzeltmeli.
# Ancak, biz bu hatayı yakalayıp loglayacağız.
WKHTMLTOPDF_PATH = r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe'
# Eğer PATH'inizde kuruluysa, boş dize bırakabilirsiniz: WKHTMLTOPDF_PATH = "" 

class SynaraReporter:
    """
    Raporlama sınıfı. SynaraScannerEngine verilerini kullanarak
    HTML ve PDF formatÄ±nda gÃ¼venlik raporlarÄ± oluÅŸturur.
    """
    def __init__(self, engine):
        # Engine objesini referans olarak tutar, böylece tüm verilere (score, results vb.) erişebilir.
        self.engine = engine
        self.folder_name = "reports"
        
        # Jinja2 ortamını kur
        self._setup_jinja_environment()
        
        # wkhtmltopdf konfigürasyonu
        self.pdf_config = None
        if WKHTMLTOPDF_PATH:
            try:
                # SADECE wkhtmltopdf.exe'nin yolunu config'e ver
                self.pdf_config = pdfkit.configuration(wkhtmltopdf=WKHTMLTOPDF_PATH)
            except Exception as e:
                # Bu hata genellikle pdfkit'in yapılandırma dosyasını okuyamamasından kaynaklanır
                print(f"Hata: pdfkit konfigürasyonu başarısız oldu: {e}")

    def _clean_hostname(self, url):
        """URL'den temiz bir hostname/dosya adı tabanı oluşturur."""
        try:
            parsed = urlparse(url)
            # Hostname'i al
            netloc = parsed.netloc or parsed.path
            
            # Hostname'i temizle (port, www. kaldır, noktaları alt çizgiye çevir)
            if ':' in netloc:
                 netloc = netloc.split(':')[0] # Portu kaldır
            if netloc.startswith('www.'):
                netloc = netloc[4:]
            
            # Dosya adlarında geçerli karakterler olması için özel karakterleri ve noktaları alt çizgiye çevir
            clean_name = re.sub(r'[^a-zA-Z0-9_.-]', '_', netloc).replace('.', '_').strip('_')
            
            # Çok uzun isimleri kısaltmak için 50 karakterle sınırla
            return clean_name if clean_name else "unknown_target"
            
        except Exception:
            return "unknown_target"

    def _setup_jinja_environment(self):
        """
        Jinja2 ortamını hazırlar ve şablonların bulunduğu klasörü ayarlar.
        KRİTİK DÜZELTME: sys.frozen kontrolü ve MEIPASS kullanımı.
        """
        # --- PYINSTALLER UYUMLU KAYNAK YOLU KONTROLÜ ---
        # Eğer program paketlenmişse, kaynak dosyaları sys._MEIPASS (veya os.path.dirname(sys.executable)) altında olacaktır.
        if getattr(sys, 'frozen', False):
            # Dosyalarımız EXE'nin içinde ve 'core/templates' yolunda paketlendi.
            # Base path'i sys._MEIPASS olarak almalıyız.
            base_path = sys._MEIPASS 
        else:
            base_path = os.getcwd()
            
        # Şablonların konumu: core/templates (Bu yol, spec dosyasındaki hedef yol ile uyumlu olmalı)
        template_dir = os.path.join(base_path, "core", "templates")
        
        # Jinja2 Loader ile şablon klasörünü ayarla
        self.template_loader = jinja2.FileSystemLoader(template_dir)
        self.template_env = jinja2.Environment(loader=self.template_loader)
        
        try:
            # Şablonu yükle
            self.template = self.template_env.get_template("report_template.html")
            print(f"[JINJA] Şablon başarıyla yüklendi: {template_dir}/report_template.html")
        except jinja2.TemplateNotFound as e:
            # HTML Report generation failed hatasının nedeni burasıdır.
            print(f"Hata: Jinja2 şablonu '{e}' bulunamadı. Lütfen 'core/templates/report_template.html' dosyasının paketlendiğinden emin olun.")
            self.template = None


    def _get_report_path(self, timestamp_str):
        """
        Rapor çıktı klasörünü belirler ve HTML/PDF dosya yollarını döndürür.
        """
        # Çıktı yolları her zaman çalıştırılabilir dosyanın olduğu yere göre (veya projeye göre) olmalıdır.
        if getattr(sys, 'frozen', False):
            # EXE'nin bulunduğu dizin (output klasörü)
            base_path = os.path.dirname(sys.executable)
        else:
            base_path = os.getcwd()
            
        report_dir = os.path.join(base_path, self.folder_name)
        
        if not os.path.exists(report_dir):
            try: 
                os.makedirs(report_dir)
            except OSError as e:
                print(f"Hata: Rapor çıktı klasörü oluşturulamadı: {e}")
                return None, None
        
        # YENİ: Dinamik dosya adı (hedef URL'ye göre)
        clean_url_base = self._clean_hostname(self.engine.target_url)
        base_filename = f"{clean_url_base}_{timestamp_str}"

        html_path = os.path.join(report_dir, f"{base_filename}.html")
        pdf_path = os.path.join(report_dir, f"{base_filename}.pdf")
        
        return html_path, pdf_path


    def generate_pdf_report(self, html_path, pdf_path):
        """
        Oluşturulmuş HTML dosyasını alıp PDF'e dönüştürür.
        """
        # pdfkit config ayarları
        options = {
            'quiet': '', 
            'page-size': 'A4',
            'margin-top': '10mm',
            'margin-right': '10mm',
            'margin-bottom': '10mm',
            'margin-left': '10mm',
            'encoding': "UTF-8",
            # KRİTİK AYAR: Bu, pdfkit'in yerel olarak yüklediği CSS/Font/JS dosyalarını okumasını sağlar.
            'enable-local-file-access': True 
        }
        
        try:
            # pdfkit.from_file çağrısına konfigürasyonu ekle
            pdfkit.from_file(html_path, pdf_path, options=options, configuration=self.pdf_config)
            return pdf_path
            
        except OSError as e:
            # wkhtmltopdf bulunamadı hatası (WKHTMLTOPDF_PATH'in yanlış ayarlandığı anlamına gelir)
            error_message = f"HATA: PDF DönüşümÃ¼ BaÅŸarÄ±sÄ±z. Lütfen WKHTMLTOPDF_PATH'i kontrol edin veya PATH'e ekleyin. Detay: {e}"
            print(error_message)
            return None
        except Exception as e:
            print(f"Kritik PDF Dönüşüm Hatası: {e}")
            return None


    def generate_report(self):
        """
        Jinja2 şablonunu kullanarak HTML rapor içeriğini oluşturur, dosyaya kaydeder ve
        PDF dönüşümünü başlatır. HTML ve PDF yollarını döndürür.
        """
        if self.template is None:
            print("[RAPORLAMA] HATA: Jinja2 şablonu yüklenemediği için rapor oluşturulamıyor.")
            return None, None 
            
        timestamp_str = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        html_path, pdf_path = self._get_report_path(timestamp_str)
        
        if not html_path:
            return None, None
            
        # Motor verilerini hazırla
        score = max(0, int(self.engine.score)) # Faz 10: Skoru int olarak göster
        results = self.engine.results
        target_url = self.engine.target_url
        scan_duration = datetime.datetime.now() - self.engine.start_time
        duration_str = str(scan_duration).split('.')[0]
        
        # YENİ METRİK HESAPLAMA
        total_requests = self.engine.total_requests
        avg_response_time_ms = "N/A"
        
        if total_requests > 0:
            # Toplam süreyi saniyeden milisaniyeye çevirip istek sayısına böl
            total_duration_ms = scan_duration.total_seconds() * 1000
            avg_response_time_ms = f"{total_duration_ms / total_requests:.2f} ms"
        
        template_context = {
            "score": score,
            "results": results,
            "target_url": target_url,
            "scan_date": datetime.datetime.now().strftime('%d.%m.%Y %H:%M:%S'),
            "scan_duration": duration_str,
            "avg_response_time": avg_response_time_ms,
            "total_cvss_score": f"{self.engine.total_cvss_deduction:.1f}", # Faz 10: Toplam CVSS Düşüşü
            "total_requests": total_requests # Rapor şablonunda kullanılan yeni metrik
        }

        # 1. HTML Çıktısı Oluştur ve Kaydet
        try:
            html_content = self.template.render(template_context)
            with open(html_path, "w", encoding="utf-8") as f: 
                f.write(html_content)
                print(f"[RAPORLAMA] HTML raporu başarıyla oluşturuldu: {os.path.basename(html_path)}")
        except Exception as e:
            print(f"Hata: HTML raporu render edilemedi veya yazılamadı: {e}")
            return None, None

        # 2. PDF Çıktısı Oluştur
        final_pdf_path = self.generate_pdf_report(html_path, pdf_path)
        
        # HTML ve (varsa) PDF yolunu döndür
        return html_path, final_pdf_path