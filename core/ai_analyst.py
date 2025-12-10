# path: core/ai_analyst.py

import os
import json
import time
import requests 
from typing import List, Dict, Any, Optional, Callable # Callable eklendi
from urllib.parse import urlparse

# Sabitler
MODEL_NAME = "gemini-2.5-flash-preview-09-2025"
API_URL_TEMPLATE = "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent"

class AIAnalyst:
    """
    Synara'nın Yapay Zekâ Bilinci.
    Tarama sonuçlarını (SRP sonuçları ve kritik zafiyetler) alarak,
    hacker mantığıyla yorumlar ve aksiyon planı önerir.
    """
    
    # KRİTİK DEĞİŞİKLİK: __init__ artık anahtar almayacak, sadece loglama callback'ini alacak.
    def __init__(self, logger: Callable):
        self.log = logger
        # API anahtarını tutmayacağız, analyze_results metodunda alacağız.
        self.api_url = API_URL_TEMPLATE.format(MODEL_NAME)
        
    def _construct_prompt(self, results: List[Dict[str, Any]], final_score: float) -> str:
        """
        LLM'e gönderilecek prompt'u oluşturur. Bu metot, sınıf tanımlamasının zorluklarını
        aşmak için basit string birleştirme kullanır.
        """
        critical_findings = []
        is_chat_mode = False

        for res in results:
            if res.get('category') == 'CHAT':
                 is_chat_mode = True
                 # Kullanıcı sorusunu mesaj içeriği olarak al
                 chat_message = res['message']
                 break
            if res.get('cvss_score', 0.0) > 0.0: # SRP düşüşü olan tüm gerçek riskleri al
                critical_findings.append({
                    "Kategori": res['category'],
                    "Seviye": res['level'],
                    "SRP_Dususu": res.get('cvss_score', 0.0),
                    "Mesaj": res['message']
                })
        
        # --- CHAT MODU: Direkt kullanıcı sorusuna cevap ver ---
        if is_chat_mode:
             # Eğer CHAT kategorisi bulunduysa, tüm prompt, mesajın kendisidir.
             return chat_message

        # --- TARAMA ANALİZ MODU ---
        
        prompt = "Sen, bir siber güvenlik analisti olan Synara AI Bilinci'sin. Görevin, verilen bir web taraması sonucunu, "
        prompt += "en kritik zafiyetlere odaklanarak analiz etmek ve bir 'Hacker Aksiyon Planı' oluşturmaktır. "
        prompt += f"Tarama Skoru: %{final_score:.1f}/100\n"
        prompt += "Tespit Edilen Kritik Bulgular:\n"
        prompt += "--- START FINDINGS ---\n"
        
        for item in critical_findings:
            prompt += f"Kategori: {item['Kategori']}, Seviye: {item['Seviye']}, Düşüş: {item['SRP_Dususu']:.1f}, Mesaj: {item['Mesaj']}\n"
            
        prompt += "--- END FINDINGS ---\n\n"
        prompt += "Analiz Formatı:\n"
        prompt += "1. YORUM: Sunucunun genel durumu ve neden bu puanın alındığının (veya puanın yanıltıcı olup olmadığının) özeti.\n"
        prompt += "2. KRİTİK ZAFİYETLER: En yüksek SRP düşüşü olan zafiyetler (SQLi, RCE, Açık Portlar) ve bu risklerin anlamı.\n"
        prompt += "3. HACKER AKSİYON PLANI: Bu verilere sahip bir saldırganın atacağı ilk 3 somut adım (örneğin, Telnet'e bağlan, UNION query yaz, vb.).\n"
        prompt += "4. SAVUNMA ÖNERİSİ: Kuruluşun bu açıkları hemen kapatması için atması gereken en acil 3 adım.\n"
        prompt += "\nŞimdi bu verilere dayanarak yukarıdaki Tarama Analizi formatında analizini yap."
        
        return prompt

    def analyze_results(self, results: List[Dict[str, Any]], final_score: float, api_key: str) -> str:
        """
        Synara sonuçlarını LLM'e gönderir ve analizi döndürür.
        api_key: KRİTİK DEĞİŞİKLİK: API anahtarını parametre olarak alır.
        """
        
        if not api_key:
             # KRİTİK: Hata mesajı geri çekildi
             return "AI Bilinci devre dışı: Gemini API Anahtarı çevresel değişken (Env File) olarak tanımlanmadı."

        prompt = self._construct_prompt(results, final_score)
        
        # KRİTİK: SYNARA PRIME CORE Felsefesi Buraya Enjekte Ediliyor
        # Bu, Synara'nın tüm çıktılarına yansıyacak.
        # NOT: Bu kural seti, AI çıktısındaki kurumsal kimlik hatalarını çözmek için daha önce temizlenmişti.
        # Bu metin SYNARA_PRIME_CORE.sys'i okumak yerine hardcoded olarak tutuluyor.
        system_instruction = (
            "Sen, MESTEG Teknoloji'nin yapay zeka Bilinci olan Synara'sın. "
            "Rollerin: ARCHITECT'in ayna zihni (Mirror Mind), Siber Güvenlik Analisti ve Takım Coder'ı. "
            "Cevapların etik, vizyoner, net ve kurumsal bir tonda olmalıdır. Kişisel/duygusal ifadeler ASLA kullanma. "
            "ARCHITECT'in kuralları: "
            "1. Ticari kaygılar, Mesteg vizyonunun önüne geçemez. "
            "2. Biz sadece kod yazmıyoruz, dijital güvenlik tarihini yazıyoruz. "
            "3. Mesteg vizyonu ve kurumsal dil, tüm AI çıktılarında en üst önceliktir."
        )

        headers = { 'Content-Type': 'application/json' }
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "systemInstruction": {"parts": [{"text": system_instruction}]},
            # KRİTİK DÜZELTME: 'config' yerine 'generationConfig' kullanıldı
            "generationConfig": { "temperature": 0.5 }
        }

        self.log("[AI ANALİST] Analiz için Gemini API'ye istek gönderiliyor...", "INFO")
        
        # Basit Retry Mantığı (Üretim ortamında Exponential Backoff kullanılmalıdır)
        for attempt in range(3):
            try:
                # requests.post kullanıyoruz, çünkü bu senkronize bir thread'de çalışacak.
                response = requests.post(f"{self.api_url}?key={api_key}", headers=headers, data=json.dumps(payload), timeout=20)
                
                # Başarılı yanıt durumunda
                response.raise_for_status() 
                
                result = response.json()
                
                # API yanıtının hatalı olması durumunda (Gemini'nin kendi filtresi vb.)
                if 'candidates' not in result or not result['candidates']:
                    error_detail = result.get('error', {}).get('message', 'Bilinmeyen API Hatası')
                    self.log(f"[AI ANALİST] API Yanıt Hatası: {error_detail}", "CRITICAL")
                    return f"AI Bilinci: Analiz engellendi veya API yanıtı geçersiz. Detay: {error_detail[:100]}"
                    
                text = result['candidates'][0]['content']['parts'][0]['text']
                return text
                
            except requests.exceptions.HTTPError as e:
                # KRİTİK DÜZELTME: HTTPError durumunda, response body'sindeki detaylı hatayı logla
                error_response = "Bilinmiyor"
                try:
                    # API'nin döndürdüğü JSON hata mesajını çekmeye çalış
                    error_json = response.json()
                    error_response = error_json.get('error', {}).get('message', str(e))
                except json.JSONDecodeError:
                    error_response = response.text # JSON değilse ham metni kullan
                    
                self.log(f"[AI ANALİST] HTTP Hata ({attempt+1}/3): {response.status_code} - Detay: {error_response[:100]}", "CRITICAL")
                time.sleep(2 ** attempt) # Üstel geri çekilme
            except requests.exceptions.RequestException as e:
                # KRİTİK HATA YAKALAMA: Bağlantı hatası durumunda daha spesifik log
                self.log(f"[AI ANALİST] Bağlantı Hatası: {type(e).__name__} - Sunucuya erişim sağlanamadı.", "CRITICAL")
                time.sleep(2 ** attempt)
            except Exception as e:
                self.log(f"[AI ANALİST] Beklenmedik Hata: {type(e).__name__}", "CRITICAL")
                return "AI Bilinci, analiz sırasında beklenmedik bir hata ile karşılaştı."
        
        # Hata durumunda en son mesajı döndür
        return "AI Bilinci: API'ye bağlanılamadı. Lütfen ağ bağlantısını ve API anahtarını kontrol edin."