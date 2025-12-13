# path: core/ai_analyst.py
import os
import json
import time
import requests
from typing import List, Dict, Any, Optional, Callable
from urllib.parse import urlparse

# MODEL FALLBACK LİSTESİ (Öncelik Sırasına Göre)
# Sistem 404 alırsa sıradakine geçer.
AVAILABLE_MODELS = [
    "gemini-1.5-flash",          # En Hızlı/Ucuz (Varsayılan)
    "gemini-1.5-flash-001",      # Alternatif Versiyon
    "gemini-1.5-flash-latest",   # Son Sürüm Alias
    "gemini-1.5-pro",            # Daha Güçlü (Yedek)
    "gemini-1.5-pro-001",        # Pro Versiyon
    "gemini-pro"                 # Legacy (Son Çare)
]

API_URL_TEMPLATE = "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent"

class AIAnalyst:
    """
    Synara'nın Yapay Zekâ Bilinci (Gemini 1.5 Smart Fallback Edition).
    Tarama sonuçlarını (SRP sonuçları ve kritik zafiyetler) alarak,
    hacker mantığıyla yorumlar ve aksiyon planı önerir.
    
    Güncellemeler:
    - Smart Fallback: 404 hatasında otomatik model değiştirme.
    - Robustness: API kararsızlıklarına karşı dirençli.
    """
    
    def __init__(self, logger: Callable):
        self.log = logger
        # Dinamik Model Yönetimi
        self.current_model_index = 0
        self.model_name = AVAILABLE_MODELS[0]
        
    def _get_current_url(self) -> str:
        """Şu anki aktif model ile URL oluşturur."""
        return API_URL_TEMPLATE.format(self.model_name)

    def _switch_model(self):
        """Bir sonraki modele geçer (Fallback)."""
        old_model = self.model_name
        self.current_model_index = (self.current_model_index + 1) % len(AVAILABLE_MODELS)
        self.model_name = AVAILABLE_MODELS[self.current_model_index]
        self.log(f"[AI ANALİST] Model Rotasyonu: {old_model} (404) -> {self.model_name} modeline geçiliyor...", "WARNING")
        
    def _construct_prompt(self, results: List[Dict[str, Any]], final_score: float) -> str:
        """
        LLM'e gönderilecek genel analiz prompt'unu oluşturur.
        """
        critical_findings = []
        is_chat_mode = False

        for res in results:
            if res.get('category') == 'CHAT':
                 is_chat_mode = True
                 chat_message = res['message']
                 break
            if res.get('cvss_score', 0.0) > 0.0: # SRP düşüşü olan tüm gerçek riskleri al
                critical_findings.append({
                    "Kategori": res['category'],
                    "Seviye": res['level'],
                    "SRP_Dususu": res.get('cvss_score', 0.0),
                    "Mesaj": res['message']
                })
        
        if is_chat_mode:
             return chat_message

        prompt = "Sen, bir siber güvenlik analisti olan Synara AI Bilinci'sin. Görevin, verilen bir web taraması sonucunu, "
        prompt += "en kritik zafiyetlere odaklanarak analiz etmek ve bir 'Hacker Aksiyon Planı' oluşturmaktır. "
        prompt += f"Tarama Skoru: %{final_score:.1f}/100\n"
        prompt += "Tespit Edilen Kritik Bulgular:\n"
        prompt += "--- START FINDINGS ---\n"
        
        for item in critical_findings:
            prompt += f"Kategori: {item['Kategori']}, Seviye: {item['Seviye']}, Düşüş: {item['SRP_Dususu']:.1f}, Mesaj: {item['Mesaj']}\n"
            
        prompt += "--- END FINDINGS ---\n\n"
        prompt += "Analiz Formatı:\n"
        prompt += "1. YORUM: Sunucunun genel durumu ve neden bu puanın alındığının özeti.\n"
        prompt += "2. KRİTİK ZAFİYETLER: En yüksek SRP düşüşü olan zafiyetler (SQLi, RCE, Açık Portlar) ve bu risklerin anlamı.\n"
        prompt += "3. HACKER AKSİYON PLANI: Bu verilere sahip bir saldırganın atacağı ilk 3 somut adım (örneğin, Telnet'e bağlan, UNION query yaz, vb.).\n"
        prompt += "4. SAVUNMA ÖNERİSİ: Kuruluşun bu açıkları hemen kapatması için atması gereken en acil 3 adım.\n"
        prompt += "\nŞimdi bu verilere dayanarak analizini yap."
        
        return prompt

    def analyze_kill_chain(self, results: List[Dict[str, Any]], api_key: str) -> str:
        """
        Kinetik Zincir Analizi:
        Birden fazla zafiyeti birleştirerek tam sistem ele geçirme senaryosu (Kill Chain) oluşturur.
        """
        if not api_key:
            return "AI Bilinci: API Anahtarı eksik olduğu için Zincir Analizi yapılamadı."

        # Sadece Yüksek ve Kritik seviyeli bulguları filtrele
        high_critical_findings = [
            res for res in results 
            if res.get('level') in ['CRITICAL', 'HIGH']
        ]

        if not high_critical_findings:
            return "Kinetik Zincir Analizi: Zincir oluşturacak yeterli kritik bulgu tespit edilemedi (Sistem nispeten güvenli)."

        prompt = "Sen elit bir Red Teamer'sın. Aşağıdaki kritik zafiyetleri birleştirerek hedef sistemi ele geçirmek için bir 'Kill Chain' (Saldırı Zinciri) senaryosu yaz.\n\n"
        prompt += "MEVCUT ZAFİYETLER:\n"
        
        for item in high_critical_findings:
            prompt += f"- [{item['category']}] {item['message']}\n"

        prompt += "\nİSTENEN FORMAT:\n"
        prompt += "1. STRATEJİK HEDEF: Bu açıklarla ne yapılabilir? (Örn: Veritabanı sızıntısı, RCE ile sunucu kontrolü vb.)\n"
        prompt += "2. SALDIRI ZİNCİRİ (ADIM ADIM): Hangi zafiyet ilk kullanılmalı, sonra hangisiyle ilerlenmeli?\n"
        prompt += "   - Adım 1: ...\n   - Adım 2: ...\n"
        prompt += "3. RİSK SEVİYESİ: Bu senaryonun gerçekleşme ihtimali ve etkisi.\n"
        prompt += "Çok teknik, net ve doğrudan saldırgan bakış açısıyla yaz."

        return self._send_gemini_request(prompt, api_key, "KILL_CHAIN")

    def analyze_results(self, results: List[Dict[str, Any]], final_score: float, api_key: str) -> str:
        """
        Genel tarama sonuçlarını analiz eder.
        """
        if not api_key:
             return "AI Bilinci devre dışı: Gemini API Anahtarı bulunamadı."

        prompt = self._construct_prompt(results, final_score)
        return self._send_gemini_request(prompt, api_key, "GENERAL_ANALYSIS")

    def _send_gemini_request(self, prompt: str, api_key: str, analysis_type: str) -> str:
        """
        Gemini API'ye istek gönderen yardımcı metot (Rotasyonlu).
        """
        system_instruction = (
            "Sen, MESTEG Teknoloji'nin yapay zeka Bilinci olan Synara'sın. "
            "Cevapların etik, vizyoner, net ve kurumsal bir tonda olmalıdır. "
            "Siber güvenlik terimlerini doğru kullan."
        )

        headers = { 'Content-Type': 'application/json' }
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "systemInstruction": {"parts": [{"text": system_instruction}]},
            "generationConfig": { "temperature": 0.5 }
        }

        self.log(f"[AI ANALİST] {analysis_type} analizi için Gemini API ({self.model_name})'ye istek gönderiliyor...", "INFO")
        
        clean_key = str(api_key).strip().strip("'").strip('"').strip('[').strip(']')
        
        # Retry Mantığı (Smart Fallback)
        # Toplam deneme sayısı = Model sayısı * 2 (her model için ortalama 2 şans gibi, veya sabit sayı)
        max_attempts = len(AVAILABLE_MODELS) + 2
        
        for attempt in range(max_attempts):
            # Güncel URL'i al
            current_url = self._get_current_url()
            clean_url = current_url.strip().strip("'").strip('"')

            try:
                response = requests.post(f"{clean_url}?key={clean_key}", headers=headers, data=json.dumps(payload), timeout=30)
                
                if response.status_code == 200:
                    result = response.json()
                    if 'candidates' not in result or not result['candidates']:
                        return "AI Bilinci: Analiz yapılamadı (Boş yanıt)."
                    text = result['candidates'][0]['content']['parts'][0]['text']
                    return text.strip()

                # --- 404 ROTASYONU ---
                elif response.status_code == 404:
                    self._switch_model()
                    # Beklemeden devam et
                    continue
                
                # --- Rate Limit ---
                elif response.status_code == 429:
                    self.log(f"[AI ANALİST] Rate Limit (429). Bekleniyor...", "WARNING")
                    time.sleep(2 * (attempt + 1))
                    continue

                else:
                    self.log(f"[AI ANALİST] API Hatası: {response.status_code}", "WARNING")
                    time.sleep(1)
                
            except Exception as e:
                self.log(f"[AI ANALİST] Bağlantı Hatası ({attempt+1}/{max_attempts}): {str(e)[:50]}", "WARNING")
                time.sleep(1)
        
        return "AI Bilinci: Tüm modeller denendi ancak bağlantı kurulamadı."