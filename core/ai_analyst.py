# path: core/ai_analyst.py

import os
import json
import time
import requests 
from typing import List, Dict, Any, Optional, Callable # Callable eklendi
from urllib.parse import urlparse

# Sabitler
# MODEL_NAME = "gemini-2.5-flash-preview-09-2025" # DEPRECATED
MODEL_NAME = "gemini-1.5-flash" # KARARLI MODEL
API_URL_TEMPLATE = "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent"

class AIAnalyst:
    """
    Synara'nın Yapay Zekâ Bilinci.
    Tarama sonuçlarını (SRP sonuçları ve kritik zafiyetler) alarak,
    hacker mantığıyla yorumlar ve aksiyon planı önerir.
    FAZ 39: Kinetik Zincir Analizi (Kill Chain) eklendi.
    """
    
    def __init__(self, logger: Callable):
        self.log = logger
        # API anahtarını tutmayacağız, analyze_results metodunda alacağız.
        self.api_url = API_URL_TEMPLATE.format(MODEL_NAME)
        
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
        [FAZ 39] Kinetik Zincir Analizi:
        Birden fazla zafiyeti birleştirerek tam sistem ele geçirme senaryosu (Kill Chain) oluşturur.
        Özellikle RCE, SQLi, LFI ve Auth Bypass gibi kritik bulgulara odaklanır.
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

        # Prompt Hazırlığı
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

        # API İsteği
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
        Gemini API'ye istek gönderen yardımcı metot.
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

        self.log(f"[AI ANALİST] {analysis_type} analizi için Gemini API'ye istek gönderiliyor...", "INFO")
        
        # Retry Mantığı
        for attempt in range(3):
            try:
                response = requests.post(f"{self.api_url}?key={api_key}", headers=headers, data=json.dumps(payload), timeout=30)
                response.raise_for_status() 
                result = response.json()
                
                if 'candidates' not in result or not result['candidates']:
                    return "AI Bilinci: Analiz yapılamadı (Boş yanıt)."
                    
                text = result['candidates'][0]['content']['parts'][0]['text']
                return text.strip()
                
            except Exception as e:
                self.log(f"[AI ANALİST] Hata ({attempt+1}/3): {str(e)[:100]}", "WARNING")
                time.sleep(2)
        
        return "AI Bilinci: Bağlantı kurulamadı."