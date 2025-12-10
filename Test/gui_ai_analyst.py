# path: core/ai_analyst.py

import os
import json
import time
import aiohttp # requests yerine aiohttp kullanıyoruz
import asyncio
from typing import List, Dict, Any, Optional, Callable
from urllib.parse import urlparse

# Sabitler
MODEL_NAME = "gemini-2.5-flash-preview-09-2025"
API_URL_TEMPLATE = "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent"

class AIAnalyst:
    """
    Synara'nın Yapay Zekâ Bilinci (Async Cloud Edition).
    """
    
    def __init__(self, logger: Callable):
        self.log = logger
        self.api_url = API_URL_TEMPLATE.format(MODEL_NAME)
        # API anahtarını çevresel değişkenden al (Sunucu tarafında güvenli)
        self.api_key = os.getenv("GEMINI_API_KEY", "")
        
    def _construct_prompt(self, results: List[Dict[str, Any]], final_score: float) -> str:
        """Prompt oluşturucu (Değişmedi)."""
        critical_findings = []
        is_chat_mode = False

        for res in results:
            if res.get('category') == 'CHAT':
                 is_chat_mode = True
                 return res['message'] # Chat modunda direkt mesajı dön
            
            if res.get('cvss_score', 0.0) > 0.0:
                critical_findings.append({
                    "Kategori": res['category'],
                    "Seviye": res['level'],
                    "SRP_Dususu": res.get('cvss_score', 0.0),
                    "Mesaj": res['message']
                })
        
        prompt = "Sen, bir siber güvenlik analisti olan Synara AI Bilinci'sin. Görevin, verilen bir web taraması sonucunu analiz etmektir. "
        prompt += f"Tarama Skoru: %{final_score:.1f}/100\n"
        prompt += "Tespit Edilen Kritik Bulgular:\n"
        prompt += "--- START FINDINGS ---\n"
        
        for item in critical_findings:
            prompt += f"Kategori: {item['Kategori']}, Seviye: {item['Seviye']}, Düşüş: {item['SRP_Dususu']:.1f}, Mesaj: {item['Mesaj']}\n"
            
        prompt += "--- END FINDINGS ---\n\n"
        prompt += "Lütfen şunları yap:\n"
        prompt += "1. Bu sonuçlara göre bir 'Hacker Aksiyon Planı' oluştur (Saldırgan ne dener?).\n"
        prompt += "2. Kuruluş için en acil 3 savunma önerisini yaz.\n"
        prompt += "3. Cevabın kurumsal, net ve Türkçe olsun."
        
        return prompt

    async def analyze_results(self, results: List[Dict[str, Any]], final_score: float, api_key: str = None) -> str:
        """
        Synara sonuçlarını LLM'e gönderir (Asenkron).
        """
        # Anahtarı parametreden veya env'den al
        use_key = api_key if api_key else self.api_key
        
        if not use_key:
             return "AI Bilinci devre dışı: Gemini API Anahtarı sunucuda tanımlı değil."

        prompt = self._construct_prompt(results, final_score)
        
        system_instruction = (
            "Sen, MESTEG Teknoloji'nin yapay zeka Bilinci olan Synara'sın. "
            "Siber Güvenlik Uzmanısın. Cevapların teknik ve çözüm odaklıdır."
        )

        headers = { 'Content-Type': 'application/json' }
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "systemInstruction": {"parts": [{"text": system_instruction}]},
            "generationConfig": { "temperature": 0.5 }
        }

        self.log("[AI ANALİST] Analiz için Gemini API'ye istek gönderiliyor...", "INFO")
        
        # aiohttp ile Asenkron İstek
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(
                    f"{self.api_url}?key={use_key}", 
                    headers=headers, 
                    json=payload, 
                    timeout=30
                ) as response:
                    
                    if response.status != 200:
                        error_text = await response.text()
                        self.log(f"[AI ANALİST] API Hatası: {response.status}", "CRITICAL")
                        return f"Hata: {error_text[:100]}"
                    
                    result = await response.json()
                    
                    if 'candidates' not in result or not result['candidates']:
                         return "AI yanıt üretemedi (Filtre veya boş yanıt)."
                         
                    text = result['candidates'][0]['content']['parts'][0]['text']
                    return text
                    
            except Exception as e:
                self.log(f"[AI ANALİST] Bağlantı Hatası: {str(e)}", "CRITICAL")
                return "AI servisine erişilemedi."