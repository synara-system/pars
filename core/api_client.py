# path: core/api_client.py
# PARS API İstemcisi - V2.2

import requests
import json
import time

class PARSClient:
    def __init__(self, api_base_url, api_key=None):
        self.base_url = api_base_url.rstrip('/')
        self.api_key = api_key
        self.current_scan_id = None
        
    def check_connection(self):
        try:
            resp = requests.get(f"{self.base_url}/", timeout=10)
            return resp.status_code == 200
        except Exception as e:
            print(f"[API ERROR] Bağlantı hatası: {e}")
            return False

    def start_scan(self, target_url, profile="BUG_BOUNTY_CORE"):
        endpoint = f"{self.base_url}/scan/start"
        payload = {
            "target_url": target_url,
            "profile": profile,
            "api_key": self.api_key
        }
        try:
            resp = requests.post(endpoint, json=payload, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                self.current_scan_id = data.get("scan_id")
                return self.current_scan_id
            else:
                raise Exception(f"API Hatası ({resp.status_code}): {resp.text}")
        except Exception as e:
            raise Exception(f"Tarama başlatılamadı: {e}")

    def get_status(self):
        if not self.current_scan_id: return None
        endpoint = f"{self.base_url}/scan/{self.current_scan_id}/status"
        try:
            resp = requests.get(endpoint, timeout=5)
            if resp.status_code == 200: return resp.json()
            else: return None
        except Exception: return None
            
    def get_results(self):
        if not self.current_scan_id: return []
        endpoint = f"{self.base_url}/scan/{self.current_scan_id}/results"
        try:
            resp = requests.get(endpoint, timeout=10)
            if resp.status_code == 200: return resp.json().get("results", [])
            else: return []
        except Exception: return []

    # --- YENİ AI METODU ---
    def ask_ai(self, prompt, context_scan_id=None):
        """Sunucudaki AI modülüne soru sorar."""
        endpoint = f"{self.base_url}/ai/analyze"
        payload = {
            "prompt": prompt,
            "context_scan_id": context_scan_id # Varsa bu ID'nin sonuçlarını analiz eder
        }
        try:
            resp = requests.post(endpoint, json=payload, timeout=60) # AI yavaş olabilir, timeout yüksek
            if resp.status_code == 200:
                return resp.json().get("response", "Cevap yok.")
            else:
                return f"AI Hatası: {resp.text}"
        except Exception as e:
            return f"Bağlantı Hatası: {e}"