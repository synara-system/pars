# path: tests/test_oob_listener.py

import sys
import os
import time
import logging

# Proje kök dizinini path'e ekle (Modüllerin bulunabilmesi için)
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.oob_listener import OOBListener

# Basit bir logger yapılandırması
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger("TestLogger")

def mock_log(message, level="INFO"):
    print(f"[{level}] {message}")

def test_callback(token, interaction):
    print(f"\n[CALLBACK TETİKLENDİ] Token: {token}")
    print(f"    -> Protokol: {interaction.protocol}")
    print(f"    -> Kaynak IP: {interaction.source_ip}")
    print(f"    -> Veri: {interaction.data}")

def main():
    print("--- OOB Listener (The Signal Hunter) Bağımsız Testi Başlıyor ---\n")
    
    # 1. Listener'ı Başlat
    listener = OOBListener(mock_log)
    
    # 2. Token Üretimi (HTTP)
    print("[1] HTTP Token Üretiliyor...")
    http_token = listener.generate_token(module_name="TEST_MODULE", protocol="HTTP", callback=test_callback)
    http_address = listener.get_payload_address(http_token)
    print(f"    -> Token: {http_token}")
    print(f"    -> Adres: {http_address}")
    
    # 3. Token Üretimi (DNS)
    print("\n[2] DNS Token Üretiliyor...")
    dns_token = listener.generate_token(module_name="TEST_MODULE", protocol="DNS", callback=test_callback)
    dns_address = listener.get_payload_address(dns_token)
    print(f"    -> Token: {dns_token}")
    print(f"    -> Adres: {dns_address}")
    
    # 4. Durum Kontrolü (Henüz Hit Yok)
    status = listener.check_token_status(http_token)
    print(f"\n[3] Token Durumu Kontrolü (Beklenen: WAITING): {status}")
    
    # 5. Sinyal Simülasyonu (Hit!)
    print("\n[4] Dış Dünyadan Sinyal Simüle Ediliyor (HIT!)...")
    listener.register_hit(http_token, source_ip="192.168.1.100", data="GET /?id=1 HTTP/1.1")
    
    # 6. Sonuç Kontrolü
    status_after = listener.check_token_status(http_token)
    print(f"\n[5] Token Durumu Kontrolü (Beklenen: HIT): {status_after}")
    
    interactions = listener.get_interactions(http_token)
    if interactions:
        print(f"    -> Yakalanan Etkileşim Sayısı: {len(interactions)}")
    else:
        print("    -> HATA: Etkileşim kaydedilmedi!")

    print("\n--- Test Tamamlandı ---")

if __name__ == "__main__":
    main()