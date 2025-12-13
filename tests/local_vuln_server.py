# Bu dosya, PARS motorunu test etmek için kasıtlı olarak savunmasız bırakılmış bir test sunucusudur.
# Race Condition, XSS, SQLi ve IDOR zafiyetlerini simüle eder.

import sys # Hata durumunda çıkış yapmak için gerekli

# --- KRİTİK BAĞIMLILIK KONTROLÜ ---
# Flask'ın kurulu olup olmadığını kontrol eder. Kurulum hatasını direkt olarak gösterir.
try:
    from flask import Flask, request, jsonify
    import time
    import threading
except ImportError:
    print("\n" + "="*70)
    print("\033[91m[KRİTİK HATA] Flask modülü (veya bağımlılıkları) bulunamadı!")
    print("\033[93mLütfen aşağıdaki komutu çalıştırarak Flask'ı kurun ve tekrar deneyin:\033[0m")
    print("\n\t\033[92m>>> python -m pip install Flask <<<\033[0m\n")
    print("="*70 + "\n")
    sys.exit(1)

app = Flask(__name__)

# --- GÖRSELLEŞTİRME YARDIMCISI ---
def log_race_event(msg):
    """Race condition anını terminalde renkli/belirgin gösterir."""
    print(f"\033[91m[RACE ALERT] {msg}\033[0m")

def log_info(msg):
    """Log info messages to the console."""
    print(f"\033[94m[INFO] {msg}\033[0m")

# --- GLOBAL STATE (Database Simulation) ---
# Race Condition testi için paylaşılan durum
GLOBAL_DB = {
    "coupons": {
        "RACE2025": {"valid": True, "discount": 50, "usage_count": 0}
    },
    "users": {
        "101": {"balance": 1000, "name": "Admin User"}, # IDOR testinde string ID'ye izin vermek için key'ler string yapıldı
        "102": {"balance": 50, "name": "Guest User"}
    },
    "inventory": {
        "item_1": 1 # Sadece 1 adet stok var
    }
}

@app.route('/')
def home():
    return """
    <h1>PARS Vulnerability Lab v2.1</h1>
    <p>Target Endpoints:</p>
    <ul>
        <li>POST /api/v1/coupon/apply (Race Condition - Coupon)</li>
        <li>POST /api/v1/transfer (Race Condition - Money)</li>
        <li>GET /search?q= (XSS)</li>
        <li>GET /user?id= (IDOR)</li>
    </ul>
    """

# --- 1. RACE CONDITION SENARYOSU: KUPON KULLANIMI ---
@app.route('/api/v1/coupon/apply', methods=['POST'])
def apply_coupon():
    """
    ZAFİYET: Kupon kontrolü ile kullanımı arasında 'time.sleep' var.
    """
    try:
        data = request.json
        code = data.get('code')
    except Exception:
        return jsonify({"error": "Invalid JSON"}), 400
    
    if not code:
        return jsonify({"error": "Code required"}), 400

    thread_id = threading.get_ident()
    log_info(f"Thread-{thread_id} kupon kontrolüne başladı: {code}")

    # 1. Aşama: Kontrol (Check)
    if code in GLOBAL_DB["coupons"] and GLOBAL_DB["coupons"][code]["valid"]:
        
        log_info(f"Thread-{thread_id} -> KUPON GEÇERLİ. İşlem yapılıyor...")

        # --- ZAFİYET PENCERESİ BAŞLANGIÇ ---
        # Veritabanı gecikmesini simüle ediyoruz (300ms)
        time.sleep(0.3) 
        # --- ZAFİYET PENCERESİ BİTİŞ ---

        # 2. Aşama: Kullanım (Act / Update)
        # Kritik Bölge: Buraya birden fazla thread aynı anda girmemeliydi!
        
        current_usage = GLOBAL_DB["coupons"][code]["usage_count"]
        if current_usage > 0:
            log_race_event(f"!!! RACE CONDITION TESPİT EDİLDİ !!! Thread-{thread_id} geçersiz kuponu kullandı!")
        
        GLOBAL_DB["coupons"][code]["valid"] = False # Kuponu geçersiz kıl
        GLOBAL_DB["coupons"][code]["usage_count"] += 1
        
        log_info(f"Thread-{thread_id} -> Kupon kullanıldı. Toplam Kullanım: {GLOBAL_DB['coupons'][code]['usage_count']}")

        return jsonify({
            "status": "success",
            "message": f"Coupon {code} applied!",
            "new_usage_count": GLOBAL_DB["coupons"][code]["usage_count"],
            "thread_id": thread_id
        }), 200
    else:
        log_info(f"Thread-{thread_id} -> KUPON GEÇERSİZ.")
        return jsonify({"status": "failed", "message": "Coupon invalid or already used."}), 400

# --- 2. RACE CONDITION SENARYOSU: PARA TRANSFERİ ---
@app.route('/api/v1/transfer', methods=['POST'])
def transfer_money():
    """
    ZAFİYET: Bakiye kontrolü ve düşümü atomik değil.
    """
    try:
        amount = request.json.get('amount', 10)
        user_id = "101" 
    except Exception:
        return jsonify({"error": "Invalid JSON"}), 400
    
    current_balance = GLOBAL_DB["users"][user_id]["balance"]
    
    if current_balance >= amount:
        time.sleep(0.2) # Gecikme
        
        GLOBAL_DB["users"][user_id]["balance"] = current_balance - amount
        return jsonify({"status": "transferred", "new_balance": GLOBAL_DB["users"][user_id]["balance"]}), 200
    else:
        return jsonify({"error": "Insufficient funds"}), 402

# --- 3. XSS (Reflected) ---
@app.route('/search')
def search():
    query = request.args.get('q', '')
    return f"<h1>Search Results for: {query}</h1>"

# --- 4. IDOR ---
@app.route('/user')
def get_user():
    # Artık int() zorlaması yapılmıyor. IDOR'un string/int ID denemelerini kabul eder.
    user_id = request.args.get('id', "102") 
    
    # Oturum kontrolü yok - Zafiyet burada simüle ediliyor.
    if user_id in GLOBAL_DB["users"]:
        
        # IDOR'un başarısını göstermek için hassas olmayan veriyi döndürür
        return jsonify(GLOBAL_DB["users"][user_id]) 
    return jsonify({"error": "User not found"}), 404

@app.after_request
def add_headers(response):
    response.headers['X-Powered-By'] = 'PHP/5.6.40' 
    response.headers['Server'] = 'Apache/2.4.1'
    response.headers['Access-Control-Allow-Origin'] = '*'
    # HTTP Smuggling/Genel testler için simülasyon başlığı kaldırıldı.
    # response.headers['Transfer-Encoding'] = 'chunked' # Kaldırıldı
    return response

if __name__ == '__main__':
    print("\n" + "="*50)
    print("[*] PARS VULNERABILITY LAB v2.1 STARTED")
    print("[*] Race Condition Target: http://127.0.0.1:5000/api/v1/coupon/apply")
    print("[*] Payload Code: 'RACE2025'")
    print("="*50 + "\n")
    # Threaded=True çoklu istekleri simüle etmek için şarttır.
    # Güvenli başlatma için debug=True kaldırıldı, threaded=True korundu.
    app.run(port=5000, threaded=True)