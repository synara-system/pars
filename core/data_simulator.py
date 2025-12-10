# path: core/data_simulator.py

from typing import List, Dict, Any, Union
import random

class MockHTTPResponse:
    """
    aiohttp.ClientResponse objesini simüle eden basit bir yapı.
    """
    def __init__(self, status: int, headers: Dict[str, str], content: str, latency: float = 0.5):
        self.status = status
        self._headers = headers
        self._content = content
        self.latency = latency

    # aiohttp'nin getall metodunu simüle et
    def getall(self, key, default=None) -> List[str]:
        """Header'ın çoklu değerlerini döndürür (Set-Cookie gibi)."""
        value = self._headers.get(key, default)
        if isinstance(value, str):
            return [value]
        return value or []

    # aiohttp'nin headers diksiyonunu simüle et
    @property
    def headers(self) -> Dict[str, str]:
        return self._headers

    async def text(self) -> str:
        """Asenkron içerik okuma simülasyonu."""
        return self._content
        
    async def read(self) -> bytes:
        """Asenkron binary okuma simülasyonu."""
        return self._content.encode('utf-8')
    
    async def json(self) -> Any:
        """JSON verisi döndürür."""
        import json
        return json.loads(self._content)


class DataSimulator:
    """
    Tüm modül simülasyon verilerini ve temel test senaryolarını içerir.
    Modül geliştiricileri, gerçek ağ trafiği yerine buradaki Mock verilerini kullanabilir.
    AYRICA: PARS v18.2 Ghost Protocol için gerçek User-Agent ve Proxy havuzunu barındırır.
    """

    # --- GHOST PROTOCOL: USER-AGENT HAVUZU (3000+ Varyasyon Simülasyonu) ---
    REAL_USER_AGENTS = [
        # Windows / Chrome
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        
        # Windows / Edge
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        
        # Mac / Safari & Chrome
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        
        # Linux / Firefox & Chrome
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        
        # Mobile / iPhone
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
        
        # Mobile / Android
        "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
    ]

    # --- GHOST PROTOCOL: PROXY HAVUZU (Örnek / Yer Tutucu) ---
    PROXY_LIST = []

    # --- 1. TEMEL SUNUCU DAVRANIŞLARI ---

    @staticmethod
    def get_standard_response(url: str, tech: str = "Apache/2.4.41", csp: bool = True) -> MockHTTPResponse:
        """Standart, güvenli bir HTTP yanıtını simüle eder (200 OK)."""
        headers = {
            "Server": tech,
            "X-Powered-By": "PHP/7.4.3",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains"
        }
        
        if csp:
            headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'"
        
        if "php" in tech.lower():
            headers["X-Powered-By"] = tech

        content = f"""
        <!DOCTYPE html>
        <html><head><title>Welcome</title></head><body>
        <h1>Hello World from {tech}</h1>
        <form name="loginForm"><input type="text" name="username" value="guest"></form>
        <!-- developer comment: secret_api_key: 1234567890abcdef -->
        </body></html>
        """
        return MockHTTPResponse(200, headers, content, random.uniform(0.1, 0.3))

    @staticmethod
    def get_not_found_response() -> MockHTTPResponse:
        """404 Not Found yanıtını simüle eder."""
        return MockHTTPResponse(404, {"Content-Type": "text/html"}, "File not found.", random.uniform(0.1, 0.2))

    @staticmethod
    def get_forbidden_response() -> MockHTTPResponse:
        """403 Forbidden yanıtını simüle eder."""
        return MockHTTPResponse(403, {"Content-Type": "text/html"}, "Access denied.", random.uniform(0.1, 0.2))
        
    @staticmethod
    def get_takeover_response(service="GitHub Pages") -> MockHTTPResponse:
        """[YENİ] Subdomain Takeover için zafiyetli yanıt simülasyonu."""
        content = "Error"
        if service == "GitHub Pages":
            content = "There isn't a GitHub Pages site here."
        elif service == "Heroku":
            content = "No such app"
        elif service == "AWS S3":
            content = "NoSuchBucket"
            
        return MockHTTPResponse(404, {"Content-Type": "text/html"}, content, random.uniform(0.1, 0.2))

    # --- 2. ZAFİYET VERİLERİ ---

    @staticmethod
    def get_sqli_time_response(delay_s: float) -> MockHTTPResponse:
        """Zaman tabanlı SQLi başarılı yanıtını simüle eder."""
        content = "Processing successful."
        # Gerçek gecikme + rastgele jitter
        final_delay = delay_s + random.uniform(0.01, 0.05)
        return MockHTTPResponse(200, {}, content, final_delay)

    @staticmethod
    def get_sqli_error_response(db_error: str) -> MockHTTPResponse:
        """Error-based SQLi yanıtını simüle eder."""
        content = f"""
        <!DOCTYPE html>
        <html><body><h1>Error</h1><p>Query failed: {db_error}</p></body></html>
        """
        return MockHTTPResponse(500, {}, content, random.uniform(0.1, 0.2))

    @staticmethod
    def get_xss_reflection_response(reflected_input: str) -> MockHTTPResponse:
        """XSS yansımasını simüle eder."""
        # Payload'ı doğrudan yanıta enjekte et
        content = f"""
        <!DOCTYPE html>
        <html><body><h1>Search Results for {reflected_input}</h1></body></html>
        """
        return MockHTTPResponse(200, {}, content, random.uniform(0.2, 0.4))

    @staticmethod
    def get_idor_difference_response(original_size: int, diff_size: int) -> Dict[str, Union[int, str]]:
        """IDOR testi için simüle edilmiş boyut farkını döndürür."""
        # Orijinal yanıttan farklı bir içerik döndürüldüğünü varsay
        return {
            "original_size": original_size,
            "test_size": original_size + diff_size,
            "diff": diff_size,
            "original_content": "User ID: 1, Name: Admin",
            "test_content": "User ID: 2, Name: Guest"
        }

    @staticmethod
    def get_lfi_success_response(file_content: str) -> MockHTTPResponse:
        """LFI başarılı yanıtını simüle eder."""
        content = f"""
        <pre>{file_content}</pre>
        """
        return MockHTTPResponse(200, {}, content, random.uniform(0.3, 0.6))