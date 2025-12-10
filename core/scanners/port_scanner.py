# path: core/scanners/port_scanner.py

import asyncio
import socket
from typing import Callable, Tuple, Optional
from urllib.parse import urlparse

from core.scanners.base_scanner import BaseScanner

class PortScanner(BaseScanner):
    """
    Hedef sunucu üzerindeki kritik ağ portlarını (TCP) tarar ve
    çalışan servisleri (Banner Grabbing) tespit etmeye çalışır.
    
    V17.2 UPDATE (ANTI-FREEZE):
    - Socket bağlantıları için agresif timeout (2.0s -> 0.7s).
    - SMB/NetBIOS gibi "dondurucu" portlar için ekstra koruma.
    - Blocking I/O sorunlarını çözmek için tamamen executor tabanlı yapı.
    """
    
    # En sık hedef alınan kritik portlar
    TARGET_PORTS = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        139: "NetBIOS",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        1433: "MSSQL",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        6379: "Redis",
        8080: "HTTP-Proxy/Alt",
        8443: "HTTPS-Alt",
        27017: "MongoDB"
    }
    
    # Bağlantı zaman aşımı (saniye) - DÜŞÜRÜLDÜ
    TIMEOUT = 0.7

    @property
    def name(self):
        return "Ağ Port ve Servis Taraması (Anti-Freeze)"

    @property
    def category(self):
        return "SYSTEM" # System/Network kategorisi
        
    def __init__(self, logger, results_callback, request_callback: Callable[[], None]):
        super().__init__(logger, results_callback, request_callback)

    async def scan(self, url: str, session, completed_callback: Callable[[], None]):
        """
        Port tarama mantığını uygular.
        """
        self.log(f"[{self.category}] Hedef sunucu port analizi başlatılıyor (Hızlı Mod)...", "INFO")
        
        try:
            # 1. Hostname ve IP Çözümleme
            parsed = urlparse(url)
            hostname = parsed.netloc.split(':')[0] # Varsa portu temizle
            
            # DNS Çözümleme (Non-Blocking Executor ile)
            try:
                loop = asyncio.get_running_loop()
                target_ip = await loop.run_in_executor(None, socket.gethostbyname, hostname)
                self.log(f"[{self.category}] Hedef IP Çözüldü: {target_ip}", "INFO")
            except Exception as e:
                self.add_result(self.category, "CRITICAL", f"DNS Hatası: {hostname} çözülemedi.", 0)
                completed_callback()
                return

            tasks = []
            
            # 2. Portları Tara (Semaphore ile sınırlı, donmayı önler)
            # Port taraması çok sayıda thread açabilir, bunu 20 ile sınırlayalım.
            sem = asyncio.Semaphore(20)
            
            async def limited_scan(ip, p, s):
                async with sem:
                    return await self._scan_port(ip, p, s)

            for port, service_name in self.TARGET_PORTS.items():
                tasks.append(limited_scan(target_ip, port, service_name))
            
            scan_results = await asyncio.gather(*tasks)
            
            open_ports = [res for res in scan_results if res is not None]
            
            if not open_ports:
                self.add_result(self.category, "INFO", "Açık kritik port tespit edilmedi.", 0)
            else:
                for port, service, banner in open_ports:
                    msg = f"AÇIK PORT: {port} ({service})"
                    level = "WARNING"
                    deduction = 2.0
                    
                    if banner:
                        # Banner temizliği (satır sonlarını sil)
                        clean_banner = banner.strip().replace('\n', ' ').replace('\r', '')[:50]
                        msg += f" | Banner: {clean_banner}"
                        deduction = 4.0
                    
                    # Kritik Servisler
                    if port in [21, 22, 23, 445, 3306, 3389]:
                        level = "HIGH"
                        if port == 23 or port == 21: # Telnet/FTP
                             level = "CRITICAL"
                             msg = f"KRİTİK: Güvensiz protokol ({service}) açık! " + msg
                             deduction = self._calculate_score_deduction("CRITICAL")
                        elif port == 445: # SMB
                             level = "CRITICAL"
                             msg = f"KRİTİK: SMB Servisi (WannaCry/EternalBlue riski)! " + msg
                             deduction = self._calculate_score_deduction("CRITICAL")
                        else:
                             msg = f"RİSK: {service} servisi dışarıya açık. " + msg
                             deduction = self._calculate_score_deduction("HIGH")

                    self.add_result(self.category, level, msg, deduction)

        except Exception as e:
            self.log(f"[{self.category}] Port Tarama Hatası: {str(e)}", "WARNING")
            
        completed_callback()

    async def _scan_port(self, ip: str, port: int, service_name: str) -> Optional[Tuple[int, str, str]]:
        """
        Tek bir portu tarar. Tamamen asenkron ve timeout korumalı.
        """
        try:
            # open_connection, düşük seviyeli bir stream açar.
            # wait_for ile sarmalayarak işletim sistemi timeout'unu eziyoruz.
            conn_coro = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn_coro, timeout=self.TIMEOUT)
            
            banner = ""
            try:
                # Banner Grabbing (Hızlıca veri gönderip cevap bekle)
                if port in [80, 8080, 443]:
                    writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                else:
                    # Diğer servisler için sadece bekle (bazıları connect olunca banner atar)
                    pass
                
                await writer.drain()
                
                # Banner okuma süresi de çok kısa olmalı
                data = await asyncio.wait_for(reader.read(1024), timeout=0.5)
                banner = data.decode('utf-8', errors='ignore').strip()
            except:
                pass # Banner yoksa sorun değil, port açık
            
            writer.close()
            try:
                await writer.wait_closed()
            except: pass
                
            return (port, service_name, banner)

        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None # Kapalı veya Timeout
        except Exception:
            return None