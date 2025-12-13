# path: core/scanners/nuclei_scanner.py
import asyncio
import json
import logging
import shutil
import os
from typing import List, Dict, Any
from core.scanners.base_scanner import BaseScanner

# Standart logger yerine PARS motorunun log mekanizması kullanılacak
# logger = logging.getLogger(__name__)

class NucleiScanner(BaseScanner):
    """
    ProjectDiscovery Nuclei aracı için asenkron sarmalayıcı (wrapper).
    PARS mimarisine uygun olarak non-blocking (bloklamayan) çalışır.
    """

    def __init__(self, log_callback=None, result_callback=None, request_callback=None, *args, **kwargs):
        # BaseScanner __init__ metoduna argümanları iletiyoruz
        # Eğer BaseScanner bu argümanları doğrudan almıyorsa, manuel atama yapıyoruz.
        super().__init__(log_callback, result_callback, request_callback, *args, **kwargs)
        
        # Eğer üst sınıf (BaseScanner) bu atamaları yapmıyorsa garantiye alalım:
        if not hasattr(self, 'log'): self.log = log_callback if log_callback else self._dummy_log
        if not hasattr(self, 'add_result'): self.add_result = result_callback
        
        self.binary_path = self._check_binary()
        self.description = "Advanced vulnerability scanning using ProjectDiscovery Nuclei (Async)"

    def _dummy_log(self, msg, level="INFO"):
        pass

    @property
    def name(self) -> str:
        return "Nuclei Scanner"

    @property
    def category(self) -> str:
        return "NUCLEI"

    def _check_binary(self) -> str:
        """
        Nuclei binary dosyasının sistemde (PATH) olup olmadığını kontrol eder.
        """
        path = shutil.which("nuclei")
        if not path:
            # Windows uyumluluğu için
            path = shutil.which("nuclei.exe")
            
        if not path:
            self.log("Nuclei binary not found in system PATH! Scanner will be disabled.", "CRITICAL")
            return None
        return path

    async def scan(self, target: str, session=None, callback=None, **kwargs) -> List[Dict[str, Any]]:
        """
        Hedef üzerinde asenkron Nuclei taraması gerçekleştirir.
        """
        results = []
        try:
            if not self.binary_path:
                self.log("Scan aborted: Nuclei binary is missing.", "ERROR")
                if self.add_result:
                    self.add_result("NUCLEI", "INFO", "Nuclei binary bulunamadı, tarama atlandı.", 0.0)
                return []

            # kwargs içinden options al, yoksa boş dict
            options = kwargs.get("options", {})
            
            # Nuclei Parametreleri
            cmd_args = [
                "-target", target,
                "-json",
                "-silent",
                "-nc"
            ]

            if options.get("templates"):
                for temp in options["templates"]:
                    cmd_args.extend(["-t", temp])

            rate_limit = str(options.get("rate_limit", 150))
            concurrency = str(options.get("concurrency", 25))
            
            cmd_args.extend(["-rl", rate_limit])
            cmd_args.extend(["-c", concurrency])

            if options.get("tags"):
                cmd_args.extend(["-tags", options["tags"]])

            self.log(f"Starting async Nuclei scan on {target} [RL:{rate_limit}, C:{concurrency}]", "INFO")
            
            # --- ÇAKIŞMA ÖNLEME (FIX) ---
            # Nuclei'nin, PARS'ın Gemini API anahtarını kendi Google Search modülü 
            # sanmasını ve "CX ID eksik" hatası vermesini önlemek için ortamı temizliyoruz.
            nuclei_env = os.environ.copy()
            if "GOOGLE_API_KEY" in nuclei_env:
                del nuclei_env["GOOGLE_API_KEY"]
            if "GOOGLE_API_CX" in nuclei_env:
                del nuclei_env["GOOGLE_API_CX"]
            # ----------------------------

            process = None
            try:
                process = await asyncio.create_subprocess_exec(
                    self.binary_path,
                    *cmd_args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=nuclei_env # Temizlenmiş ortamı kullan
                )

                while True:
                    line = await process.stdout.readline()
                    if not line:
                        break
                    
                    try:
                        decoded_line = line.decode().strip()
                        if not decoded_line:
                            continue
                        
                        vuln_data = json.loads(decoded_line)
                        parsed_vuln = self._parse_nuclei_output(vuln_data)
                        
                        if parsed_vuln:
                            results.append(parsed_vuln)
                            # Bulguyu engine'e raporla
                            self._report_finding(parsed_vuln)
                            # Log çıktısı
                            self.log(f"Nuclei found: {parsed_vuln['name']} ({parsed_vuln['severity']})", "WARNING")

                    except json.JSONDecodeError:
                        pass
                    except Exception as e:
                        self.log(f"Error parsing Nuclei line: {e}", "ERROR")

                await process.wait()

                stderr_output = await process.stderr.read()
                if stderr_output and process.returncode != 0:
                    # Stderr çıktısını decode edip temizleyelim
                    err_msg = stderr_output.decode().strip()
                    if err_msg:
                        # Eğer hata "context deadline exceeded" gibi önemsiz bir şeyse INFO bas
                        if "context deadline exceeded" in err_msg:
                            pass 
                        else:
                            self.log(f"Nuclei stderr output: {err_msg}", "WARNING")

            except asyncio.CancelledError:
                self.log(f"Nuclei scan cancelled for {target}. Terminating process...", "WARNING")
                if process:
                    try:
                        process.terminate()
                        await process.wait()
                    except Exception:
                        pass
                raise

            except Exception as e:
                self.log(f"Critical error executing Nuclei: {e}", "CRITICAL")
                if self.add_result:
                    self.add_result("NUCLEI", "CRITICAL", f"Nuclei Execution Error: {str(e)}", 0.0)

            self.log(f"Nuclei scan completed for {target}. Total findings: {len(results)}", "SUCCESS")
            return results

        finally:
            # Motorun kilitlenmemesi için callback MUTLAKA çağrılmalı
            if callback:
                callback()

    def _parse_nuclei_output(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Nuclei ham JSON çıktısını standart PARS zafiyet formatına dönüştürür.
        """
        try:
            info = data.get("info", {})
            severity = info.get("severity", "unknown").lower()

            if severity not in ["low", "medium", "high", "critical"]:
                return None

            return {
                "type": "vulnerability",
                "scanner": "Nuclei",
                "name": info.get("name", data.get("template-id", "Unknown Issue")),
                "severity": severity,
                "description": info.get("description", "No description provided."),
                "url": data.get("matched-at"),
                "curl_command": data.get("curl-command", ""),
                "matcher_name": data.get("matcher-name", ""),
                "template_id": data.get("template-id"),
                "timestamp": data.get("timestamp"),
                "evidence": data.get("extracted-results", [])
            }
        except Exception as e:
            self.log(f"Error normalising Nuclei data: {e}", "ERROR")
            return None

    def _report_finding(self, vuln_data):
        """
        Bulguyu engine'e raporlar.
        """
        if not hasattr(self, 'add_result') or not self.add_result:
            return

        severity_map = {
            "critical": "CRITICAL",
            "high": "HIGH",
            "medium": "WARNING",
            "low": "INFO"
        }
        
        level = severity_map.get(vuln_data['severity'], "INFO")
        message = f"{vuln_data['name']} detected at {vuln_data['url']}"
        
        # Basit CVSS skor mapping
        cvss_score = 0.0
        if level == "CRITICAL": cvss_score = 9.0
        elif level == "HIGH": cvss_score = 7.0
        elif level == "WARNING": cvss_score = 4.0
        
        self.add_result(
            category="NUCLEI",
            level=level,
            message=message,
            cvss_score=cvss_score,
            poc_data={"url": vuln_data['url'], "evidence": vuln_data.get('evidence')}
        )