"""
AEGIS core/aegis_scanner.py
============================
Full scanning engine. Each method wraps one tool and writes into
self.results — a structured dict, not a raw text blob.

Tools:
  run_nmap()           port scan + service versions + vuln scripts
  run_web_audit()      parallel HTTP probe of sensitive paths
  detect_web_stack()   fingerprint CMS, framework, security headers
  run_ssl_osint()      pull certificate info and SANs
  run_theharvester()   email / subdomain OSINT
  run_gobuster()       directory and file brute-force
  run_nuclei()         template-based CVE / misconfiguration scanning
  run_zap_scan()       OWASP ZAP active DAST scan
  check_compliance()   flag plaintext services, missing headers, exposed DBs
"""

import socket
import nmap
import requests
import ssl
import subprocess
import json
import concurrent.futures
import warnings
import os

warnings.filterwarnings("ignore", message="Unverified HTTPS request")


class UnifiedAegisEngine:

    def __init__(self, target: str):
        self.target = target
        self.results = {
            "nmap_raw":      "",
            "web_discovery": [],
            "tech_stack":    [],
            "osint":         [],
            "harvester":     [],
            "gobuster":      [],
            "nuclei":        [],
            "zap":           [],
            "compliance":    [],
        }

    # =========================================================================
    # NMAP
    # =========================================================================

    def run_nmap(self, ports="1-1000", stealth=False):
        """
        Port scan + service version detection + vuln scripts.
        -sV   = detect software versions on open ports
        --script=vuln = run all nmap vulnerability scripts
        -Pn   = skip ping (important for firewalled hosts in Docker)
        -T2   = slow/stealthy   -T4 = fast/loud
        """
        nm = nmap.PortScanner()

        try:
            target_host = socket.gethostbyname(self.target)
        except Exception:
            target_host = self.target

        timing = "-T2" if stealth else "-T4"
        args   = f"-sV --script=vuln {timing} -Pn"
        if stealth:
            args += " -sS"

        try:
            nm.scan(target_host, ports=ports, arguments=args)
            report = ""

            if not nm.all_hosts():
                self.results["nmap_raw"] = "[!] Target unreachable or blocking scan"
                return

            for host in nm.all_hosts():
                report += f"\nHost : {host} ({nm[host].hostname()})\n"
                report += f"State: {nm[host].state()}\n"

                for proto in nm[host].all_protocols():
                    for port in sorted(nm[host][proto].keys()):
                        data = nm[host][proto][port]
                        if data.get("state") != "open":
                            continue

                        service = data.get("name", "unknown").upper()
                        version = f"{data.get('product','')} {data.get('version','')}".strip()

                        report += f"\n  Port {port}/{proto}  [{service}]  OPEN\n"
                        if version:
                            report += f"    Version : {version}\n"

                        if "script" in data:
                            for script, output in data["script"].items():
                                low = output.lower()
                                if "not vulnerable" in low:
                                    continue
                                if "cve-" in low or "vulnerable" in low:
                                    report += f"    [!!!] VULN: {script}\n"
                                    for line in output.split("\n"):
                                        if any(k in line for k in ["CVE-", "State:", "IDs:"]):
                                            report += f"          {line.strip()}\n"
                                else:
                                    info = (output.splitlines()[0] if output else "")[:80]
                                    if info:
                                        report += f"    [+] {script}: {info}\n"

            self.results["nmap_raw"] = report or "No open ports found."

        except Exception as e:
            self.results["nmap_raw"] = f"[ENGINE ERROR] {e}"

    # =========================================================================
    # WEB AUDIT — parallel HTTP probe
    # =========================================================================

    def _check_path(self, port: int, path: str):
        scheme = "https" if port == 443 else "http"
        url    = f"{scheme}://{self.target}:{port}{path}"
        try:
            r = requests.get(
                url,
                headers={"User-Agent": "Mozilla/5.0 (AegisScanner/2.0)"},
                timeout=3,
                allow_redirects=False,
                verify=False,
            )
            if r.status_code in [200, 301, 302, 401, 403]:
                return f"[HTTP {r.status_code}] {url}  ({len(r.content)} bytes)"
        except Exception:
            return None

    def run_web_audit(self):
        """
        Parallel probe of ~35 high-value paths across common web ports.
        Catches exposed .env files, admin panels, git repos, backups, etc.
        """
        paths = [
            "/.env", "/.env.bak", "/.env.local", "/.env.production",
            "/.git", "/.git/config", "/.git/HEAD",
            "/admin", "/admin/", "/administrator", "/wp-admin",
            "/backup", "/backup.zip", "/backup.sql", "/backup.tar.gz",
            "/config.php", "/config.yml", "/config.json",
            "/uploads", "/upload",
            "/api", "/api/v1", "/api/v2", "/swagger", "/swagger-ui.html",
            "/phpmyadmin", "/pma",
            "/wp-config.php", "/wp-content",
            "/server-status", "/server-info",
            "/.htpasswd", "/.htaccess",
            "/robots.txt", "/sitemap.xml",
            "/debug", "/console",
            "/actuator", "/actuator/env", "/actuator/health",
        ]

        ports   = [80, 443, 8080, 8081, 8082, 8443]
        results = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
            futures = {
                ex.submit(self._check_path, p, path): (p, path)
                for p in ports for path in paths
            }
            for fut in concurrent.futures.as_completed(futures):
                r = fut.result()
                if r:
                    results.append(r)

        self.results["web_discovery"] = results

    # =========================================================================
    # TECHNOLOGY FINGERPRINT
    # =========================================================================

    def detect_web_stack(self):
        findings = []
        cms_sigs = {
            "wp-content":  "WordPress",
            "wp-json":     "WordPress (REST API exposed)",
            "laravel":     "Laravel",
            "django":      "Django",
            "react":       "React",
            "angular":     "Angular",
            "vue.js":      "Vue.js",
            "joomla":      "Joomla",
            "drupal":      "Drupal",
            "magento":     "Magento",
        }
        sec_headers = [
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Content-Security-Policy",
            "Referrer-Policy",
        ]

        for port in [80, 443, 8080, 8081, 8082]:
            scheme = "https" if port == 443 else "http"
            try:
                r = requests.get(
                    f"{scheme}://{self.target}:{port}",
                    timeout=4, verify=False,
                    headers={"User-Agent": "Mozilla/5.0"},
                )
                h    = r.headers
                html = r.text.lower()

                if srv := h.get("Server"):
                    findings.append(f"Server: {srv}  (port {port})")
                if px := h.get("X-Powered-By"):
                    findings.append(f"X-Powered-By: {px}  (port {port})")

                for sig, name in cms_sigs.items():
                    if sig in html:
                        findings.append(f"{name} detected  (port {port})")

                missing = [hdr for hdr in sec_headers if hdr not in h]
                if missing:
                    findings.append(
                        f"[SECURITY] Missing headers on port {port}: {', '.join(missing)}"
                    )

            except Exception:
                continue

        self.results["tech_stack"] = findings or ["No web stack detected"]

    # =========================================================================
    # SSL OSINT
    # =========================================================================

    def run_ssl_osint(self):
        """Grab cert metadata — issuer, CN, SANs (hidden subdomains), expiry."""
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=self.target) as s:
                s.settimeout(4)
                s.connect((self.target, 443))
                cert = s.getpeercert()

            subj   = dict(x[0] for x in cert["subject"])
            issuer = dict(x[0] for x in cert["issuer"])

            self.results["osint"] += [
                f"SSL Issuer   : {issuer.get('organizationName', 'Unknown')}",
                f"SSL CN       : {subj.get('commonName', 'Unknown')}",
                f"SSL Expires  : {cert.get('notAfter', '')}",
            ]
            for san_type, val in cert.get("subjectAltName", []):
                if san_type == "DNS":
                    self.results["osint"].append(f"SSL SAN (subdomain): {val}")

        except Exception:
            pass

    # =========================================================================
    # theHarvester — email / subdomain OSINT
    # =========================================================================

    def run_theharvester(self, limit: int = 50):
        """
        Finds emails, subdomains, IPs from public sources.
        Most useful against real domain names (e.g. target.com).
        Install: apt install theharvester
        """
        findings = []
        out_file = f"/tmp/harv_{self.target.replace('.','_')}"

        try:
            subprocess.run(
                [
                    "theHarvester",
                    "-d", self.target,
                    "-b", "bing,urlscan,hackertarget,dnsdumpster",
                    "-l", str(limit),
                    "-f", out_file,
                ],
                capture_output=True, text=True, timeout=60,
            )

            json_path = f"{out_file}.json"
            if os.path.exists(json_path):
                with open(json_path) as f:
                    data = json.load(f)
                for email in data.get("emails", [])[:20]:
                    findings.append(f"[EMAIL]     {email}")
                for host in data.get("hosts", [])[:20]:
                    findings.append(f"[SUBDOMAIN] {host}")
                for ip in data.get("ips", [])[:10]:
                    findings.append(f"[IP]        {ip}")

        except FileNotFoundError:
            findings.append("[SKIP] theHarvester not installed (apt install theharvester)")
        except subprocess.TimeoutExpired:
            findings.append("[TIMEOUT] theHarvester exceeded 60s")
        except Exception as e:
            findings.append(f"[ERROR] theHarvester: {e}")

        self.results["harvester"] = findings or ["[INFO] No OSINT data found"]
        self.results["osint"].extend(findings)

    # =========================================================================
    # Gobuster — directory / file discovery
    # =========================================================================

    def run_gobuster(self, port: int = None):
        """
        Brute-forces directories and files using a wordlist.
        Finds /backup_2019/, /old_admin/, /.env.prod etc.
        Install: apt install gobuster dirb
        """
        if port is None:
            port = self._detect_web_port()

        scheme   = "https" if port == 443 else "http"
        url      = f"{scheme}://{self.target}:{port}"
        findings = []

        wordlists = [
            "/usr/share/dirb/wordlists/common.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/nmap.lst",
        ]
        wordlist = next((w for w in wordlists if os.path.exists(w)), None)

        if not wordlist:
            self.results["gobuster"] = [
                "[SKIP] No wordlist found. Run: apt install dirb"
            ]
            return

        try:
            result = subprocess.run(
                [
                    "gobuster", "dir",
                    "-u", url,
                    "-w", wordlist,
                    "-t", "30",
                    "-q",
                    "--no-error",
                    "--timeout", "10s",
                    "-s", "200,204,301,302,307,401,403",
                    "-x", "php,html,txt,bak,sql,zip,xml",
                ],
                capture_output=True, text=True, timeout=180,
            )
            for line in result.stdout.splitlines():
                line = line.strip()
                if line and not line.startswith("="):
                    findings.append(line)

        except FileNotFoundError:
            findings.append("[SKIP] Gobuster not installed (apt install gobuster)")
        except subprocess.TimeoutExpired:
            findings.append("[TIMEOUT] Gobuster exceeded 3 minutes")
        except Exception as e:
            findings.append(f"[ERROR] Gobuster: {e}")

        self.results["gobuster"] = findings or ["[INFO] No paths found by Gobuster"]

    # =========================================================================
    # Nuclei — template-based CVE / misconfiguration scanning
    # =========================================================================

    def run_nuclei(self):
        """
        Runs 7000+ community templates — finds CVEs, default creds,
        exposed panels, CORS issues, and much more.
        Install: apt install nuclei  then: nuclei -update-templates
        """
        port     = self._detect_web_port()
        scheme   = "https" if port == 443 else "http"
        url      = f"{scheme}://{self.target}:{port}"
        findings = []

        try:
            result = subprocess.run(
                [
                    "nuclei",
                    "-u", url,
                    "-t", "cves/",
                    "-t", "exposures/",
                    "-t", "misconfigurations/",
                    "-t", "default-logins/",
                    "-severity", "medium,high,critical",
                    "-jsonl",
                    "-silent",
                    "-timeout", "5",
                    "-rate-limit", "50",
                ],
                capture_output=True, text=True, timeout=300,
            )

            for line in result.stdout.splitlines():
                try:
                    f        = json.loads(line)
                    severity = f.get("info", {}).get("severity", "info").upper()
                    name     = f.get("info", {}).get("name", "Unknown")
                    matched  = f.get("matched-at", url)
                    tid      = f.get("template-id", "")
                    findings.append(f"[{severity}] {name}  —  {matched}  ({tid})")
                except json.JSONDecodeError:
                    if line.strip():
                        findings.append(line.strip())

        except FileNotFoundError:
            findings.append("[SKIP] Nuclei not installed")
        except subprocess.TimeoutExpired:
            findings.append("[TIMEOUT] Nuclei exceeded 5 minutes")
        except Exception as e:
            findings.append(f"[ERROR] Nuclei: {e}")

        self.results["nuclei"] = findings or ["[INFO] No findings from Nuclei"]

    # =========================================================================
    # OWASP ZAP — active web application DAST scanner
    # =========================================================================

    def run_zap_scan(self, port: int = None):
        """
        ZAP actively attacks the web app to find XSS, SQLi, CSRF,
        insecure cookies, path traversal, open redirects, and more.

        Requires ZAP running as a daemon via docker-compose.
        Uses docker exec to communicate with ZAP API (WSL2 compatible).
        """
        if port is None:
            port = self._detect_web_port()

        scheme     = "https" if port == 443 else "http"
        target_url = f"{scheme}://{self.target}:{port}"
        findings   = []

        ZAP_KEY = "aegis_zap_key"
        ZAP_CONTAINER = "aegis_framework-zap-1"
        ZAP_BASE = "http://localhost:8080"

        def zap_api(endpoint, params=None):
            """Call ZAP API via docker exec (WSL2 compatible)."""
            param_str = ""
            if params:
                param_str = "&".join(f"{k}={v}" for k, v in params.items())
            url = f"{ZAP_BASE}{endpoint}?apikey={ZAP_KEY}"
            if param_str:
                url += f"&{param_str}"
            result = subprocess.run(
                ["docker", "exec", ZAP_CONTAINER, "curl", "-s", url],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode != 0:
                raise Exception(f"docker exec failed: {result.stderr}")
            return json.loads(result.stdout)

        try:
            import time

            # Step 1: Spider the target
            spider_data = zap_api("/JSON/spider/action/scan/",
                                   {"url": target_url})
            spider_id = spider_data.get("scan")

            # Wait for spider to finish
            for _ in range(40):
                status = zap_api("/JSON/spider/view/status/",
                                  {"scanId": str(spider_id)}).get("status", "0")
                if status == "100":
                    break
                time.sleep(3)

            # Step 2: Active scan
            scan_data = zap_api("/JSON/ascan/action/scan/",
                                 {"url": target_url})
            scan_id = scan_data.get("scan")

            for _ in range(60):
                status = zap_api("/JSON/ascan/view/status/",
                                  {"scanId": str(scan_id)}).get("status", "0")
                if status == "100":
                    break
                time.sleep(3)

            # Step 3: Collect alerts
            alerts = zap_api("/JSON/alert/view/alerts/",
                              {"baseurl": target_url}).get("alerts", [])

            for alert in alerts:
                risk = alert.get("risk", "Informational").upper()
                name = alert.get("alert", "Unknown")
                url = alert.get("url", target_url)
                desc = alert.get("description", "")[:120]
                findings.append(f"[{risk}] {name}  —  {url}\n          {desc}")

        except subprocess.TimeoutExpired:
            findings.append("[SKIP] ZAP scan timed out.")
        except json.JSONDecodeError as e:
            findings.append(f"[ERROR] ZAP: Invalid response — {e}")
        except Exception as e:
            findings.append(f"[ERROR] ZAP: {e}")

        self.results["zap"] = findings or ["[INFO] No alerts from ZAP"]

    # =========================================================================
    # COMPLIANCE CHECK
    # =========================================================================

    def check_compliance(self):
        raw    = self.results["nmap_raw"]
        tech   = " ".join(self.results["tech_stack"])
        issues = []

        if "FTP"    in raw: issues.append("Unencrypted FTP (use SFTP/FTPS)")
        if "TELNET" in raw: issues.append("Telnet exposed (use SSH)")
        if "HTTP"   in raw and "443" not in raw:
            issues.append("Plaintext HTTP with no HTTPS")

        if "Missing headers" in tech:
            issues.append("Security headers missing (CSP, HSTS, X-Frame-Options)")

        exposed = {
            "3306":  "MySQL exposed to network",
            "5432":  "PostgreSQL exposed to network",
            "27017": "MongoDB exposed to network",
            "6379":  "Redis exposed (likely unauthenticated)",
            "9200":  "Elasticsearch exposed",
            "2375":  "Docker API exposed — CRITICAL, full host takeover possible",
        }
        for p, msg in exposed.items():
            if f"Port {p}" in raw:
                issues.append(f"[CRITICAL] {msg}")

        self.results["compliance"] = (
            [f"[ALERT] {i}" for i in issues] or ["No compliance issues detected"]
        )

    # =========================================================================
    # HELPER
    # =========================================================================

    def _detect_web_port(self) -> int:
        nmap_text = self.results.get("nmap_raw", "")
        for port in [80, 443, 8080, 8081, 8082]:
            if f"Port {port}" in nmap_text:
                return port
        return 80