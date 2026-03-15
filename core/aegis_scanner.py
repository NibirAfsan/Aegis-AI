import socket
import nmap
import requests
import ssl
import concurrent.futures


class UnifiedAegisEngine:

    def __init__(self, target):
        self.target = target

        self.results = {
            "nmap_raw": "",
            "web_discovery": [],
            "osint": [],
            "compliance": [],
            "tech_stack": []
        }

    # ------------------------------------------------
    # NMAP SCANNER
    # ------------------------------------------------

    def run_nmap(self, ports="1-1000", stealth=False):

        nm = nmap.PortScanner()

        try:
            target_host = socket.gethostbyname(self.target)
        except Exception:
            target_host = self.target

        timing = "-T2" if stealth else "-T4"

        args = f"-sV --script=vuln {timing} -Pn"

        try:

            nm.scan(target_host, ports=ports, arguments=args)

            report = ""

            if not nm.all_hosts():
                report = "[!] Target unreachable or blocking scan\n"

            for host in nm.all_hosts():

                report += f"\nTarget: {host} ({nm[host].hostname()})\n"

                for proto in nm[host].all_protocols():

                    ports_found = nm[host][proto].keys()

                    for port in sorted(ports_found):

                        data = nm[host][proto][port]

                        state = data.get("state")

                        if state != "open":
                            continue

                        service = data.get("name", "unknown").upper()

                        version = f"{data.get('product','')} {data.get('version','')}".strip()

                        report += f"\n Port {port} [{service}] : OPEN\n"

                        if version:
                            report += f"  VERSION: {version}\n"

                        if "script" in data:

                            for script, output in data["script"].items():

                                lower = output.lower()

                                if "not vulnerable" in lower:
                                    continue

                                if "cve-" in lower or "vulnerable" in lower:

                                    report += f"  [!!!] VULNERABILITY: {script}\n"

                                    for line in output.split("\n"):

                                        if "CVE-" in line:
                                            report += f"      {line.strip()}\n"

                                else:

                                    info = output.splitlines()[0] if output else ""

                                    report += f"  [+] INFO: {script} -> {info[:60]}\n"

            self.results["nmap_raw"] = report if report else "No open ports discovered."

        except Exception as e:

            self.results["nmap_raw"] = f"[ENGINE ERROR] {str(e)}"

    # ------------------------------------------------
    # WEB AUDIT (PARALLEL)
    # ------------------------------------------------

    def check_path(self, port, path):

        scheme = "https" if port == 443 else "http"

        url = f"{scheme}://{self.target}:{port}{path}"

        headers = {
            "User-Agent": "AegisScanner/1.0"
        }

        try:

            r = requests.get(
                url,
                headers=headers,
                timeout=3,
                allow_redirects=False,
                verify=False
            )

            if r.status_code == 200:
                return f"[!!!] EXPOSED RESOURCE: {url}"

        except Exception:
            return None

    def run_web_audit(self):

        findings = []

        web_ports = [80, 443, 8080, 8081, 8082]

        paths = [
            "/.env",
            "/admin",
            "/backup",
            "/.git",
            "/.git/config",
            "/backup.sql",
            "/config.php",
            "/uploads",
            "/api",
            "/phpmyadmin"
        ]

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:

            futures = []

            for port in web_ports:
                for path in paths:

                    futures.append(
                        executor.submit(self.check_path, port, path)
                    )

            for future in futures:

                result = future.result()

                if result:
                    findings.append(result)

        self.results["web_discovery"] = findings

    # ------------------------------------------------
    # WEB TECHNOLOGY DETECTION
    # ------------------------------------------------

    def detect_web_stack(self):

        technologies = []

        urls = [
            f"http://{self.target}",
            f"https://{self.target}"
        ]

        for url in urls:

            try:

                r = requests.get(url, timeout=4, verify=False)

                headers = r.headers

                server = headers.get("Server", "")

                powered = headers.get("X-Powered-By", "")

                if server:
                    technologies.append(f"Server: {server}")

                if powered:
                    technologies.append(f"X-Powered-By: {powered}")

                html = r.text.lower()

                if "wp-content" in html:
                    technologies.append("WordPress detected")

                if "laravel" in html:
                    technologies.append("Laravel detected")

                if "django" in html:
                    technologies.append("Django detected")

                if "react" in html:
                    technologies.append("React detected")

            except Exception:
                continue

        self.results["tech_stack"] = technologies

    # ------------------------------------------------
    # SSL OSINT
    # ------------------------------------------------

    def run_ssl_osint(self):

        try:

            ctx = ssl.create_default_context()

            with ctx.wrap_socket(
                socket.socket(),
                server_hostname=self.target
            ) as s:

                s.settimeout(4)

                s.connect((self.target, 443))

                cert = s.getpeercert()

                subject = dict(x[0] for x in cert["subject"])

                issuer = dict(x[0] for x in cert["issuer"])

                self.results["osint"].append(
                    f"SSL Issuer: {issuer.get('organizationName','Unknown')}"
                )

                self.results["osint"].append(
                    f"SSL Common Name: {subject.get('commonName','Unknown')}"
                )

        except Exception:
            pass

    # ------------------------------------------------
    # SIMPLE EMAIL OSINT
    # ------------------------------------------------

    def run_osint(self):

        self.results["osint"].append(
            f"Possible admin email: admin@{self.target}"
        )

    # ------------------------------------------------
    # COMPLIANCE CHECK
    # ------------------------------------------------

    def check_compliance(self):

        raw = self.results["nmap_raw"]

        issues = []

        if "FTP" in raw:
            issues.append("Unencrypted FTP service")

        if "HTTP" in raw and "HTTPS" not in raw:
            issues.append("Plaintext HTTP service")

        if issues:

            self.results["compliance"] = [
                f"[ALERT] {', '.join(issues)}"
            ]

        else:

            self.results["compliance"] = ["No compliance issues detected"]