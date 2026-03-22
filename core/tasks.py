"""
AEGIS core/tasks.py
====================
Celery background tasks. Django fires these with .delay() and returns
to the browser immediately. The browser polls /scan-status/<task_id>/
every 3 seconds to get progress updates.

WHY CELERY:
  Without it: browser waits → nmap takes 20 min → browser times out → user sees nothing
  With it:    browser gets task_id in 50ms → polls every 3s → sees live progress bar

Start the worker (separate terminal):
  celery -A aegis_web worker --loglevel=info

Monitor tasks (Flower UI at http://localhost:5555):
  celery -A aegis_web flower
"""

from celery import shared_task
from core.aegis_scanner import UnifiedAegisEngine
from scanner_ui.models import ScanResult   # correct import for YOUR project


@shared_task(bind=True)
def run_full_scan(self, target: str, scan_type: str,
                  stealth: bool = False, run_zap: bool = False):
    """
    Main background scan task.
    bind=True gives us `self` so we can push progress updates.
    """

    def progress(pct: int, msg: str):
        self.update_state(
            state='PROGRESS',
            meta={'current': pct, 'total': 100, 'message': msg}
        )

    scan_record = None

    try:
        # Create DB record immediately so we have an ID to return
        scan_record = ScanResult.objects.create(
            target=target,
            scan_mode=scan_type,
            status='RUNNING',
        )

        port_map = {
            "lab":    "8081-8083",
            "web":    None,
            "top100": "80,443,8080,22,21,25,53,110,143,3306,5432",
            "full":   "1-65535",
        }
        ports  = port_map.get(scan_type)
        engine = UnifiedAegisEngine(target)

        progress(5,  "Initialising engine...")
        progress(10, "Running Nmap scan...")
        engine.run_nmap(ports=ports, stealth=stealth)

        progress(30, "Running web directory audit...")
        engine.run_web_audit()

        progress(40, "Fingerprinting technology stack...")
        engine.detect_web_stack()

        progress(50, "Running SSL OSINT...")
        engine.run_ssl_osint()

        progress(55, "Running theHarvester OSINT...")
        engine.run_theharvester()

        progress(65, "Running Gobuster directory scan...")
        engine.run_gobuster()

        progress(75, "Running Nuclei vulnerability templates...")
        engine.run_nuclei()

        if run_zap:
            progress(85, "Running OWASP ZAP active scan...")
            engine.run_zap_scan()

        progress(95, "Running compliance checks...")
        engine.check_compliance()

        severity = _calculate_severity(engine.results)

        scan_record.raw_data    = engine.results
        scan_record.severity    = severity
        scan_record.status      = 'COMPLETE'
        scan_record.is_critical = severity in ('CRITICAL', 'HIGH')
        scan_record.save()

        progress(100, "Scan complete.")

        return {
            "status":   "COMPLETE",
            "scan_id":  scan_record.id,
            "severity": severity,
        }

    except Exception as e:
        if scan_record:
            scan_record.status = 'FAILED'
            scan_record.save()
        raise e


def _calculate_severity(results: dict) -> str:
    nmap_text   = results.get("nmap_raw", "").lower()
    nuclei_text = " ".join(results.get("nuclei", [])).lower()
    zap_text    = " ".join(results.get("zap", [])).lower()
    web         = results.get("web_discovery", [])

    if "critical" in nuclei_text or "critical" in zap_text:
        return "CRITICAL"
    elif "high" in nuclei_text or "high" in zap_text or "cve-" in nmap_text:
        return "HIGH"
    elif web or "medium" in nuclei_text or "medium" in zap_text:
        return "MEDIUM"
    elif results.get("compliance", []) != ["No compliance issues detected"]:
        return "LOW"
    else:
        return "INFO"