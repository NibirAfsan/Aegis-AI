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

"""
AEGIS core/tasks.py
====================
Celery background tasks for scanning and attacking.
"""

from celery import shared_task
from core.aegis_scanner import UnifiedAegisEngine
from scanner_ui.models import ScanResult


@shared_task(bind=True)
def run_full_scan(self, target: str, scan_type: str,
                  stealth: bool = False, run_zap: bool = False):
    """Background scan task."""

    def progress(pct: int, msg: str):
        self.update_state(
            state='PROGRESS',
            meta={'current': pct, 'total': 100, 'message': msg}
        )

    scan_record = None

    try:
        scan_record = ScanResult.objects.create(
            target=target, scan_mode=scan_type, status='RUNNING',
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

        return {"status": "COMPLETE", "scan_id": scan_record.id, "severity": severity}

    except Exception as e:
        if scan_record:
            scan_record.status = 'FAILED'
            scan_record.save()
        raise e


@shared_task(bind=True)
def run_attack_task(self, scan_id: int):
    """
    Background attack task — fires from initiate_attack view.

    Flow:
      1. Load scan results from DB
      2. Ask Gemini to generate attack plan
      3. Execute plan with AttackOrchestrator
      4. Save results + evidence to DB
    """

    def progress(pct: int, msg: str):
        self.update_state(
            state='PROGRESS',
            meta={'current': pct, 'total': 100, 'message': msg}
        )

    try:
        progress(5, "Loading scan results...")
        scan = ScanResult.objects.get(id=scan_id)

        if scan.status != 'COMPLETE':
            return {"status": "ERROR", "message": "Scan must be complete before attacking"}

        progress(10, "AI analysing vulnerabilities and generating attack plan...")

        from core.ai_engine import generate_attack_plan
        attack_plan = generate_attack_plan(scan.raw_data, scan.target)

        num_attacks = len(attack_plan.get("attack_sequence", []))
        progress(30, f"AI planned {num_attacks} attack vectors. Executing...")

        from core.attack_engine import AttackOrchestrator
        orchestrator = AttackOrchestrator(scan, attack_plan)

        sequence = sorted(
            attack_plan.get("attack_sequence", []),
            key=lambda x: x.get("priority", 99)
        )

        attack_results = []
        for i, attack in enumerate(sequence):
            pct = 30 + int((i / max(len(sequence), 1)) * 60)
            vuln = attack.get('vulnerability', '')[:40]
            tool = attack.get('tool', '?').upper()
            progress(pct, f"Executing: {tool} → {vuln}...")

            result = orchestrator._execute_single_attack(
                attack, attack.get("tool", "manual")
            )
            attack_results.append(result)

        progress(95, "Saving evidence and results...")

        import datetime
        execution_summary = {
            "status":      "COMPLETE",
            "target":      scan.target,
            "attacks_run": len(attack_results),
            "successful":  sum(1 for r in attack_results if r.get("success")),
            "results":     attack_results,
            "evidence_dir": orchestrator.evidence_dir,
            "timestamp":   datetime.datetime.now().isoformat()
        }

        raw_data = dict(scan.raw_data)
        raw_data["attack_plan"]    = attack_plan
        raw_data["attack_results"] = execution_summary
        scan.raw_data = raw_data
        scan.save()

        progress(100, "Attack sequence complete.")

        return {
            "status":      "COMPLETE",
            "scan_id":     scan_id,
            "attacks_run": len(attack_results),
            "successful":  execution_summary["successful"],
            "ai_summary":  attack_plan.get("summary", "")
        }

    except ScanResult.DoesNotExist:
        return {"status": "ERROR", "message": f"Scan ID {scan_id} not found"}
    except Exception as e:
        return {"status": "ERROR", "message": str(e)}


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