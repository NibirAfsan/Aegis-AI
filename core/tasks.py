"""
AEGIS core/tasks.py
====================
Celery background tasks: scan, attack, report.
All three are async — browser polls for progress, never hangs.
"""

import datetime
from celery import shared_task
from core.aegis_scanner import UnifiedAegisEngine
from scanner_ui.models import ScanResult


# ─────────────────────────────────────────────────────────────────────────────
# SCAN TASK
# ─────────────────────────────────────────────────────────────────────────────

@shared_task(bind=True)
def run_full_scan(self, target: str, scan_type: str,
                  stealth: bool = False, run_zap: bool = False):
    def progress(pct, msg):
        self.update_state(state='PROGRESS',
                          meta={'current': pct, 'total': 100, 'message': msg})

    scan_record = None
    try:
        scan_record = ScanResult.objects.create(
            target=target, scan_mode=scan_type, status='RUNNING')

        port_map = {
            "lab":    "8081-8083,2121,2222,3306,5432",
            "web":    None,
            "top100": "80,443,8080,22,21,25,53,110,143,3306,5432",
            "full":   "1-65535",
        }
        engine = UnifiedAegisEngine(target)

        progress(5,  "Initialising engine...")
        progress(10, "Running Nmap scan...")
        engine.run_nmap(ports=port_map.get(scan_type), stealth=stealth)

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


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK TASK
# ─────────────────────────────────────────────────────────────────────────────

@shared_task(bind=True)
def run_attack_task(self, scan_id: int):
    def progress(pct, msg):
        self.update_state(state='PROGRESS',
                          meta={'current': pct, 'total': 100, 'message': msg})

    try:
        progress(5, "Loading scan results...")
        scan = ScanResult.objects.get(id=scan_id)

        if scan.status != 'COMPLETE':
            return {"status": "ERROR", "message": "Scan must be complete first"}

        progress(10, "AI analysing vulnerabilities and generating attack plan...")

        from core.ai_engine import generate_attack_plan
        attack_plan = generate_attack_plan(scan.raw_data, scan.target)

        num_attacks = len(attack_plan.get("attack_sequence", []))
        progress(30, f"AI planned {num_attacks} attack vectors. Executing...")

        from core.attack_engine import AttackOrchestrator
        orchestrator = AttackOrchestrator(scan, attack_plan)

        sequence = sorted(attack_plan.get("attack_sequence", []),
                          key=lambda x: x.get("priority", 99))

        attack_results = []
        for i, attack in enumerate(sequence):
            pct  = 30 + int((i / max(len(sequence), 1)) * 60)
            tool = attack.get('tool', '?').upper()
            vuln = attack.get('vulnerability', '')[:40]
            progress(pct, f"Executing: {tool} → {vuln}...")

            result = orchestrator._execute_single_attack(
                attack, attack.get("tool", "manual"))
            attack_results.append(result)

        progress(95, "Saving evidence and results...")

        execution_summary = {
            "status":      "COMPLETE",
            "target":      scan.target,
            "attacks_run": len(attack_results),
            "successful":  sum(1 for r in attack_results if r.get("success")),
            "results":     attack_results,
            "evidence_dir": orchestrator.evidence_dir,
            "timestamp":   datetime.datetime.now().isoformat()
        }

        # FIX: reassign dict so Django detects the change
        raw_data                   = dict(scan.raw_data)
        raw_data["attack_plan"]    = attack_plan
        raw_data["attack_results"] = execution_summary
        scan.raw_data              = raw_data
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
        return {"status": "ERROR", "message": f"Scan {scan_id} not found"}
    except Exception as e:
        return {"status": "ERROR", "message": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# REPORT TASK — async so browser never hangs
# ─────────────────────────────────────────────────────────────────────────────

@shared_task(bind=True)
def run_report_task(self, scan_id: int):
    """
    Generates both the pentest report and DFIR report in the background.
    Browser polls /report-status/<task_id>/ every 5 seconds.
    """
    def progress(msg):
        self.update_state(state='PROGRESS', meta={'message': msg})

    try:
        progress("Loading scan data...")
        scan = ScanResult.objects.get(id=scan_id)

        results        = scan.raw_data
        attack_results = results.get("attack_results", {})

        from core.ai_engine import generate_pentest_report, generate_dfir_report

        progress("Writing executive summary and findings...")
        pentest_report = generate_pentest_report(results, attack_results, scan.target)

        dfir_report = ""
        if attack_results.get("attacks_run", 0) > 0:
            progress("Writing incident response report...")
            from scanner_ui.models import ForensicEvidence
            evidence_items = ForensicEvidence.objects.filter(scan=scan)
            forensic_evidence = {
                "items": [
                    {"type": e.evidence_type, "file": e.file_path,
                     "sha256": e.sha256_hash, "description": e.description,
                     "timestamp": e.collected_at.isoformat()}
                    for e in evidence_items
                ],
                "total": evidence_items.count()
            }
            dfir_report = generate_dfir_report(
                results, attack_results, forensic_evidence, scan.target)

        # Save to DB
        progress("Saving report...")
        scan.ai_report = pentest_report
        scan.save()

        # Generate PDF
        progress("Generating PDF...")
        pdf_available = False
        try:
            from scanner_ui.views import _generate_pdf
            pdf_bytes = _generate_pdf(scan, pentest_report)
            pdf_path  = f"evidence/{scan_id}/report_{scan_id}.pdf"
            os.makedirs(f"evidence/{scan_id}", exist_ok=True)
            with open(pdf_path, "wb") as f:
                f.write(pdf_bytes)
            pdf_available = True
        except Exception:
            pass   # PDF is optional — report still works without it

        return {
            "status":         "COMPLETE",
            "scan_id":        scan_id,
            "pentest_report": pentest_report,
            "dfir_report":    dfir_report,
            "pdf_available":  pdf_available,
        }

    except ScanResult.DoesNotExist:
        return {"status": "ERROR", "message": f"Scan {scan_id} not found"}
    except Exception as e:
        return {"status": "ERROR", "message": str(e)}


import os


# ─────────────────────────────────────────────────────────────────────────────
# HELPER
# ─────────────────────────────────────────────────────────────────────────────

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