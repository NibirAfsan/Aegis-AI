"""
AEGIS scanner_ui/views.py
==========================
All views — Phase 3 update wires the attack button to real logic.
"""

from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from celery.result import AsyncResult
from scanner_ui.models import ScanResult
from core.tasks import run_full_scan, run_attack_task
import json
import os


# ─────────────────────────────────────────────────────────────────────────────
# DASHBOARD
# ─────────────────────────────────────────────────────────────────────────────

def home(request):
    recent_scans = ScanResult.objects.order_by('-timestamp')[:10]
    return render(request, 'scanner_ui/index.html', {'recent_scans': recent_scans})


# ─────────────────────────────────────────────────────────────────────────────
# START SCAN
# ─────────────────────────────────────────────────────────────────────────────

@csrf_exempt
def start_scan(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)

    target    = request.POST.get('target', '').strip()
    scan_type = request.POST.get('scan_type', 'lab')
    stealth   = request.POST.get('stealth_mode') == 'on'
    run_zap   = request.POST.get('run_zap') == 'on'

    if not target:
        return JsonResponse({"error": "Target is required"}, status=400)

    task = run_full_scan.delay(target, scan_type, stealth, run_zap)

    return JsonResponse({
        "status":  "QUEUED",
        "task_id": task.id,
        "message": f"Scan queued for {target}",
    })


# ─────────────────────────────────────────────────────────────────────────────
# SCAN STATUS
# ─────────────────────────────────────────────────────────────────────────────

def scan_status(request, task_id):
    task  = AsyncResult(task_id)
    state = task.state

    if state == "PENDING":
        return JsonResponse({"state": "PENDING", "progress": 0,
                             "message": "Waiting for worker..."})
    elif state == "PROGRESS":
        info = task.info or {}
        return JsonResponse({
            "state":    "PROGRESS",
            "progress": info.get("current", 0),
            "total":    info.get("total", 100),
            "message":  info.get("message", "Scanning..."),
        })
    elif state == "SUCCESS":
        result = task.result or {}
        return JsonResponse({
            "state":    "SUCCESS",
            "scan_id":  result.get("scan_id"),
            "severity": result.get("severity"),
            "message":  "Scan complete",
        })
    elif state == "FAILURE":
        return JsonResponse({"state": "FAILURE", "message": str(task.info)})

    return JsonResponse({"state": state})


# ─────────────────────────────────────────────────────────────────────────────
# GET SCAN RESULTS
# ─────────────────────────────────────────────────────────────────────────────

def get_scan_results(request, scan_id):
    try:
        scan = ScanResult.objects.get(id=scan_id)
    except ScanResult.DoesNotExist:
        return JsonResponse({"error": "Scan not found"}, status=404)

    return JsonResponse({
        "status":    "ok",
        "target":    scan.target,
        "scan_mode": scan.scan_mode,
        "severity":  scan.severity,
        "timestamp": scan.timestamp.isoformat(),
        "results":   scan.raw_data,
    })


# ─────────────────────────────────────────────────────────────────────────────
# INITIATE ATTACK — now wired to real Celery task
# ─────────────────────────────────────────────────────────────────────────────

@csrf_exempt
def initiate_attack(request):
    """
    Phase 3 — receives scan_id from the EXECUTE BREACH SEQUENCE button,
    fires a background Celery task that:
      1. Sends scan results to Gemini AI
      2. AI generates a complete attack plan
      3. Attack engine executes each attack automatically
      4. Evidence is collected and saved
    """
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)

    try:
        data    = json.loads(request.body)
        scan_id = data.get("scan_id")
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)

    if not scan_id:
        return JsonResponse({"error": "scan_id required"}, status=400)

    # Verify scan exists and is complete
    try:
        scan = ScanResult.objects.get(id=scan_id)
        if scan.status != 'COMPLETE':
            return JsonResponse({
                "error": "Scan must be complete before attacking"
            }, status=400)
    except ScanResult.DoesNotExist:
        return JsonResponse({"error": "Scan not found"}, status=404)

    # Fire the attack task in background
    task = run_attack_task.delay(scan_id)

    return JsonResponse({
        "status":  "QUEUED",
        "task_id": task.id,
        "message": f"AI attack sequence initiated for scan {scan_id}. Gemini is planning the attack...",
        "scan_id": scan_id
    })


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK STATUS — browser polls this during attack
# ─────────────────────────────────────────────────────────────────────────────

def attack_status(request, task_id):
    """Polls attack task progress — same pattern as scan_status."""
    task  = AsyncResult(task_id)
    state = task.state

    if state == "PENDING":
        return JsonResponse({"state": "PENDING", "progress": 0,
                             "message": "Attack queued..."})
    elif state == "PROGRESS":
        info = task.info or {}
        return JsonResponse({
            "state":    "PROGRESS",
            "progress": info.get("current", 0),
            "message":  info.get("message", "Attacking..."),
        })
    elif state == "SUCCESS":
        result = task.result or {}
        return JsonResponse({
            "state":       "SUCCESS",
            "scan_id":     result.get("scan_id"),
            "attacks_run": result.get("attacks_run", 0),
            "successful":  result.get("successful", 0),
            "ai_summary":  result.get("ai_summary", ""),
            "message":     "Attack sequence complete"
        })
    elif state == "FAILURE":
        return JsonResponse({"state": "FAILURE", "message": str(task.info)})

    return JsonResponse({"state": state})


# ─────────────────────────────────────────────────────────────────────────────
# GENERATE REPORT
# ─────────────────────────────────────────────────────────────────────────────

def generate_report(request, scan_id):
    try:
        scan = ScanResult.objects.get(id=scan_id)
    except ScanResult.DoesNotExist:
        return JsonResponse({"error": "Scan not found"}, status=404)

    results        = scan.raw_data
    attack_results = results.get("attack_results", {})

    try:
        from core.ai_engine import generate_pentest_report, generate_dfir_report

        pentest_report = generate_pentest_report(results, attack_results, scan.target)

        # Only attempt DFIR if we have actual attack results
        dfir_report = ""
        if attack_results.get("attacks_run", 0) > 0:
            forensic_evidence = _collect_evidence_summary(scan)
            dfir_report = generate_dfir_report(
                results, attack_results, forensic_evidence, scan.target
            )

        scan.ai_report = pentest_report
        scan.save()

        return JsonResponse({
            "status":         "ok",
            "pentest_report": pentest_report,
            "dfir_report":    dfir_report,
            "scan_id":        scan_id,
            "ai_powered":     True
        })

    except Exception as e:
        # Always fall back to text report — never leave user stuck
        report = _build_text_report(scan, results)
        return JsonResponse({
            "status":  "ok",
            "report":  report,
            "scan_id": scan_id,
            "note":    f"Text report (AI busy: {str(e)[:100]}). Try Generate Report again in 2 minutes."
        })


def _collect_evidence_summary(scan) -> dict:
    """Collects evidence files from disk for the DFIR report."""
    from scanner_ui.models import ForensicEvidence
    evidence_items = ForensicEvidence.objects.filter(scan=scan)
    return {
        "items": [
            {
                "type":        e.evidence_type,
                "file":        e.file_path,
                "sha256":      e.sha256_hash,
                "description": e.description,
                "timestamp":   e.collected_at.isoformat()
            }
            for e in evidence_items
        ],
        "total": evidence_items.count()
    }

def _build_text_report(scan, results: dict) -> str:
    lines = [
        "=" * 60,
        "  AEGIS SECURITY ASSESSMENT REPORT",
        "=" * 60,
        f"  Target   : {scan.target}",
        f"  Mode     : {scan.scan_mode}",
        f"  Severity : {scan.severity or 'Unknown'}",
        f"  Date     : {scan.timestamp:%Y-%m-%d %H:%M}",
        "=" * 60,
        "",
        "[1] NETWORK SCAN (NMAP)",
        results.get("nmap_raw", "No data"),
        "",
        "[2] NUCLEI FINDINGS",
    ]
    lines += results.get("nuclei", ["No findings"])
    lines += ["", "[3] ZAP FINDINGS"]
    lines += results.get("zap", ["No findings"])
    lines += ["", "[4] GOBUSTER"]
    lines += results.get("gobuster", ["No findings"])[:20]
    lines += ["", "[5] WEB AUDIT"]
    lines += results.get("web_discovery", ["No findings"])[:20]
    lines += ["", "[6] OSINT"]
    lines += results.get("harvester", ["No data"])
    lines += ["", "[7] TECH STACK"]
    lines += results.get("tech_stack", ["No data"])
    lines += ["", "[8] COMPLIANCE"]
    lines += results.get("compliance", ["None"])

    # Add after the compliance section in _build_text_report:
    if attack_results.get("results"):
        lines += ["", "[9] ATTACK EVIDENCE (PROOF OF EXPLOITATION)"]
        for r in attack_results["results"]:
            tool    = r.get("tool", "unknown").upper()
            vuln    = r.get("vulnerability", "")
            port    = r.get("port", "")
            success = "✓ SUCCESSFUL" if r.get("success") else "✗ FAILED/BLOCKED"
            lines.append(f"\n  {success} — {tool} on port {port}")
            lines.append(f"  Vulnerability: {vuln}")
            if r.get("output"):
                lines.append(f"  Evidence:\n    {r['output'][:500]}")
            if r.get("credentials"):
                lines.append(f"  Credentials found: {r['credentials']}")

    if results.get("attack_results"):
        ar = results["attack_results"]
        lines += [
            "",
            "[9] ATTACK RESULTS",
            f"Attacks run: {ar.get('attacks_run', 0)}",
            f"Successful:  {ar.get('successful', 0)}",
        ]

    return "\n".join(str(l) for l in lines)


# ─────────────────────────────────────────────────────────────────────────────
# LIVE TRAFFIC
# ─────────────────────────────────────────────────────────────────────────────

def get_live_traffic(request):
    try:
        from core.aegis_listener import get_recent_packets
        packets = get_recent_packets(10)
        if packets:
            return JsonResponse({'traffic': packets})
    except Exception:
        pass

    log_file = 'network_evidence.json'
    if not os.path.exists(log_file):
        return JsonResponse({'traffic': [], 'message': 'Listener not active'})

    try:
        with open(log_file, 'r') as f:
            lines = [l for l in f.readlines() if l.strip()]
        last_10 = [json.loads(l) for l in lines[-10:]]
        return JsonResponse({'traffic': last_10})
    except Exception as e:
        return JsonResponse({'traffic': [], 'error': str(e)})

def view_attack_plan(request, scan_id):
    from scanner_ui.models import ScanResult
    scan = ScanResult.objects.get(id=scan_id)
    plan = scan.raw_data.get("attack_plan", {})
    return JsonResponse(plan, json_dumps_params={'indent': 2})