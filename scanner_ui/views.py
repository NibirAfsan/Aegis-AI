"""
AEGIS scanner_ui/views.py
==========================
All views — imports corrected for YOUR project structure.
"""

from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from celery.result import AsyncResult
from scanner_ui.models import ScanResult   # YOUR app name
from core.tasks import run_full_scan       # core folder
import json
import os


# ─────────────────────────────────────────────────────────────────────────────
# DASHBOARD
# ─────────────────────────────────────────────────────────────────────────────

def home(request):
    """Renders the main dashboard with the last 10 scans in history panel."""
    recent_scans = ScanResult.objects.order_by('-timestamp')[:10]
    return render(request, 'scanner_ui/index.html', {'recent_scans': recent_scans})


# ─────────────────────────────────────────────────────────────────────────────
# START SCAN
# ─────────────────────────────────────────────────────────────────────────────

@csrf_exempt
def start_scan(request):
    """
    Receives scan form POST, fires a Celery background task,
    returns task_id immediately (browser then polls /scan-status/).
    """
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)

    target    = request.POST.get('target', '').strip()
    scan_type = request.POST.get('scan_type', 'lab')
    stealth   = request.POST.get('stealth_mode') == 'on'
    run_zap   = request.POST.get('run_zap') == 'on'

    if not target:
        return JsonResponse({"error": "Target is required"}, status=400)

    # .delay() sends the job to Celery and returns immediately
    task = run_full_scan.delay(target, scan_type, stealth, run_zap)

    return JsonResponse({
        "status":  "QUEUED",
        "task_id": task.id,
        "message": f"Scan queued for {target}",
    })


# ─────────────────────────────────────────────────────────────────────────────
# SCAN STATUS — polled every 3 seconds by the browser
# ─────────────────────────────────────────────────────────────────────────────

def scan_status(request, task_id):
    """Returns current state and progress of a running Celery task."""
    task  = AsyncResult(task_id)
    state = task.state

    if state == "PENDING":
        return JsonResponse({
            "state":    "PENDING",
            "progress": 0,
            "message":  "Waiting for worker...",
        })

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
        return JsonResponse({
            "state":   "FAILURE",
            "message": str(task.info),
        })

    return JsonResponse({"state": state})


# ─────────────────────────────────────────────────────────────────────────────
# GET SCAN RESULTS
# ─────────────────────────────────────────────────────────────────────────────

def get_scan_results(request, scan_id):
    """Returns full structured results for a completed scan."""
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
# GENERATE REPORT — text stub now, AI version when you have a key
# ─────────────────────────────────────────────────────────────────────────────

def generate_report(request, scan_id):
    """
    Currently generates a structured text report — works with NO API key.

    When you get a GenAI key:
    1. pip install anthropic
    2. Add ANTHROPIC_API_KEY=sk-ant-... to your .env
    3. Delete the STUB block below
    4. Uncomment the AI BLOCK below it
    """
    try:
        scan = ScanResult.objects.get(id=scan_id)
    except ScanResult.DoesNotExist:
        return JsonResponse({"error": "Scan not found"}, status=404)

    results = scan.raw_data

    # ── STUB — produces text report without AI key ────────────────────────────
    report = _build_text_report(scan, results)
    return JsonResponse({
        "status":  "ok",
        "report":  report,
        "note":    "Text report — add API key to upgrade to AI-generated report",
        "scan_id": scan_id,
    })
    # ── END STUB ──────────────────────────────────────────────────────────────

    # ── AI BLOCK — uncomment when you have ANTHROPIC_API_KEY ──────────────────
    # import anthropic
    # client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))
    # prompt = _build_ai_prompt(scan, results)
    # message = client.messages.create(
    #     model="claude-opus-4-5",
    #     max_tokens=4096,
    #     messages=[{"role": "user", "content": prompt}]
    # )
    # report_text = message.content[0].text
    # scan.ai_report = report_text
    # scan.save()
    # return JsonResponse({"status": "ok", "report": report_text, "scan_id": scan_id})


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
        "[2] VULNERABILITY SCAN (NUCLEI)",
    ]
    lines += results.get("nuclei", ["No findings"])
    lines += ["", "[3] WEB APPLICATION SCAN (ZAP)"]
    lines += results.get("zap", ["No findings"])
    lines += ["", "[4] DIRECTORY DISCOVERY (GOBUSTER)"]
    lines += results.get("gobuster", ["No findings"])[:20]
    lines += ["", "[5] EXPOSED RESOURCES (WEB AUDIT)"]
    lines += results.get("web_discovery", ["No findings"])[:20]
    lines += ["", "[6] OSINT / HARVESTER"]
    lines += results.get("harvester", ["No data"])
    lines += ["", "[7] TECHNOLOGY STACK"]
    lines += results.get("tech_stack", ["No data"])
    lines += ["", "[8] COMPLIANCE ISSUES"]
    lines += results.get("compliance", ["None"])
    return "\n".join(str(l) for l in lines)


def _build_ai_prompt(scan, results: dict) -> str:
    """Ready-to-use Claude prompt — waiting for when you have the API key."""
    return f"""You are a professional penetration tester writing a security assessment report.

TARGET: {scan.target}
SCAN TYPE: {scan.scan_mode}
SEVERITY: {scan.severity}
DATE: {scan.timestamp:%Y-%m-%d}

=== NMAP ===
{results.get('nmap_raw','No data')}

=== NUCLEI ===
{chr(10).join(results.get('nuclei',[]))}

=== OWASP ZAP ===
{chr(10).join(results.get('zap',[]))}

=== GOBUSTER ===
{chr(10).join(results.get('gobuster',[])[:20])}

=== WEB AUDIT ===
{chr(10).join(results.get('web_discovery',[])[:20])}

=== OSINT ===
{chr(10).join(results.get('harvester',[])[:15])}

=== COMPLIANCE ===
{chr(10).join(results.get('compliance',[]))}

Write a professional penetration testing report with:
1. EXECUTIVE SUMMARY (non-technical, 2-3 paragraphs)
2. FINDINGS TABLE (Finding | Severity | Location | CVSS estimate)
3. DETAILED FINDINGS (description, evidence, business impact, remediation)
4. REMEDIATION PRIORITY ORDER
5. COMPLIANCE IMPACT (GDPR, ISO 27001, PCI-DSS)

Format in Markdown. Be specific about evidence.
"""


# ─────────────────────────────────────────────────────────────────────────────
# INITIATE ATTACK — Phase 3 stub
# ─────────────────────────────────────────────────────────────────────────────

@csrf_exempt
def initiate_attack(request):
    """Phase 3 — Metasploit RPC will be wired here."""
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)

    try:
        data        = json.loads(request.body)
        scan_id     = data.get("scan_id")
        attack_type = data.get("attack_type", "auto")
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)

    return JsonResponse({
        "status":      "STUB",
        "scan_id":     scan_id,
        "attack_type": attack_type,
        "message":     "Phase 3 attack module coming soon.",
    })


# ─────────────────────────────────────────────────────────────────────────────
# LIVE TRAFFIC
# ─────────────────────────────────────────────────────────────────────────────

def get_live_traffic(request):
    """Returns last 10 packets from Scapy listener for the defensive monitor."""

    # Fast path — try in-memory ring buffer first
    try:
        from core.aegis_listener import get_recent_packets
        packets = get_recent_packets(10)
        if packets:
            return JsonResponse({'traffic': packets})
    except Exception:
        pass

    # Fallback — read from JSON file
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