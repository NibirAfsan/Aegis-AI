"""
AEGIS scanner_ui/views.py
==========================
Phase 3 complete — async scan, async attack, async report generation.

FIXES:
  1. generate_report() is now async via Celery — never hangs the browser
  2. PDF report generation added (reportlab)
  3. Evidence proof shown in reports
  4. Report status polling endpoint added
"""

from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from celery.result import AsyncResult
from scanner_ui.models import ScanResult
from core.tasks import run_full_scan, run_attack_task, run_report_task
import json
import os


# ─────────────────────────────────────────────────────────────────────────────
# DASHBOARD
# ─────────────────────────────────────────────────────────────────────────────

def home(request):
    recent_scans = ScanResult.objects.order_by('-timestamp')[:10]
    return render(request, 'scanner_ui/index.html', {'recent_scans': recent_scans})


# ─────────────────────────────────────────────────────────────────────────────
# SCAN
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
    return JsonResponse({"status": "QUEUED", "task_id": task.id,
                         "message": f"Scan queued for {target}"})


def scan_status(request, task_id):
    task  = AsyncResult(task_id)
    state = task.state

    if state == "PENDING":
        return JsonResponse({"state": "PENDING", "progress": 0,
                             "message": "Waiting for worker..."})
    elif state == "PROGRESS":
        info = task.info or {}
        return JsonResponse({"state": "PROGRESS",
                             "progress": info.get("current", 0),
                             "total":    info.get("total", 100),
                             "message":  info.get("message", "Scanning...")})
    elif state == "SUCCESS":
        result = task.result or {}
        return JsonResponse({"state": "SUCCESS",
                             "scan_id":  result.get("scan_id"),
                             "severity": result.get("severity"),
                             "message":  "Scan complete"})
    elif state == "FAILURE":
        return JsonResponse({"state": "FAILURE", "message": str(task.info)})
    return JsonResponse({"state": state})


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
# ATTACK
# ─────────────────────────────────────────────────────────────────────────────

@csrf_exempt
def initiate_attack(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)

    try:
        data    = json.loads(request.body)
        scan_id = data.get("scan_id")
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)

    if not scan_id:
        return JsonResponse({"error": "scan_id required"}, status=400)

    try:
        scan = ScanResult.objects.get(id=scan_id)
        if scan.status != 'COMPLETE':
            return JsonResponse({"error": "Scan must be complete"}, status=400)
    except ScanResult.DoesNotExist:
        return JsonResponse({"error": "Scan not found"}, status=404)

    task = run_attack_task.delay(scan_id)
    return JsonResponse({
        "status":  "QUEUED",
        "task_id": task.id,
        "message": "AI attack sequence initiated...",
        "scan_id": scan_id
    })


def attack_status(request, task_id):
    task  = AsyncResult(task_id)
    state = task.state

    if state == "PENDING":
        return JsonResponse({"state": "PENDING", "progress": 0,
                             "message": "Attack queued..."})
    elif state == "PROGRESS":
        info = task.info or {}
        return JsonResponse({"state": "PROGRESS",
                             "progress": info.get("current", 0),
                             "message":  info.get("message", "Attacking...")})
    elif state == "SUCCESS":
        result = task.result or {}
        return JsonResponse({"state":       "SUCCESS",
                             "scan_id":     result.get("scan_id"),
                             "attacks_run": result.get("attacks_run", 0),
                             "successful":  result.get("successful", 0),
                             "ai_summary":  result.get("ai_summary", ""),
                             "message":     "Attack sequence complete"})
    elif state == "FAILURE":
        return JsonResponse({"state": "FAILURE", "message": str(task.info)})
    return JsonResponse({"state": state})


# ─────────────────────────────────────────────────────────────────────────────
# REPORT — async via Celery so browser never hangs
# ─────────────────────────────────────────────────────────────────────────────

@csrf_exempt
def generate_report(request, scan_id):
    """
    Fires report generation as a background Celery task.
    Returns task_id immediately — browser polls /report-status/<task_id>/.
    This prevents the 10-minute hang.
    """
    try:
        scan = ScanResult.objects.get(id=scan_id)
    except ScanResult.DoesNotExist:
        return JsonResponse({"error": "Scan not found"}, status=404)

    task = run_report_task.delay(scan_id)
    return JsonResponse({
        "status":  "QUEUED",
        "task_id": task.id,
        "message": "Report generation started. This takes 1-2 minutes..."
    })


def report_status(request, task_id):
    """Polls report generation progress."""
    task  = AsyncResult(task_id)
    state = task.state

    if state == "PENDING":
        return JsonResponse({"state": "PENDING", "message": "Generating report..."})
    elif state == "PROGRESS":
        info = task.info or {}
        return JsonResponse({"state":   "PROGRESS",
                             "message": info.get("message", "Writing report...")})
    elif state == "SUCCESS":
        result = task.result or {}
        return JsonResponse({"state":          "SUCCESS",
                             "scan_id":         result.get("scan_id"),
                             "pentest_report":  result.get("pentest_report", ""),
                             "dfir_report":     result.get("dfir_report", ""),
                             "pdf_available":   result.get("pdf_available", False),
                             "message":         "Report ready"})
    elif state == "FAILURE":
        return JsonResponse({"state": "FAILURE", "message": str(task.info)})
    return JsonResponse({"state": state})


# ─────────────────────────────────────────────────────────────────────────────
# PDF DOWNLOAD
# ─────────────────────────────────────────────────────────────────────────────

def download_report_pdf(request, scan_id):
    """
    Generates and downloads a professional PDF pentest report.
    Uses the stored ai_report from the database.
    """
    try:
        scan = ScanResult.objects.get(id=scan_id)
    except ScanResult.DoesNotExist:
        return JsonResponse({"error": "Scan not found"}, status=404)

    report_text = scan.ai_report or _build_text_report(scan, scan.raw_data)

    try:
        pdf_bytes = _generate_pdf(scan, report_text)
        response  = HttpResponse(pdf_bytes, content_type='application/pdf')
        response['Content-Disposition'] = (
            f'attachment; filename="AEGIS_Report_{scan.target}_{scan.timestamp:%Y%m%d}.pdf"'
        )
        return response

    except Exception as e:
        return JsonResponse({"error": f"PDF generation failed: {str(e)}"}, status=500)


def _generate_pdf(scan, report_text: str) -> bytes:
    """
    Generates a professional PDF report using ReportLab.
    Styled like a real security consultancy report.
    """
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                     Table, TableStyle, HRFlowable)
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    import io

    buffer = io.BytesIO()
    doc    = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=2*cm, leftMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'AegisTitle',
        parent=styles['Title'],
        fontSize=24,
        textColor=colors.HexColor('#1a1a2e'),
        spaceAfter=6,
        alignment=TA_CENTER
    )
    subtitle_style = ParagraphStyle(
        'AegisSubtitle',
        parent=styles['Normal'],
        fontSize=11,
        textColor=colors.HexColor('#cc0000'),
        alignment=TA_CENTER,
        spaceAfter=20
    )
    h1_style = ParagraphStyle(
        'AegisH1',
        parent=styles['Heading1'],
        fontSize=14,
        textColor=colors.HexColor('#1a1a2e'),
        spaceBefore=16,
        spaceAfter=6,
        borderPad=4
    )
    h2_style = ParagraphStyle(
        'AegisH2',
        parent=styles['Heading2'],
        fontSize=12,
        textColor=colors.HexColor('#cc0000'),
        spaceBefore=12,
        spaceAfter=4
    )
    body_style = ParagraphStyle(
        'AegisBody',
        parent=styles['Normal'],
        fontSize=10,
        spaceAfter=6,
        leading=14
    )
    code_style = ParagraphStyle(
        'AegisCode',
        parent=styles['Code'],
        fontSize=8,
        backColor=colors.HexColor('#f5f5f5'),
        borderColor=colors.HexColor('#cccccc'),
        borderWidth=1,
        borderPad=4,
        spaceAfter=6
    )

    severity_colours = {
        'CRITICAL': colors.HexColor('#cc0000'),
        'HIGH':     colors.HexColor('#e65c00'),
        'MEDIUM':   colors.HexColor('#e6a817'),
        'LOW':      colors.HexColor('#2196f3'),
        'INFO':     colors.HexColor('#4caf50'),
    }
    sev_colour = severity_colours.get(scan.severity or 'INFO', colors.grey)

    elements = []

    # ── Cover section ────────────────────────────────────────────────────────
    elements.append(Spacer(1, 1*cm))
    elements.append(Paragraph("AEGIS-AI", title_style))
    elements.append(Paragraph("Security Assessment Report", subtitle_style))
    elements.append(HRFlowable(width="100%", thickness=2,
                                color=colors.HexColor('#cc0000')))
    elements.append(Spacer(1, 0.5*cm))

    # Metadata table
    meta_data = [
        ["Target",        scan.target],
        ["Scan Mode",     scan.scan_mode.upper()],
        ["Overall Risk",  scan.severity or "Unknown"],
        ["Date",          scan.timestamp.strftime("%Y-%m-%d %H:%M UTC")],
        ["Classification","CONFIDENTIAL"],
        ["Framework",     "AEGIS-AI Automated Penetration Testing"],
    ]
    meta_table = Table(meta_data, colWidths=[5*cm, 12*cm])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#1a1a2e')),
        ('TEXTCOLOR',  (0, 0), (0, -1), colors.white),
        ('BACKGROUND', (1, 0), (1, -1), colors.HexColor('#f8f8f8')),
        ('FONTSIZE',   (0, 0), (-1, -1), 10),
        ('PADDING',    (0, 0), (-1, -1), 6),
        ('GRID',       (0, 0), (-1, -1), 0.5, colors.HexColor('#dddddd')),
        ('FONTNAME',   (0, 0), (0, -1), 'Helvetica-Bold'),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 0.5*cm))

    # Severity badge
    sev_data   = [[f"  OVERALL RISK: {scan.severity or 'UNKNOWN'}  "]]
    sev_table  = Table(sev_data, colWidths=[17*cm])
    sev_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), sev_colour),
        ('TEXTCOLOR',  (0, 0), (-1, -1), colors.white),
        ('FONTNAME',   (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE',   (0, 0), (-1, -1), 14),
        ('ALIGN',      (0, 0), (-1, -1), 'CENTER'),
        ('PADDING',    (0, 0), (-1, -1), 10),
    ]))
    elements.append(sev_table)
    elements.append(Spacer(1, 1*cm))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.grey))

    # ── Report body — parse Markdown roughly ─────────────────────────────────
    for line in report_text.splitlines():
        line = line.strip()
        if not line:
            elements.append(Spacer(1, 0.2*cm))
        elif line.startswith("# "):
            elements.append(Paragraph(line[2:], h1_style))
        elif line.startswith("## "):
            elements.append(Paragraph(line[3:], h2_style))
        elif line.startswith("### "):
            elements.append(Paragraph(line[4:], styles['Heading3']))
        elif line.startswith("```") or line.startswith("    "):
            elements.append(Paragraph(line.replace("<", "&lt;").replace(">", "&gt;"),
                                       code_style))
        elif line.startswith("| "):
            # Simple table row — just render as body text
            elements.append(Paragraph(line, body_style))
        elif line.startswith("- ") or line.startswith("* "):
            elements.append(Paragraph(f"• {line[2:]}", body_style))
        elif line.startswith("**") and line.endswith("**"):
            elements.append(Paragraph(f"<b>{line[2:-2]}</b>", body_style))
        else:
            # Escape HTML special chars
            safe = line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            elements.append(Paragraph(safe, body_style))

    # ── Footer ───────────────────────────────────────────────────────────────
    elements.append(Spacer(1, 1*cm))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
    elements.append(Paragraph(
        f"Generated by AEGIS-AI Framework | {scan.timestamp:%Y-%m-%d} | CONFIDENTIAL",
        ParagraphStyle('footer', parent=styles['Normal'],
                       fontSize=8, textColor=colors.grey,
                       alignment=TA_CENTER)
    ))

    doc.build(elements)
    return buffer.getvalue()


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK PLAN VIEWER (debug/development)
# ─────────────────────────────────────────────────────────────────────────────

def view_attack_plan(request, scan_id):
    """Shows the AI-generated attack plan for a completed attack."""
    try:
        scan = ScanResult.objects.get(id=scan_id)
        plan = scan.raw_data.get("attack_plan", {})
        return JsonResponse(plan, json_dumps_params={'indent': 2})
    except ScanResult.DoesNotExist:
        return JsonResponse({"error": "Scan not found"}, status=404)


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


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _build_text_report(scan, results: dict) -> str:
    """Fallback text report — used when AI is unavailable."""
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
    lines += ["", "[5] EXPOSED RESOURCES"]
    lines += results.get("web_discovery", ["No findings"])[:20]
    lines += ["", "[6] OSINT"]
    lines += results.get("harvester", ["No data"])
    lines += ["", "[7] TECH STACK"]
    lines += results.get("tech_stack", ["No data"])
    lines += ["", "[8] COMPLIANCE"]
    lines += results.get("compliance", ["None"])

    attack_results = results.get("attack_results", {})
    if attack_results:
        lines += [
            "",
            "[9] ATTACK RESULTS — PROOF OF EXPLOITATION",
            f"  Total attacks:     {attack_results.get('attacks_run', 0)}",
            f"  Successful:        {attack_results.get('successful', 0)}",
            "",
        ]
        for r in attack_results.get("results", []):
            status = "✓ SUCCESSFUL" if r.get("success") else "✗ FAILED"
            lines.append(
                f"  [{status}] {r.get('tool','?').upper()} "
                f"on port {r.get('port','?')}"
            )
            lines.append(f"  Vulnerability: {r.get('vulnerability','')}")
            if r.get("output"):
                lines.append(f"  Evidence:\n    {r['output'][:400]}")
            if r.get("credentials"):
                lines.append(f"  Credentials: {r['credentials']}")
            lines.append("")

    return "\n".join(str(l) for l in lines)