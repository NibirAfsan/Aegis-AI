"""
AEGIS scanner_ui/views.py
==========================
Phase 3 + Phase 4 — offensive engine + SIEM defensive monitor.
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
# REPORT — async via Celery
# ─────────────────────────────────────────────────────────────────────────────

@csrf_exempt
def generate_report(request, scan_id):
    try:
        scan = ScanResult.objects.get(id=scan_id)
    except ScanResult.DoesNotExist:
        return JsonResponse({"error": "Scan not found"}, status=404)

    task = run_report_task.delay(scan_id)
    return JsonResponse({
        "status":  "QUEUED",
        "task_id": task.id,
        "message": "Report generation started..."
    })


def report_status(request, task_id):
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
        return JsonResponse({"error": f"PDF failed: {str(e)}"}, status=500)


def _sanitize_for_pdf(text: str) -> str:
    """
    Strips markdown/HTML formatting that ReportLab can't handle.
    Converts to plain text safe for PDF paragraphs.
    """
    import re
    s = text
    # Remove HTML tags that ReportLab chokes on (br, span, div, etc.)
    s = re.sub(r'<br\s*/?>', ' / ', s, flags=re.IGNORECASE)
    s = re.sub(r'</?[a-zA-Z][^>]*>', '', s)
    # Remove markdown formatting
    s = s.replace("**", "")
    s = s.replace("__", "")
    s = s.replace("`", "'")
    # Escape XML special chars for ReportLab
    s = s.replace("&", "&amp;")
    s = s.replace("<", "&lt;")
    s = s.replace(">", "&gt;")
    return s


def _generate_pdf(scan, report_text: str) -> bytes:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                     Table, TableStyle, HRFlowable)
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    import io

    buffer = io.BytesIO()
    doc    = SimpleDocTemplate(buffer, pagesize=A4,
                               rightMargin=2*cm, leftMargin=2*cm,
                               topMargin=2*cm, bottomMargin=2*cm)

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('AegisTitle', parent=styles['Title'],
                                  fontSize=24, textColor=colors.HexColor('#1a1a2e'),
                                  spaceAfter=6, alignment=TA_CENTER)
    subtitle_style = ParagraphStyle('AegisSub', parent=styles['Normal'],
                                     fontSize=11, textColor=colors.HexColor('#cc0000'),
                                     alignment=TA_CENTER, spaceAfter=20)
    h1_style = ParagraphStyle('AegisH1', parent=styles['Heading1'],
                               fontSize=14, textColor=colors.HexColor('#1a1a2e'),
                               spaceBefore=16, spaceAfter=6)
    h2_style = ParagraphStyle('AegisH2', parent=styles['Heading2'],
                               fontSize=12, textColor=colors.HexColor('#cc0000'),
                               spaceBefore=12, spaceAfter=4)
    body_style = ParagraphStyle('AegisBody', parent=styles['Normal'],
                                 fontSize=10, spaceAfter=6, leading=14)
    code_style = ParagraphStyle('AegisCode', parent=styles['Code'],
                                 fontSize=8, backColor=colors.HexColor('#f5f5f5'),
                                 borderColor=colors.HexColor('#cccccc'),
                                 borderWidth=1, borderPad=4, spaceAfter=6)

    severity_colours = {
        'CRITICAL': colors.HexColor('#cc0000'),
        'HIGH':     colors.HexColor('#e65c00'),
        'MEDIUM':   colors.HexColor('#e6a817'),
        'LOW':      colors.HexColor('#2196f3'),
        'INFO':     colors.HexColor('#4caf50'),
    }
    sev_colour = severity_colours.get(scan.severity or 'INFO', colors.grey)

    elements = []
    elements.append(Spacer(1, 1*cm))
    elements.append(Paragraph("AEGIS-AI", title_style))
    elements.append(Paragraph("Security Assessment Report", subtitle_style))
    elements.append(HRFlowable(width="100%", thickness=2,
                                color=colors.HexColor('#cc0000')))
    elements.append(Spacer(1, 0.5*cm))

    meta_data = [
        ["Target",         scan.target],
        ["Scan Mode",      scan.scan_mode.upper()],
        ["Overall Risk",   scan.severity or "Unknown"],
        ["Date",           scan.timestamp.strftime("%Y-%m-%d %H:%M UTC")],
        ["Classification", "CONFIDENTIAL"],
        ["Framework",      "AEGIS-AI Automated Penetration Testing"],
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

    sev_data  = [[f"  OVERALL RISK: {scan.severity or 'UNKNOWN'}  "]]
    sev_table = Table(sev_data, colWidths=[17*cm])
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

    # Parse report text — all lines sanitized through _sanitize_for_pdf
    for line in report_text.splitlines():
        line = line.strip()
        if not line:
            elements.append(Spacer(1, 0.2*cm))
        elif line.startswith("# "):
            elements.append(Paragraph(_sanitize_for_pdf(line[2:]), h1_style))
        elif line.startswith("## "):
            elements.append(Paragraph(_sanitize_for_pdf(line[3:]), h2_style))
        elif line.startswith("### "):
            elements.append(Paragraph(
                _sanitize_for_pdf(line[4:]), styles['Heading3']))
        elif line.startswith("```") or line.startswith("    "):
            elements.append(Paragraph(_sanitize_for_pdf(line), code_style))
        elif line.startswith("| "):
            elements.append(Paragraph(_sanitize_for_pdf(line), body_style))
        elif line.startswith("- ") or line.startswith("* "):
            elements.append(Paragraph(
                "&bull; " + _sanitize_for_pdf(line[2:]), body_style))
        elif line.startswith("**") and line.endswith("**"):
            elements.append(Paragraph(
                "<b>" + _sanitize_for_pdf(line[2:-2]) + "</b>", body_style))
        else:
            elements.append(Paragraph(_sanitize_for_pdf(line), body_style))

    elements.append(Spacer(1, 1*cm))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
    elements.append(Paragraph(
        f"Generated by AEGIS-AI Framework | {scan.timestamp:%Y-%m-%d} | CONFIDENTIAL",
        ParagraphStyle('footer', parent=styles['Normal'], fontSize=8,
                       textColor=colors.grey, alignment=TA_CENTER)))

    doc.build(elements)
    return buffer.getvalue()


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK PLAN VIEWER
# ─────────────────────────────────────────────────────────────────────────────

def view_attack_plan(request, scan_id):
    try:
        scan = ScanResult.objects.get(id=scan_id)
        plan = scan.raw_data.get("attack_plan", {})
        return JsonResponse(plan, json_dumps_params={'indent': 2})
    except ScanResult.DoesNotExist:
        return JsonResponse({"error": "Scan not found"}, status=404)


# ─────────────────────────────────────────────────────────────────────────────
# LIVE TRAFFIC — Phase 4: now includes ML classification
# ─────────────────────────────────────────────────────────────────────────────

def get_live_traffic(request):
    try:
        from core.aegis_listener import get_recent_packets
        packets = get_recent_packets(50)
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
# SIEM ENDPOINTS — Phase 4: reads from Redis (shared with listener)
# ─────────────────────────────────────────────────────────────────────────────

def siem_threat_summary(request):
    """Returns ML threat statistics from Redis."""
    try:
        import redis as rd
        r = rd.Redis(host='localhost', port=6379, db=1, decode_responses=True)

        total_packets  = int(r.get("aegis:siem:total_packets") or 0)
        total_threats  = int(r.get("aegis:siem:total_threats") or 0)
        critical       = int(r.get("aegis:siem:critical_alerts") or 0)
        by_category    = r.hgetall("aegis:siem:by_category") or {}
        running        = r.get("aegis:siem:running") == "true"

        by_category = {k: int(v) for k, v in by_category.items()}

        threat_rate = round(total_threats / max(total_packets, 1) * 100, 2)

        return JsonResponse({
            "total_packets":   total_packets,
            "total_threats":   total_threats,
            "critical_alerts": critical,
            "by_category":     by_category,
            "threat_rate":     threat_rate,
            "model_accuracy":  99.61,
            "model_classes":   10,
            "listener_running": running,
        })
    except Exception as e:
        return JsonResponse({
            "total_packets": 0, "total_threats": 0,
            "critical_alerts": 0, "by_category": {},
            "threat_rate": 0.0, "model_accuracy": 99.61,
            "error": str(e)
        })


def siem_alerts(request):
    """Returns recent ML-classified threat alerts from Redis."""
    try:
        import redis as rd
        r = rd.Redis(host='localhost', port=6379, db=1, decode_responses=True)
        count = int(request.GET.get('count', 50))
        raw = r.lrange("aegis:siem:recent_alerts", 0, count - 1)
        alerts = [json.loads(a) for a in raw]
        return JsonResponse({"alerts": alerts, "count": len(alerts)})
    except Exception as e:
        return JsonResponse({"alerts": [], "error": str(e)})


@csrf_exempt
def siem_playbook(request):
    """Generates an AI response playbook for a specific attack type."""
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    try:
        data = json.loads(request.body)
        attack_type = data.get("attack_type", "UNKNOWN")
        details = data.get("details", {})
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)
    try:
        from core.ml_detector import generate_response_playbook
        playbook = generate_response_playbook(attack_type, details)
        return JsonResponse({
            "status": "ok",
            "attack_type": attack_type,
            "playbook": playbook
        })
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


# ─────────────────────────────────────────────────────────────────────────────
# DYNAMIC LEARNING — GenAI-in-the-loop feedback pipeline
# ─────────────────────────────────────────────────────────────────────────────

def siem_learning_status(request):
    """Returns dynamic learning pipeline statistics."""
    try:
        from core.feedback_engine import get_feedback_stats, get_anomalies
        stats = get_feedback_stats()
        stats["recent_anomalies"] = get_anomalies(5)
        return JsonResponse(stats)
    except Exception as e:
        return JsonResponse({"error": str(e)})


def siem_pending_reviews(request):
    """Returns detections awaiting verification."""
    try:
        from core.feedback_engine import get_pending_reviews
        count = int(request.GET.get('count', 20))
        reviews = get_pending_reviews(count)
        return JsonResponse({"reviews": reviews, "count": len(reviews)})
    except Exception as e:
        return JsonResponse({"reviews": [], "error": str(e)})


@csrf_exempt
def siem_submit_feedback(request):
    """Human analyst submits feedback on a detection."""
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    try:
        data = json.loads(request.body)
        detection_id = data.get("detection_id", "")
        verified_label = data.get("verified_label", "")
        notes = data.get("notes", "")
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)
    if not detection_id or not verified_label:
        return JsonResponse({"error": "detection_id and verified_label required"}, status=400)
    try:
        from core.feedback_engine import submit_feedback
        result = submit_feedback(detection_id, verified_label,
                                 verified_by="human", notes=notes)
        return JsonResponse(result)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


@csrf_exempt
def siem_genai_validate(request):
    """Syncs Redis alerts to feedback CSV, then runs GenAI validation."""
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)
    try:
        # Step 1: Sync alerts from Redis to feedback CSV
        from core.feedback_engine import sync_from_redis, genai_validate_detections
        sync_result = sync_from_redis()

        # Step 2: Run GenAI validation on unverified detections
        count = 10
        try:
            data = json.loads(request.body)
            count = data.get("count", 10)
        except Exception:
            pass
        validate_result = genai_validate_detections(count)

        return JsonResponse({
            "sync": sync_result,
            "validation": validate_result,
        })
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _build_text_report(scan, results: dict) -> str:
    lines = [
        "=" * 60,
        "  AEGIS SECURITY ASSESSMENT REPORT",
        "=" * 60,
        f"  Target   : {scan.target}",
        f"  Mode     : {scan.scan_mode}",
        f"  Severity : {scan.severity or 'Unknown'}",
        f"  Date     : {scan.timestamp:%Y-%m-%d %H:%M}",
        "=" * 60, "",
        "[1] NETWORK SCAN (NMAP)",
        results.get("nmap_raw", "No data"), "",
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
            "", "[9] ATTACK RESULTS",
            f"  Total: {attack_results.get('attacks_run', 0)}",
            f"  Successful: {attack_results.get('successful', 0)}", "",
        ]
        for r in attack_results.get("results", []):
            status = "SUCCESS" if r.get("success") else "FAILED"
            lines.append(f"  [{status}] {r.get('tool','?').upper()} "
                         f"port {r.get('port','?')}")
            lines.append(f"  Vuln: {r.get('vulnerability','')}")
            if r.get("output"):
                lines.append(f"  Evidence:\n    {r['output'][:400]}")
            lines.append("")

    return "\n".join(str(l) for l in lines)