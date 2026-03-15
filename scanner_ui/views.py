from django.shortcuts import render
from django.http import JsonResponse
from .models import ScanResult
from core.aegis_scanner import UnifiedAegisEngine
import json
import os

def home(request):
    if request.method == "POST":
        target = request.POST.get('target', 'host.docker.internal')
        scan_type = request.POST.get('scan_type', 'lab')
        # Check if user manually enabled Stealth via checkbox
        stealth_enabled = request.POST.get('stealth_mode') == 'on'
        
        engine = UnifiedAegisEngine(target)
        
        # --- MISSION MAPPING ---
        if scan_type == "lab":
            ports = '8081-8083'
        elif scan_type == "web": # Web Audit = Top 100
            ports = None # Nmap Default (Top 100)
        elif scan_type == "top100": # Quick Recon
            ports = '80,443,8080,22,21'
        else: # Deep Penetration
            ports = '1-65535'

        # Execute Pipeline
        engine.run_nmap(ports, stealth=stealth_enabled)
        engine.run_web_audit()
        engine.run_osint()
        engine.check_compliance()

        # Build Report
        report = f"--- [ AEGIS-AI: MISSION INTELLIGENCE REPORT ] ---\n"
        report += f"MISSION: {scan_type.upper()} | TARGET: {target}\n"
        report += f"MODE: {'STEALTH (GHOST)' if stealth_enabled else 'AGGRESSIVE (LOUD)'}\n"
        report += "----------------------------------------------\n\n"
        
        report += "[+] NETWORK RECONNAISSANCE (NMAP):\n"
        report += engine.results["nmap_raw"] + "\n\n"
        
        report += "[!] WEB DIRECTORY AUDIT:\n "
        report += "\n ".join(engine.results["web_discovery"]) if engine.results["web_discovery"] else "No leaks found.\n"
        
        report += "\n[?] OSINT & COMPLIANCE:\n "
        report += "\n ".join(engine.results["osint"] + engine.results["compliance"]) + "\n\n"

        # AI Strategy
        report += "[BRAIN] GEN-AI ATTACK STRATEGY:\n"
        if "EXPLOITABLE" in report or "CRITICAL" in report:
            report += " > [READY] Target compromised. Proceed to BREACH SEQUENCE.\n"
        else:
            report += " > [LOCKED] No exploit path found. Try disabling Stealth Mode.\n"

        ScanResult.objects.create(target=target, scan_mode=scan_type, raw_data=report)
        return JsonResponse({'status': 'success', 'results': report})

    return render(request, 'scanner_ui/index.html')

def get_live_traffic(request):
    log_file = 'network_evidence.json'
    if not os.path.exists(log_file):
        return JsonResponse({'traffic': []})
    try:
        with open(log_file, 'r') as f:
            lines = f.readlines()
            # Return last 10 packets for the monitor
            last_10 = [json.loads(line) for line in lines[-10:]]
        return JsonResponse({'traffic': last_10})
    except:
        return JsonResponse({'traffic': []})
