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
        
        engine = UnifiedAegisEngine(target)
        
        # --- Mapping Buttons to REAL Nmap Logic ---
        # Default flags for all scans
        args = '-sV --script=vuln -Pn'
        
        if scan_type == "lab":
            ports = '8081-8083'
        elif scan_type == "web":
            ports = '80,443,8080,8081' 
        elif scan_type == "top100":
            ports = None  # Uses Nmap's internal list
            args = '--top-ports 100 -sV --script=vuln -Pn'
        else: # Full Deep Penetration
            ports = '1-65535'
            args = '-sV --script=vuln -Pn -T4' # Speed optimized for 65k ports

        # Execute the full pipeline
        engine.run_nmap(ports, args=args)
        engine.run_web_discovery()
        engine.run_osint()
        engine.check_compliance()

        # Format the Integrated Report
        report = f"--- [ AEGIS-AI: MISSION INTELLIGENCE REPORT ] ---\n"
        report += f"MISSION: {scan_type.upper()} | TARGET: {target}\n"
        report += "----------------------------------------------\n\n"
        
        report += "[+] NETWORK RECONNAISSANCE (NMAP):\n"
        report += engine.results["nmap_raw"] + "\n"
        
        report += "[!] WEB DIRECTORY AUDIT:\n"
        if engine.results["web_discovery"]:
            report += " " + "\n ".join(engine.results["web_discovery"]) + "\n\n"
        else:
            report += " No sensitive directories found on tested ports.\n\n"
        
        report += "[?] OSINT / DATA LEAK ANALYSIS (SIMULATED):\n"
        report += " " + "\n ".join(engine.results["osint"]) + "\n\n"
        
        report += "[§] REGULATORY COMPLIANCE STATUS:\n"
        report += " " + "\n ".join(engine.results["compliance"]) + "\n\n"

        report += "[BRAIN] GEN-AI ATTACK STRATEGY (PREVIEW):\n"
        if "CRITICAL VULNERABILITIES" in engine.results["nmap_raw"]:
            report += " > [CRITICAL] Real vulnerabilities detected. Ready for exploit generation.\n"
        else:
            report += " > No direct vulnerabilities found. Recommend further social engineering.\n"

        # Save to Database
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
            last_10 = [json.loads(line) for line in lines[-10:]]
        return JsonResponse({'traffic': last_10})
    except:
        return JsonResponse({'traffic': []})