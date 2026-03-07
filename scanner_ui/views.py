from django.shortcuts import render
from django.http import JsonResponse
import nmap
from .models import ScanResult
import json
import os

def home(request):
    if request.method == "POST":
        target = request.POST.get('target')
        scan_type = request.POST.get('scan_type')
        
        nm = nmap.PortScanner()
        
        if scan_type == "lab":
            nm.scan(target, '8081-8083', '-sV --script=vuln -Pn')
        elif scan_type == "web":
            nm.scan(target, '21,22,80,443', '-sV --script=vuln -Pn')
        elif scan_type == "top100":
            nm.scan(target, arguments='--top-ports 100 -sV -Pn')
        else:
            nm.scan(target, '1-65535', '-sV -T4 -Pn')

        results_str = f"--- [PRO SCAN COMPLETED] ---\n"
        for host in nm.all_hosts():
            results_str += f"Target: {host} ({nm[host].hostname()})\n"
            for proto in nm[host].all_protocols():
                for port in nm[host][proto].keys():
                    state = nm[host][proto][port]['state']
                    service = nm[host][proto][port].get('name', 'unknown')
                    product = nm[host][proto][port].get('product', '')
                    ver_num = nm[host][proto][port].get('version', '')
                    version_full = f"{product} {ver_num}".strip()
                    
                    results_str += f" Port {port} [{service.upper()}]: {state}\n"
                    if version_full:
                        results_str += f"   -> Version: {version_full}\n"

                    if 'script' in nm[host][proto][port]:
                        results_str += "   [!!!] SECURITY FINDINGS DETECTED:\n"
                        for script_id, output in nm[host][proto][port]['script'].items():
                            clean_output = output.replace('\n', '\n       ')
                            results_str += f"       - {script_id}: {clean_output}\n"

        ScanResult.objects.create(
            target=target,
            scan_mode=scan_type,
            raw_data=results_str
        )

        return JsonResponse({'status': 'success', 'results': results_str})

    return render(request, 'scanner_ui/index.html')

# This MUST be outside the home function!
def get_live_traffic(request):
    log_file = 'network_evidence.json'
    if not os.path.exists(log_file):
        return JsonResponse({'traffic': []})
    
    try:
        with open(log_file, 'r') as f:
            lines = f.readlines()
            # We take the last 10 lines (packets)
            last_10 = [json.loads(line) for line in lines[-10:]]
        return JsonResponse({'traffic': last_10})
    except Exception:
        return JsonResponse({'traffic': []})