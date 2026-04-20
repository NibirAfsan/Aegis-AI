#!/bin/bash
echo "--- [ AEGIS-AI SIEM LISTENER ] ---"
echo "Starting ML-powered packet analysis..."
sudo /home/kali/Aegis_Framework/venv/bin/python3 -c "
import os, django, time
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'aegis_web.settings')
django.setup()
from core.aegis_listener import start_listener, get_listener_status
from core.ml_detector import load_model
print('[ML] Loading ONNX model...')
load_model()
print('[LISTENER] Starting Scapy capture...')
start_listener()
print('[LISTENER] Running. Ctrl+C to stop.')
try:
    while True:
        s = get_listener_status()
        print(f'[SIEM] Packets: {s[\"buffer_size\"]} | Running: {s[\"running\"]}', end='\r')
        time.sleep(5)
except KeyboardInterrupt:
    print('\n[LISTENER] Stopped.')
"