import scapy.all as scapy
import json
from datetime import datetime

# THIS IS THE "SECURITY CAMERA"
print("--- [ AEGIS-AI SOC LISTENER ACTIVE ] ---")
print("[*] Monitoring virtual bridge for traffic...")

def process_packet(packet):
    # We only care about IP traffic (the core of most attacks)
    if packet.haslayer(scapy.IP):
        # Create a log entry of what we 'saw'
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "source": packet[scapy.IP].src,
            "destination": packet[scapy.IP].dst,
            "protocol": packet[scapy.IP].proto,
            "size": len(packet)
        }
        
        # Save this to a file so the AI can read it later
        with open("network_evidence.json", "a") as f:
            f.write(json.dumps(log_entry) + "\n")
        
        # Print a live 'ping' so you know it's working
        print(f"[!] Captured Packet: {log_entry['source']} -> {log_entry['destination']}")

# Start sniffing. 'iface' is usually eth0 in Docker, but we'll let scapy find it.
scapy.sniff(store=False, prn=process_packet)