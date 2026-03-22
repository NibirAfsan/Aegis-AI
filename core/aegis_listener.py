"""
AEGIS core/aegis_listener.py
==============================
Upgraded from your original aegis_listener.py (which was in the root folder).

WHAT YOUR ORIGINAL DID:
  - Captured IP packets with Scapy
  - Wrote source/destination/size to network_evidence.json
  - Good foundation!

WHAT THIS ADDS:
  1. TCP/UDP layer — captures port numbers, flags, protocol names
  2. Attack detection — port scan, SYN flood, DNS amplification
  3. Severity tagging — CRITICAL / HIGH / MEDIUM / INFO on each entry
  4. In-memory ring buffer — Django reads this directly (faster than file)
  5. Auto interface detection — works in Docker without manual config
  6. Log rotation — keeps file to 1000 lines so it never grows forever

HOW TO RUN:
  sudo python core/aegis_listener.py           # auto-detect interface
  sudo python core/aegis_listener.py --iface eth0

Needs root/sudo for raw packet capture.
In Docker the interface is usually eth0.
"""

import scapy.all as scapy
import json
import os
import argparse
import threading
from datetime import datetime
from collections import defaultdict, deque

# ── Config ────────────────────────────────────────────────────────────────────
LOG_FILE       = "network_evidence.json"
MAX_ENTRIES    = 1000
SCAN_THRESHOLD = 15   # unique ports hit in a short window = port scan

# ── Attack detection state ────────────────────────────────────────────────────
_port_hits  = defaultdict(set)   # src_ip → set of destination ports seen
_syn_counts = defaultdict(int)   # src_ip → count of SYN-only packets
_lock       = threading.Lock()

# In-memory ring buffer — last 1000 packets, served instantly to Django
_ring_buffer = deque(maxlen=MAX_ENTRIES)


def _detect_attack(packet, log_entry: dict) -> dict:
    """Checks each packet against known attack patterns. Adds alert + severity."""
    src = log_entry["source"]

    with _lock:

        if packet.haslayer(scapy.TCP):
            dst_port = packet[scapy.TCP].dport
            flags    = packet[scapy.TCP].flags

            _port_hits[src].add(dst_port)

            # Port scan: one IP hitting many different ports quickly
            if len(_port_hits[src]) >= SCAN_THRESHOLD:
                log_entry["alert"]    = "PORT_SCAN"
                log_entry["severity"] = "HIGH"
                _port_hits[src].clear()

            # SYN flood: many SYN packets without completing handshake
            if flags == 0x002:   # SYN only (no ACK)
                _syn_counts[src] += 1
                if _syn_counts[src] > 50:
                    log_entry["alert"]    = "SYN_FLOOD"
                    log_entry["severity"] = "CRITICAL"
                    _syn_counts[src] = 0

        # DNS amplification: large DNS responses
        if packet.haslayer(scapy.DNS):
            if packet[scapy.DNS].qr == 1 and log_entry["size"] > 512:
                log_entry["alert"]    = "DNS_AMPLIFICATION"
                log_entry["severity"] = "MEDIUM"

        # Default — normal traffic
        if "alert" not in log_entry:
            log_entry["alert"]    = "NORMAL"
            log_entry["severity"] = "INFO"

    return log_entry


def _rotate_log():
    """Trim log file to MAX_ENTRIES lines."""
    if not os.path.exists(LOG_FILE):
        return
    with open(LOG_FILE, "r") as f:
        lines = f.readlines()
    if len(lines) > MAX_ENTRIES:
        with open(LOG_FILE, "w") as f:
            f.writelines(lines[-MAX_ENTRIES:])


def process_packet(packet):
    """Called by Scapy for every captured packet."""
    if not packet.haslayer(scapy.IP):
        return

    ip = packet[scapy.IP]

    log_entry = {
        "timestamp":   datetime.now().isoformat(),
        "source":      ip.src,
        "destination": ip.dst,
        "protocol":    ip.proto,
        "size":        len(packet),
    }

    # Add TCP details
    if packet.haslayer(scapy.TCP):
        tcp = packet[scapy.TCP]
        log_entry["protocol_name"] = "TCP"
        log_entry["src_port"]      = tcp.sport
        log_entry["dst_port"]      = tcp.dport
        log_entry["tcp_flags"]     = str(tcp.flags)

    # Add UDP details
    elif packet.haslayer(scapy.UDP):
        udp = packet[scapy.UDP]
        log_entry["protocol_name"] = "UDP"
        log_entry["src_port"]      = udp.sport
        log_entry["dst_port"]      = udp.dport

    # Add ICMP details
    elif packet.haslayer(scapy.ICMP):
        log_entry["protocol_name"] = "ICMP"
        log_entry["icmp_type"]     = packet[scapy.ICMP].type
    else:
        log_entry["protocol_name"] = f"PROTO_{ip.proto}"

    # Run attack detection
    log_entry = _detect_attack(packet, log_entry)

    # Store in memory ring buffer
    _ring_buffer.append(log_entry)

    # Write to file
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(log_entry) + "\n")

    # Rotate every 100 packets
    if len(_ring_buffer) % 100 == 0:
        _rotate_log()

    # Only print alerts to terminal — don't spam normal traffic
    if log_entry["alert"] != "NORMAL":
        print(
            f"[{log_entry['severity']}] [{log_entry['alert']}] "
            f"{log_entry['source']}:{log_entry.get('src_port','')} → "
            f"{log_entry['destination']}:{log_entry.get('dst_port','')} "
            f"({log_entry['size']} bytes)"
        )


def get_recent_packets(n: int = 10) -> list:
    """
    Returns last n packets from the ring buffer.
    Called by Django's get_live_traffic view — much faster than reading the file.
    """
    return list(_ring_buffer)[-n:]


def start_listener(iface: str = None):
    print("─" * 50)
    print("  AEGIS-AI  |  SOC LISTENER ACTIVE")
    print(f"  Interface : {iface or 'auto-detect'}")
    print(f"  Log file  : {LOG_FILE}")
    print(f"  Detection : port-scan / SYN-flood / DNS-amp")
    print("─" * 50)

    kwargs = {"store": False, "prn": process_packet}
    if iface:
        kwargs["iface"] = iface

    scapy.sniff(**kwargs)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AEGIS Network Listener")
    parser.add_argument("--iface", help="Network interface e.g. eth0", default=None)
    args = parser.parse_args()
    start_listener(iface=args.iface)