"""
AEGIS core/aegis_listener.py — Phase 4
Scapy packet capture with ML-powered classification.
"""

import threading
import time
from datetime import datetime
from collections import deque

_packet_buffer = deque(maxlen=200)
_buffer_lock = threading.Lock()
_listener_running = False
_listener_thread = None


def start_listener(interface="any", packet_count=0):
    global _listener_running, _listener_thread
    if _listener_running:
        return {"status": "already_running"}
    _listener_running = True
    _listener_thread = threading.Thread(
        target=_sniff_loop, args=(interface, packet_count), daemon=True)
    _listener_thread.start()
    return {"status": "started", "interface": interface}


def stop_listener():
    global _listener_running
    _listener_running = False
    return {"status": "stopped"}


def _sniff_loop(interface, packet_count):
    global _listener_running
    try:
        from scapy.all import sniff, IP
        print(f"[LISTENER] Starting on interface: {interface}")

        def process_packet(packet):
            if not _listener_running or not packet.haslayer(IP):
                return
            ip = packet[IP]
            pkt_info = {
                "timestamp":     datetime.now().isoformat(),
                "source":        ip.src,
                "destination":   ip.dst,
                "protocol":      ip.proto,
                "protocol_name": {1:"ICMP",6:"TCP",17:"UDP"}.get(ip.proto, f"IP({ip.proto})"),
                "size":          len(packet),
                "dst_port":      _get_dst_port(packet),
            }
            try:
                from core.ml_detector import classify_packet
                cls = classify_packet(packet)
                if cls and "classification" in cls:
                    pkt_info["ml_class"]   = cls["classification"]
                    pkt_info["severity"]   = cls["severity"]
                    pkt_info["confidence"] = cls["confidence"]
                    pkt_info["is_threat"]  = cls["is_threat"]
                    pkt_info["alert"]      = cls["classification"] if cls["is_threat"] else "NORMAL"
                else:
                    pkt_info.update({"ml_class":"UNCLASSIFIED","severity":"LOW",
                                     "alert":"NORMAL","is_threat":False})
            except Exception:
                pkt_info.update({"ml_class":"ERROR","severity":"LOW",
                                 "alert":"NORMAL","is_threat":False})
            with _buffer_lock:
                _packet_buffer.append(pkt_info)

        sniff(iface=interface if interface != "any" else None,
              prn=process_packet, count=packet_count if packet_count > 0 else 0,
              store=False, stop_filter=lambda _: not _listener_running)
    except PermissionError:
        print("[LISTENER] Permission denied — run with sudo")
    except Exception as e:
        print(f"[LISTENER] Error: {e}")
    finally:
        _listener_running = False


def get_recent_packets(count=50):
    with _buffer_lock:
        return list(_packet_buffer)[-count:]


def get_listener_status():
    return {"running": _listener_running, "buffer_size": len(_packet_buffer)}


def _get_dst_port(packet):
    from scapy.all import TCP, UDP
    if packet.haslayer(TCP): return packet[TCP].dport
    if packet.haslayer(UDP): return packet[UDP].dport
    return 0