"""
AEGIS core/aegis_listener.py — Phase 4
Scapy packet capture with ML classification.
Uses Redis as shared storage so Django can read the results.
"""

import threading
import json
import time
import redis
from datetime import datetime
from collections import deque

# Local buffer for the listener process
_packet_buffer = deque(maxlen=200)
_buffer_lock = threading.Lock()
_listener_running = False
_listener_thread = None

# Redis connection — shared between listener and Django
_redis = None

def _get_redis():
    global _redis
    if _redis is None:
        _redis = redis.Redis(host='localhost', port=6379, db=1, decode_responses=True)
    return _redis


def start_listener(interface="any", packet_count=0):
    global _listener_running, _listener_thread
    if _listener_running:
        return {"status": "already_running"}

    # Reset counters in Redis
    r = _get_redis()
    r.set("aegis:siem:total_packets", 0)
    r.set("aegis:siem:total_threats", 0)
    r.set("aegis:siem:critical_alerts", 0)
    r.delete("aegis:siem:by_category")
    r.delete("aegis:siem:recent_packets")
    r.delete("aegis:siem:recent_alerts")
    r.set("aegis:siem:running", "true")

    _listener_running = True
    _listener_thread = threading.Thread(
        target=_sniff_loop, args=(interface, packet_count), daemon=True)
    _listener_thread.start()
    return {"status": "started", "interface": interface}


def stop_listener():
    global _listener_running
    _listener_running = False
    try:
        _get_redis().set("aegis:siem:running", "false")
    except Exception:
        pass
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
                "protocol_name": {1: "ICMP", 6: "TCP", 17: "UDP"}.get(
                                     ip.proto, f"IP({ip.proto})"),
                "size":          len(packet),
                "dst_port":      _get_dst_port(packet),
            }

            # ML classification
            try:
                from core.ml_detector import classify_packet
                cls = classify_packet(packet)
                if cls and "classification" in cls:
                    pkt_info["ml_class"]   = cls["classification"]
                    pkt_info["severity"]   = cls["severity"]
                    pkt_info["confidence"] = cls.get("confidence", 0.85)
                    pkt_info["is_threat"]  = cls["is_threat"]
                    pkt_info["alert"]      = (cls["classification"]
                                              if cls["is_threat"] else "NORMAL")
                else:
                    pkt_info.update({"ml_class": "UNCLASSIFIED", "severity": "LOW",
                                     "alert": "NORMAL", "is_threat": False})
            except Exception:
                pkt_info.update({"ml_class": "ERROR", "severity": "LOW",
                                 "alert": "NORMAL", "is_threat": False})

            # Store in local buffer
            with _buffer_lock:
                _packet_buffer.append(pkt_info)

            # Store in Redis for Django to read
            try:
                r = _get_redis()
                # Push to recent packets list (keep last 200)
                r.lpush("aegis:siem:recent_packets", json.dumps(pkt_info))
                r.ltrim("aegis:siem:recent_packets", 0, 199)

                # Update counters
                r.incr("aegis:siem:total_packets")

                if pkt_info.get("is_threat"):
                    r.incr("aegis:siem:total_threats")
                    r.hincrby("aegis:siem:by_category",
                              pkt_info.get("ml_class", "UNKNOWN"), 1)

                    # Store in alerts list
                    r.lpush("aegis:siem:recent_alerts", json.dumps(pkt_info))
                    r.ltrim("aegis:siem:recent_alerts", 0, 99)

                    if pkt_info.get("severity") == "CRITICAL":
                        r.incr("aegis:siem:critical_alerts")

            except Exception:
                pass  # Redis write failure shouldn't stop packet capture

        sniff(iface=interface if interface != "any" else None,
              prn=process_packet, count=packet_count if packet_count > 0 else 0,
              store=False, stop_filter=lambda _: not _listener_running)

    except PermissionError:
        print("[LISTENER] Permission denied — run with sudo")
    except Exception as e:
        print(f"[LISTENER] Error: {e}")
    finally:
        _listener_running = False
        try:
            _get_redis().set("aegis:siem:running", "false")
        except Exception:
            pass


def get_recent_packets(count=50):
    """Read from Redis — works across processes."""
    try:
        r = _get_redis()
        raw = r.lrange("aegis:siem:recent_packets", 0, count - 1)
        return [json.loads(p) for p in raw]
    except Exception:
        # Fallback to local buffer
        with _buffer_lock:
            return list(_packet_buffer)[-count:]


def get_listener_status():
    try:
        r = _get_redis()
        return {
            "running":     r.get("aegis:siem:running") == "true",
            "buffer_size": r.llen("aegis:siem:recent_packets"),
        }
    except Exception:
        return {"running": _listener_running, "buffer_size": len(_packet_buffer)}


def _get_dst_port(packet):
    from scapy.all import TCP, UDP
    if packet.haslayer(TCP):
        return packet[TCP].dport
    if packet.haslayer(UDP):
        return packet[UDP].dport
    return 0