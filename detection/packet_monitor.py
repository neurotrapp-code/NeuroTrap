#!/usr/bin/env python3
"""CADN Scapy packet monitor. Sniffs the honeypot interface and runs detectors.

Run as root (raw sockets):
    sudo ../.venv/bin/python packet_monitor.py -i eth0
"""
import argparse
import os
import sys

# make sibling modules importable regardless of cwd
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scapy.all import sniff, TCP, IP, UDP, Raw  # noqa: E402
from alert_event import AlertEvent, HoneypotSource  # noqa: E402
from detectors.port_scan import PortScanDetector  # noqa: E402
from detectors.brute_force import BruteForceDetector  # noqa: E402
from detectors.anomaly import detect_flag_anomaly  # noqa: E402
from detectors.tool_fingerprint import ToolFingerprintDetector  # noqa: E402

port_scan = PortScanDetector()
brute = BruteForceDetector()
tool_fp = ToolFingerprintDetector()


def emit(detection: dict):
    evt = AlertEvent(
        timestamp=AlertEvent.now_ts(),
        src_ip=detection["src_ip"],
        dst_port=detection.get("dst_port"),
        attack_type=detection["attack_type"],
        severity=detection["severity"],
        honeypot_source=HoneypotSource.SCAPY,
        detail=detection.get("detail"),
        raw_payload=(str(detection["ports"]) if detection.get("ports") else None),
    )
    print(evt.to_json(), flush=True)


def handle(pkt):
    if IP not in pkt:
        return
    src = pkt[IP].src
    if TCP in pkt:
        dport = int(pkt[TCP].dport)
        flags = int(pkt[TCP].flags)
        is_syn = bool(flags & 0x02) and not (flags & 0x10)   # SYN, not SYN-ACK
        detections = [
            port_scan.observe(src, dport),
            brute.observe(src, dport, is_syn),
            detect_flag_anomaly(src, dport, flags),
        ]
        # fingerprint automated tools from cleartext payloads (HTTP UA, SSH banner)
        if Raw in pkt:
            try:
                payload = bytes(pkt[Raw].load).decode("latin-1", "ignore")
            except Exception:
                payload = ""
            detections.append(tool_fp.observe(src, payload, dport))
        for d in detections:
            if d:
                emit(d)
    elif UDP in pkt:
        dport = int(pkt[UDP].dport)
        d = port_scan.observe(src, dport)
        if d:
            emit(d)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--iface", default=os.environ.get("CAPTURE_IFACE", "eth0"),
                    help="capture interface, e.g. eth0")
    ap.add_argument("-f", "--filter", default="tcp or udp", help="BPF filter")
    args = ap.parse_args()
    print(f"[*] CADN monitor on {args.iface} filter='{args.filter}'", flush=True)
    sniff(iface=args.iface, filter=args.filter, prn=handle, store=False)


if __name__ == "__main__":
    main()
