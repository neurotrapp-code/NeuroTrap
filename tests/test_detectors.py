import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "detection"))
import pytest
from alert_event import AlertEvent, HoneypotSource, Severity
from detectors.port_scan import PortScanDetector
from detectors.brute_force import BruteForceDetector


def test_alert_event_valid():
    e = AlertEvent(timestamp=AlertEvent.now_ts(), src_ip="10.0.0.9", dst_port=22,
                   attack_type="brute_force", severity="high",
                   honeypot_source=HoneypotSource.SCAPY)
    assert str(e.src_ip) == "10.0.0.9"
    assert e.severity == Severity.HIGH


def test_alert_event_rejects_bad_ip():
    with pytest.raises(Exception):
        AlertEvent(timestamp=AlertEvent.now_ts(), src_ip="not-an-ip",
                   attack_type="x", severity="low", honeypot_source=HoneypotSource.SCAPY)


def test_alert_event_rejects_bad_port():
    with pytest.raises(Exception):
        AlertEvent(timestamp=AlertEvent.now_ts(), src_ip="10.0.0.9", dst_port=99999,
                   attack_type="x", severity="low", honeypot_source=HoneypotSource.SCAPY)


def test_port_scan_fires_over_threshold():
    d = PortScanDetector()
    fired = None
    for p in range(1, 13):           # 12 distinct ports > 10
        r = d.observe("10.0.0.50", p, now=1000.0)
        fired = fired or r           # keep the FIRST detection (debounce mutes the rest)
    assert fired and fired["attack_type"] == "port_scan"


def test_brute_force_fires():
    d = BruteForceDetector()
    fired = None
    for i in range(7):               # 7 > 5 in window
        r = d.observe("10.0.0.51", 22, is_syn=True, now=1000.0 + i)
        fired = fired or r           # keep the FIRST detection (debounce mutes the rest)
    assert fired and fired["attack_type"] == "brute_force"
