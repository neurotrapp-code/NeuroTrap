"""Week 2 — automated-tool fingerprint detector + Zeek http/ssh/dns normalizers."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "detection"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pipeline"))

from detectors.tool_fingerprint import identify_tool, ToolFingerprintDetector
import normalizer as N


# --- identify_tool --------------------------------------------------------
def test_identify_known_tools():
    assert identify_tool("Mozilla/5.0 sqlmap/1.7")[0] == "sqlmap"
    assert identify_tool("SSH-2.0-libssh_0.9.6")[0] == "libssh"
    assert identify_tool("masscan/1.3")[0] == "masscan"
    assert identify_tool("python-requests/2.31")[0] == "python-requests"
    assert identify_tool("Nmap Scripting Engine")[0] == "nmap"


def test_identify_returns_none_for_browser():
    assert identify_tool("Mozilla/5.0 (Windows NT 10.0) Chrome/120") is None
    assert identify_tool(None) is None


def test_detector_debounces():
    d = ToolFingerprintDetector()
    first = d.observe("1.2.3.4", "GET / sqlmap/1.7", 80, now=1000.0)
    again = d.observe("1.2.3.4", "GET / sqlmap/1.7", 80, now=1005.0)
    assert first and first["attack_type"] == "automated_tool"
    assert first["severity"] == "medium"        # web_scanner
    assert again is None                          # debounced within window


def test_detector_severity_for_bruteforcer():
    d = ToolFingerprintDetector()
    r = d.observe("1.2.3.4", "SSH-2.0-Hydra", 22, now=1.0)
    assert r["severity"] == "high"


# --- normalizer integration ----------------------------------------------
def test_cowrie_client_version_fingerprinted():
    e = N.from_cowrie({"eventid": "cowrie.client.version", "src_ip": "9.9.9.9",
                       "version": "SSH-2.0-paramiko_2.7"})
    assert e.attack_type == "automated_tool"
    assert "paramiko" in e.detail


def test_zeek_http_user_agent_flagged():
    e = N.from_zeek_http({"id.orig_h": "9.9.9.9", "id.resp_p": 80, "ts": 1735689600.0,
                          "method": "GET", "host": "t", "uri": "/", "user_agent": "nikto/2.5"})
    assert e.attack_type == "automated_tool" and "nikto" in e.detail


def test_zeek_http_normal_request():
    e = N.from_zeek_http({"id.orig_h": "9.9.9.9", "id.resp_p": 80, "ts": 1735689600.0,
                          "method": "GET", "user_agent": "Mozilla/5.0 Chrome/120"})
    assert e.attack_type == "http_request"


def test_zeek_ssh_and_dns():
    s = N.from_zeek_ssh({"id.orig_h": "9.9.9.9", "ts": 1735689600.0,
                         "client": "SSH-2.0-Go", "server": "x", "auth_success": False})
    assert s.attack_type == "automated_tool"
    d = N.from_zeek_dns({"id.orig_h": "9.9.9.9", "ts": 1735689600.0,
                         "query": "c2.evil.su", "qtype_name": "A"})
    assert d.attack_type == "dns_query" and d.raw_payload == "c2.evil.su"
