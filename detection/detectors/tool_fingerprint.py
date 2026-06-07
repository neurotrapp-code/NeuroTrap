"""Automated-tool fingerprint detector (Week 2, Days 8-9 objective).

Identifies the *tool* behind traffic from its signatures — HTTP User-Agent
strings, SSH client-version banners, and command/payload markers — so the
pipeline can flag automation (scanners, brute-forcers, web fuzzers, exploit
frameworks, scripting libraries, known bots) as a distinct ``automated_tool``
alert.

Two entry points:
  * ``identify_tool(text)``            — pure function, returns (tool, category) or None
  * ``ToolFingerprintDetector.observe`` — stateful, debounced per (src_ip, tool)
"""
import re
import time
from typing import Dict, Optional, Tuple

# (compiled regex, tool name, category). Order = priority (first match wins).
_SIGS = [
    # --- network / port scanners ---
    (r"\bmasscan\b", "masscan", "scanner"),
    (r"\bzgrab\b|\bzmap\b", "zgrab", "scanner"),
    (r"\bnmap\b|nmap scripting engine|nse", "nmap", "scanner"),
    (r"\bunicornscan\b", "unicornscan", "scanner"),
    # --- brute-forcers ---
    (r"\bhydra\b", "hydra", "brute_forcer"),
    (r"\bmedusa\b", "medusa", "brute_forcer"),
    (r"\bncrack\b", "ncrack", "brute_forcer"),
    (r"\bpatator\b", "patator", "brute_forcer"),
    # --- web vuln / content scanners ---
    (r"\bsqlmap\b", "sqlmap", "web_scanner"),
    (r"\bnikto\b", "nikto", "web_scanner"),
    (r"\bnuclei\b", "nuclei", "web_scanner"),
    (r"\b(gobuster|dirbuster|\bdirb\b|feroxbuster|wfuzz|ffuf)\b", "dir_bruteforcer", "web_scanner"),
    (r"\bwpscan\b", "wpscan", "web_scanner"),
    (r"\bacunetix|nessus|openvas|qualys\b", "vuln_scanner", "web_scanner"),
    # --- exploit frameworks / malware ---
    (r"metasploit|meterpreter|\bmsf\b", "metasploit", "exploit_framework"),
    (r"\bmirai\b|\bgafgyt\b|\bhajime\b", "iot_botnet", "malware"),
    # --- scripting libraries / generic clients (lower severity) ---
    (r"python-requests|python-urllib|aiohttp", "python-requests", "http_library"),
    (r"go-http-client", "go-http-client", "http_library"),
    (r"\blibwww-perl\b|\bphp\b/\d", "scripting-lib", "http_library"),
    (r"\bcurl/\d", "curl", "http_library"),
    (r"\bwget/\d|\bwget\b", "wget", "http_library"),
    # --- SSH client libraries used by bots/automation ---
    # (no trailing \b: version strings like 'libssh_0.9.6' put '_' after the name)
    (r"libssh", "libssh", "ssh_library"),
    (r"paramiko", "paramiko", "ssh_library"),
    (r"ssh-2\.0-go|\bgolang\b", "go-ssh", "ssh_library"),
    (r"\bputty\b", "putty", "ssh_library"),
]
_SIGS = [(re.compile(p, re.IGNORECASE), name, cat) for p, name, cat in _SIGS]

# Category -> alert severity.
_SEVERITY = {
    "scanner": "medium",
    "brute_forcer": "high",
    "web_scanner": "medium",
    "exploit_framework": "high",
    "malware": "high",
    "http_library": "low",
    "ssh_library": "low",
}

DEBOUNCE_WINDOW = 60        # seconds between repeat alerts for same (ip, tool)


def identify_tool(text: Optional[str]) -> Optional[Tuple[str, str]]:
    """Return ``(tool, category)`` if ``text`` matches a known signature, else None."""
    if not text:
        return None
    for rx, name, cat in _SIGS:
        if rx.search(text):
            return name, cat
    return None


class ToolFingerprintDetector:
    def __init__(self):
        self._alerted: Dict[tuple, float] = {}   # (src_ip, tool) -> last alert ts

    def observe(self, src_ip: str, text: str, dst_port: Optional[int] = None,
                now: float = None) -> Optional[dict]:
        """Fingerprint ``text`` (UA / SSH banner / payload). Returns a detection
        dict or None. Debounced per (src_ip, tool)."""
        hit = identify_tool(text)
        if not hit:
            return None
        tool, category = hit
        now = now or time.time()
        key = (src_ip, tool)
        last = self._alerted.get(key)            # None => never alerted -> fire
        if last is not None and now - last <= DEBOUNCE_WINDOW:
            return None
        self._alerted[key] = now
        return {
            "attack_type": "automated_tool",
            "severity": _SEVERITY.get(category, "low"),
            "src_ip": src_ip,
            "dst_port": dst_port,
            "detail": f"{tool} ({category})",
        }
