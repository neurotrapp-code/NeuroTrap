"""Normalize native honeypot events into the unified AlertEvent schema."""
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "detection"))
from alert_event import AlertEvent, HoneypotSource  # noqa: E402
from detectors.tool_fingerprint import identify_tool  # noqa: E402

# automated-tool category -> alert severity (mirrors tool_fingerprint)
_TOOL_SEV = {"scanner": "medium", "brute_forcer": "high", "web_scanner": "medium",
             "exploit_framework": "high", "malware": "high",
             "http_library": "low", "ssh_library": "low"}


def _sev_for_cowrie(eventid: str) -> str:
    if eventid == "cowrie.login.success":
        return "high"
    if eventid == "cowrie.command.input":
        return "medium"
    if "file_download" in eventid:
        return "high"
    return "low"


def from_cowrie(line: dict):
    eid = line.get("eventid", "")
    if not line.get("src_ip"):
        return None
    # Day 8-9: fingerprint the SSH client banner as an automated tool.
    if eid == "cowrie.client.version":
        ver = line.get("version") or line.get("message")
        hit = identify_tool(ver)
        if hit:
            tool, cat = hit
            return AlertEvent(
                timestamp=line.get("timestamp", AlertEvent.now_ts()),
                src_ip=line["src_ip"],
                dst_port=line.get("dst_port", 22),
                attack_type="automated_tool",
                severity=_TOOL_SEV.get(cat, "low"),
                raw_payload=ver,
                honeypot_source=HoneypotSource.COWRIE,
                detail=f"{tool} ({cat})",
            )
    return AlertEvent(
        timestamp=line.get("timestamp", AlertEvent.now_ts()),
        src_ip=line["src_ip"],
        dst_port=line.get("dst_port", 22),
        attack_type=eid.replace("cowrie.", "") or "event",
        severity=_sev_for_cowrie(eid),
        raw_payload=line.get("input") or line.get("message"),
        honeypot_source=HoneypotSource.COWRIE,
        detail=eid,
    )


def from_dionaea(line: dict):
    src = line.get("remote_host") or line.get("src_ip")
    if not src:
        return None
    return AlertEvent(
        timestamp=line.get("timestamp", AlertEvent.now_ts()),
        src_ip=src,
        dst_port=line.get("local_port") or line.get("dst_port"),
        attack_type="connection",
        severity="medium",
        raw_payload=line.get("protocol") or str(line.get("connection")),
        honeypot_source=HoneypotSource.DIONAEA,
        detail=line.get("protocol"),
    )


def _ts_to_iso(ts):
    """Zeek ts may be a float epoch or already ISO-8601."""
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()
    try:
        datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        return str(ts)
    except ValueError:
        return AlertEvent.now_ts()


def from_zeek_conn(line: dict):
    src = line.get("id.orig_h")
    if not src:
        return None
    return AlertEvent(
        timestamp=_ts_to_iso(line.get("ts", AlertEvent.now_ts())),
        src_ip=src,
        dst_port=line.get("id.resp_p"),
        attack_type="connection",
        severity="low",
        raw_payload=f'{line.get("proto")}/{line.get("service")} bytes={line.get("orig_bytes")}',
        honeypot_source=HoneypotSource.ZEEK,
        detail=line.get("service") or line.get("proto"),
    )


def from_zeek_http(line: dict):
    """Day 13: Zeek http.log. Flags automated tools via the User-Agent."""
    src = line.get("id.orig_h")
    if not src:
        return None
    ua = line.get("user_agent")
    hit = identify_tool(ua)
    attack_type = "automated_tool" if hit else "http_request"
    severity = _TOOL_SEV.get(hit[1], "low") if hit else "low"
    detail = f"{hit[0]} ({hit[1]})" if hit else (ua or line.get("method"))
    return AlertEvent(
        timestamp=_ts_to_iso(line.get("ts", AlertEvent.now_ts())),
        src_ip=src,
        dst_port=line.get("id.resp_p", 80),
        attack_type=attack_type,
        severity=severity,
        raw_payload=f'{line.get("method","")} {line.get("host","")}{line.get("uri","")}'.strip(),
        honeypot_source=HoneypotSource.ZEEK,
        detail=detail,
    )


def from_zeek_ssh(line: dict):
    """Day 13: Zeek ssh.log. Flags automated SSH clients via the client banner."""
    src = line.get("id.orig_h")
    if not src:
        return None
    client = line.get("client")
    hit = identify_tool(client)
    attack_type = "automated_tool" if hit else "ssh_connection"
    severity = _TOOL_SEV.get(hit[1], "low") if hit else "low"
    detail = f"{hit[0]} ({hit[1]})" if hit else client
    return AlertEvent(
        timestamp=_ts_to_iso(line.get("ts", AlertEvent.now_ts())),
        src_ip=src,
        dst_port=line.get("id.resp_p", 22),
        attack_type=attack_type,
        severity=severity,
        raw_payload=f'client={client} server={line.get("server")} auth={line.get("auth_success")}',
        honeypot_source=HoneypotSource.ZEEK,
        detail=detail,
    )


def from_zeek_dns(line: dict):
    """Day 13: Zeek dns.log. Captures queries for C2 / exfil visibility."""
    src = line.get("id.orig_h")
    if not src:
        return None
    return AlertEvent(
        timestamp=_ts_to_iso(line.get("ts", AlertEvent.now_ts())),
        src_ip=src,
        dst_port=line.get("id.resp_p", 53),
        attack_type="dns_query",
        severity="low",
        raw_payload=line.get("query"),
        honeypot_source=HoneypotSource.ZEEK,
        detail=line.get("qtype_name") or line.get("query"),
    )
