"""Week 5 — response engine, actions, alerting."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from response import ResponseEngine, ResponseActuator, RecordingRunner, decide
from response.alerting import AlertManager, AlertRule


# --- decision matrix (plan Day 29-30) ------------------------------------
def test_decision_matrix_bands():
    assert decide(20) == ["log"]
    assert decide(55) == ["slow", "redirect"]
    assert decide(80) == ["isolate", "alert"]
    assert decide(95) == ["block", "alert", "forensic_capture"]


# --- actuator builds the right real commands -----------------------------
def test_actuator_block_command():
    rr = RecordingRunner()
    act = ResponseActuator(runner=rr)
    out = act.block("1.2.3.4")
    assert out.success and out.action == "block"
    assert ["iptables", "-I", "INPUT", "-s", "1.2.3.4", "-j", "DROP"] in rr.commands


def test_actuator_redirect_and_isolate():
    rr = RecordingRunner()
    act = ResponseActuator(runner=rr, redirect_port=2222)
    act.redirect("9.9.9.9")
    act.isolate("9.9.9.9")
    flat = [" ".join(c) for c in rr.commands]
    assert any("nat" in c and "REDIRECT" in c and "2222" in c for c in flat)
    assert any("FORWARD" in c and "DROP" in c for c in flat)


def test_forensic_capture_spawns_tcpdump():
    rr = RecordingRunner()
    act = ResponseActuator(runner=rr)
    out = act.forensic_capture("1.2.3.4", seconds=60)
    assert out.success
    assert any(c[0] == "tcpdump" for c in rr.commands)


# --- engine executes + records to the live store -------------------------
class _FakeStore:
    def __init__(self): self.responses = []
    def write_response(self, r): self.responses.append(r)


def test_engine_blocks_and_records_high_threat():
    store = _FakeStore()
    eng = ResponseEngine(actuator=ResponseActuator(runner=RecordingRunner()),
                         alerter=AlertManager(), store=store)
    res = eng.respond(src_ip="5.5.5.5", threat_score=95, intent="Malware Deployment")
    actions = [o["action"] for o in res.outcomes]
    assert "block" in actions and "forensic_capture" in actions
    assert any(r["action"] == "block" for r in store.responses)
    assert res.band == "block"


def test_engine_redirect_spawns_deception():
    import tempfile
    from deception import DeceptionEngine
    store = _FakeStore()
    dec = DeceptionEngine(workdir=tempfile.mkdtemp(), dry_run=True)
    eng = ResponseEngine(actuator=ResponseActuator(runner=RecordingRunner()),
                         store=store, deception_engine=dec)
    res = eng.respond(src_ip="6.6.6.6", threat_score=55,
                      intent="Credential Harvesting", n_ttps=5)
    assert res.deception_env_id is not None
    assert dec.get(res.deception_env_id) is not None


# --- alerting rule engine -------------------------------------------------
def test_alert_rule_matching():
    r = AlertRule("hi", min_score=70, min_severity="high")
    assert r.matches(score=80, severity="high")
    assert not r.matches(score=50, severity="high")
    assert not r.matches(score=80, severity="low")


def test_alertmanager_skips_unconfigured(monkeypatch):
    for k in ("SMTP_HOST", "SLACK_WEBHOOK", "TELEGRAM_BOT_TOKEN"):
        monkeypatch.delenv(k, raising=False)
    am = AlertManager()
    results = am.notify(src_ip="1.1.1.1", score=99, severity="critical")
    # all matched channels reported as skipped (never silently faked as sent)
    assert results and all(r["status"] == "skipped" for r in results)
