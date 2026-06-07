"""Integration: detection events -> Week-3 analysis -> DB -> Week-4 deception."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from behavior.engine import BehaviorEngine
from behavior.classifier import IntentClassifier
from behavior.features import parse_sessions
from deception import DeceptionEngine

# db.py is stdlib-only (no pydantic), safe to import here.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pipeline"))
from db import EventStore  # noqa: E402


_ATTACK = [
    {"eventid": "cowrie.session.connect", "session": "z", "src_ip": "198.51.100.7",
     "timestamp": "2026-06-01T10:00:00+00:00"},
    {"eventid": "cowrie.login.success", "session": "z", "src_ip": "198.51.100.7",
     "username": "root", "password": "123456"},
    {"eventid": "cowrie.command.input", "session": "z", "src_ip": "198.51.100.7",
     "input": "cat /etc/shadow"},
    {"eventid": "cowrie.command.input", "session": "z", "src_ip": "198.51.100.7",
     "input": "cat /root/.aws/credentials"},
    {"eventid": "cowrie.command.input", "session": "z", "src_ip": "198.51.100.7",
     "input": "ssh root@10.0.0.5"},
    {"eventid": "cowrie.session.closed", "session": "z", "duration": 95.0,
     "timestamp": "2026-06-01T10:01:35+00:00"},
]


def test_full_pipeline_persists_and_spawns(monkeypatch, tmp_path):
    # isolate the sqlite db
    monkeypatch.setenv("DB_BACKEND", "sqlite")
    monkeypatch.setenv("SQLITE_PATH", str(tmp_path / "cadn.sqlite"))
    store = EventStore()

    eng = BehaviorEngine(classifier=IntentClassifier(model=None), store=store)
    analyses = eng.analyze_events(_ATTACK, persist=True)
    a = analyses[0]
    assert a.src_ip == "198.51.100.7"
    assert any(t.technique_id == "T1003.008" for t in a.ttps)   # shadow dump

    # profile persisted to DB and retrievable
    prof = store.get_profile("198.51.100.7")
    assert prof is not None
    assert prof["threat_score"] == a.threat_score
    assert "T1003.008" in prof["ttps"]

    # Week-4: build a tailored environment straight from the analysis
    dec = DeceptionEngine(workdir=str(tmp_path / "dec"), dry_run=True, seed=1)
    session = parse_sessions(_ATTACK)["z"]
    env = DeceptionEngine.from_analysis(a, session=session, engine=dec)
    # credential harvesting / lateral -> advanced corporate decoy
    assert env.tier == "advanced"
    assert "/root/.aws/credentials" in env.manifest
    assert dec.health(env.env_id)["healthy"]
