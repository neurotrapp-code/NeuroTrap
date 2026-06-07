"""Week 5 — API + live feed (serves the real store only)."""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pipeline"))

flask = pytest.importorskip("flask")


@pytest.fixture()
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("DB_BACKEND", "sqlite")
    monkeypatch.setenv("SQLITE_PATH", str(tmp_path / "cadn.sqlite"))
    monkeypatch.setenv("ADMIN_USER", "admin")
    monkeypatch.setenv("ADMIN_PASS", "secret")
    monkeypatch.setenv("JWT_SECRET", "x" * 32)
    from db import EventStore
    s = EventStore()
    s.write({"timestamp": "2026-06-07T10:00:00+00:00", "src_ip": "45.9.1.2",
             "dst_port": 22, "attack_type": "brute_force", "severity": "high",
             "raw_payload": None, "honeypot_source": "scapy_monitor", "detail": "x"})
    return s


@pytest.fixture()
def client(store):
    from api import create_app
    app = create_app(store=store, start_feed=False)
    return app.test_client()


def _token(client):
    r = client.post("/api/auth/login", json={"username": "admin", "password": "secret"})
    return r.get_json()["token"]


def test_health_public(client):
    assert client.get("/api/health").status_code == 200


def test_requires_auth(client):
    assert client.get("/api/events").status_code == 401
    assert client.get("/api/stats").status_code == 401


def test_login_and_read_live_data(client):
    tok = _token(client)
    H = {"Authorization": "Bearer " + tok}
    stats = client.get("/api/stats", headers=H).get_json()
    assert stats["total_events"] == 1
    evs = client.get("/api/events", headers=H).get_json()
    assert evs["count"] == 1 and evs["events"][0]["src_ip"] == "45.9.1.2"
    atk = client.get("/api/attackers/45.9.1.2", headers=H).get_json()
    assert atk["src_ip"] == "45.9.1.2"


def test_bad_login_rejected(client):
    assert client.post("/api/auth/login",
                       json={"username": "admin", "password": "nope"}).status_code == 401


def test_live_feed_tails_real_inserts(store):
    """LiveFeed must broadcast rows the pipeline inserts after connect."""
    from api.live import LiveFeed

    class FakeWS:
        def __init__(self): self.sent = []
        def send(self, p): self.sent.append(json.loads(p))

    feed = LiveFeed(store, poll_interval=0.05)
    ws = FakeWS()
    feed.register(ws)
    # new live event arrives AFTER the client connected
    store.write({"timestamp": "2026-06-07T10:05:00+00:00", "src_ip": "8.8.8.8",
                 "dst_port": 80, "attack_type": "automated_tool", "severity": "medium",
                 "raw_payload": "sqlmap", "honeypot_source": "zeek", "detail": "sqlmap"})
    feed._tick()
    assert any(m["data"]["src_ip"] == "8.8.8.8" for m in ws.sent)
