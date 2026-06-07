import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pipeline"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "detection"))
import normalizer as N


def test_cowrie_login_normalizes():
    raw = {"eventid": "cowrie.login.success", "src_ip": "10.0.0.9",
           "timestamp": "2026-01-01T00:00:00+00:00", "username": "root", "password": "123456"}
    e = N.from_cowrie(raw)
    assert e.honeypot_source.value == "cowrie"
    assert e.severity.value == "high"


def test_dionaea_connection_normalizes():
    raw = {"remote_host": "10.0.0.9", "local_port": 445, "protocol": "smbd",
           "timestamp": "2026-01-01T00:00:00+00:00"}
    e = N.from_dionaea(raw)
    assert e.honeypot_source.value == "dionaea"
    assert e.dst_port == 445


def test_zeek_float_ts_normalizes():
    raw = {"id.orig_h": "10.0.0.9", "id.resp_p": 22, "ts": 1735689600.0, "proto": "tcp"}
    e = N.from_zeek_conn(raw)
    assert e.honeypot_source.value == "zeek"
