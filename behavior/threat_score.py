"""Composite threat scoring (0-100) for a classified session.

Blends three signals into one score the Week-5 response engine can threshold:
  * intent base risk        (recon is low, impact/lateral is high)
  * TTP severity            (max + breadth of MITRE techniques observed)
  * behavioural escalation  (successful login, downloads, persistence, secrets)

Returns the score plus a breakdown so the dashboard can explain *why*.
The response matrix (plan Day 29-30) reads these bands:
    <40 log · 40-70 slow/redirect · 70-90 isolate · >90 block.
"""
from __future__ import annotations

from typing import List, Optional, Tuple

from .features import Session
from .ttp_extractor import TTP

# Base risk per intent class (0-1).
_INTENT_RISK = {
    "Reconnaissance": 0.20,
    "Credential Harvesting": 0.75,
    "Malware Deployment": 0.80,
    "Lateral Movement": 0.85,
    "Cryptomining": 0.70,
    "Bot Enrollment": 0.80,
}

# Component weights (sum = 1.0).
_W_INTENT = 0.40
_W_TTP = 0.35
_W_BEHAVIOR = 0.25


def _ttp_component(ttps: List[TTP]) -> float:
    if not ttps:
        return 0.0
    strongest = max(t.weight * t.confidence for t in ttps)
    # breadth bonus: more distinct techniques => slightly higher, capped.
    breadth = min(len(ttps) / 8.0, 1.0)
    return min(0.7 * strongest + 0.3 * breadth, 1.0)


def _behavior_component(session: Session) -> float:
    score = 0.0
    if session.login_success:
        score += 0.30
    if session.downloads:
        score += 0.25
    if session.sensitive_reads() > 0:
        score += 0.25
    if any(c in session.base_commands() for c in ("crontab",)) or \
            "authorized_keys" in " ".join(session.commands).lower():
        score += 0.20            # persistence
    if session.tcpip_requests:
        score += 0.15            # pivot attempt
    return min(score, 1.0)


def score_session(session: Session, intent: str, intent_conf: float,
                  ttps: List[TTP]) -> Tuple[int, dict]:
    """Return ``(threat_score_0_100, breakdown)``."""
    intent_risk = _INTENT_RISK.get(intent, 0.5) * max(intent_conf, 0.5)
    ttp_risk = _ttp_component(ttps)
    behav_risk = _behavior_component(session)

    composite = (_W_INTENT * intent_risk
                 + _W_TTP * ttp_risk
                 + _W_BEHAVIOR * behav_risk)
    score = int(round(min(composite, 1.0) * 100))

    breakdown = {
        "intent": intent,
        "intent_risk": round(intent_risk, 3),
        "ttp_risk": round(ttp_risk, 3),
        "behavior_risk": round(behav_risk, 3),
        "weights": {"intent": _W_INTENT, "ttp": _W_TTP, "behavior": _W_BEHAVIOR},
        "band": band(score),
    }
    return score, breakdown


def band(score: int) -> str:
    """Map a 0-100 score to the Week-5 response band."""
    if score < 40:
        return "log"
    if score < 70:
        return "slow_redirect"
    if score < 90:
        return "isolate"
    return "block"
