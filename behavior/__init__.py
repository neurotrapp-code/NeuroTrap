"""CADN Week 3 — Behavior Analysis Engine (Layer 3).

Turns raw Cowrie session activity into:
  * engineered feature vectors           (features.py)
  * an attacker-intent classification    (classifier.py)
  * MITRE ATT&CK TTPs                     (ttp_extractor.py / mitre.py)
  * a composite threat score             (threat_score.py)
  * persistent attacker profiles + campaign clusters (profiler.py)

The :class:`BehaviorEngine` in ``engine.py`` wires these together and is the
single entry point used by the rest of the platform (Week 5 response engine,
Week 4 deception engine).
"""
from .features import Session, parse_sessions, vectorize, FEATURE_NAMES
from .classifier import IntentClassifier, INTENTS
from .ttp_extractor import extract_ttps, TTP
from .threat_score import score_session
from .profiler import AttackerProfile, Profiler
from .engine import BehaviorEngine, SessionAnalysis

__all__ = [
    "Session", "parse_sessions", "vectorize", "FEATURE_NAMES",
    "IntentClassifier", "INTENTS",
    "extract_ttps", "TTP",
    "score_session",
    "AttackerProfile", "Profiler",
    "BehaviorEngine", "SessionAnalysis",
]
