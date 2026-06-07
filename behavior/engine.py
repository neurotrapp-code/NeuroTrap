"""Day 21 — Behavior Analysis Engine (integration).

`BehaviorEngine` is Layer 3's single entry point. Given raw Cowrie events (or
pre-built :class:`Session` objects) it:

    parse -> classify intent -> extract MITRE TTPs -> score threat
          -> update attacker profile -> cluster campaigns -> (optionally) persist

It loads the trained intent model if present and otherwise serves the heuristic
classifier, so it is always operable. The Week-4 Deception Engine and Week-5
Response Engine consume :class:`SessionAnalysis` / :class:`AttackerProfile`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable, List, Optional

from .classifier import IntentClassifier
from .features import Session, parse_sessions
from .profiler import AttackerProfile, Profiler
from .threat_score import band, score_session
from .ttp_extractor import TTP, extract_ttps


@dataclass
class SessionAnalysis:
    session_id: str
    src_ip: str
    intent: str
    intent_confidence: float
    threat_score: int
    band: str
    ttps: List[TTP] = field(default_factory=list)
    score_breakdown: dict = field(default_factory=dict)
    analyzed_at: str = ""

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "src_ip": self.src_ip,
            "intent": self.intent,
            "intent_confidence": round(self.intent_confidence, 3),
            "threat_score": self.threat_score,
            "band": self.band,
            "ttps": [t.to_dict() for t in self.ttps],
            "score_breakdown": self.score_breakdown,
            "analyzed_at": self.analyzed_at,
        }


class BehaviorEngine:
    def __init__(self, classifier: Optional[IntentClassifier] = None,
                 store=None, fuzzy_ttp: bool = False):
        # load trained model if available; falls back to heuristic internally
        self.classifier = classifier or IntentClassifier.load()
        self.profiler = Profiler()
        self.store = store                 # optional EventStore for persistence
        self.fuzzy_ttp = fuzzy_ttp

    # -- single session ----------------------------------------------------
    def analyze_session(self, session: Session, persist: bool = True) -> SessionAnalysis:
        intent, conf = self.classifier.predict(session)
        ttps = extract_ttps(session.commands, fuzzy=self.fuzzy_ttp)
        score, breakdown = score_session(session, intent, conf, ttps)

        analysis = SessionAnalysis(
            session_id=session.session_id,
            src_ip=session.src_ip,
            intent=intent,
            intent_confidence=conf,
            threat_score=score,
            band=band(score),
            ttps=ttps,
            score_breakdown=breakdown,
            analyzed_at=datetime.now(timezone.utc).isoformat(),
        )

        self.profiler.update(
            session, intent, conf, [t.technique_id for t in ttps], score)

        if persist and self.store is not None:
            self.store.write_session_analysis(analysis.to_dict())
        return analysis

    # -- many events / sessions -------------------------------------------
    def analyze_events(self, events: Iterable[dict], persist: bool = True
                       ) -> List[SessionAnalysis]:
        sessions = parse_sessions(events)
        return self.analyze_sessions(sessions.values(), persist=persist)

    def analyze_sessions(self, sessions: Iterable[Session], persist: bool = True
                         ) -> List[SessionAnalysis]:
        analyses = [self.analyze_session(s, persist=persist) for s in sessions]
        # campaign clustering needs the whole batch
        self.profiler.cluster_campaigns()
        if persist and self.store is not None:
            for p in self.profiler.all():
                self.store.upsert_profile(p.to_dict())
        return analyses

    # -- accessors ---------------------------------------------------------
    def profile(self, src_ip: str) -> Optional[AttackerProfile]:
        return self.profiler.get(src_ip)

    def profiles(self) -> List[AttackerProfile]:
        return self.profiler.all()
