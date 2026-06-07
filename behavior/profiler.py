"""Days 19-20 — Attacker profiling & campaign clustering.

Maintains a per-source :class:`AttackerProfile` aggregated across all of that
source's sessions (first/last seen, dominant intent, union of TTPs, peak threat
score) and groups *sessions* into campaigns via DBSCAN over their feature
vectors. When scikit-learn is unavailable a deterministic radius-based fallback
clusterer is used so campaign IDs are always assigned.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

import numpy as np

from .features import Session, vectorize

try:
    from sklearn.cluster import DBSCAN
    from sklearn.preprocessing import StandardScaler
    _HAVE_SKLEARN = True
except Exception:                       # pragma: no cover
    _HAVE_SKLEARN = False


@dataclass
class AttackerProfile:
    src_ip: str
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    sessions: List[str] = field(default_factory=list)
    classified_intent: Optional[str] = None
    intent_confidence: float = 0.0
    ttps: List[str] = field(default_factory=list)            # technique IDs
    threat_score: int = 0                                    # peak across sessions
    campaign_id: Optional[int] = None
    _intent_votes: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "src_ip": self.src_ip,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "session_count": len(self.sessions),
            "sessions": self.sessions,
            "classified_intent": self.classified_intent,
            "intent_confidence": round(self.intent_confidence, 3),
            "ttps": self.ttps,
            "threat_score": self.threat_score,
            "campaign_id": self.campaign_id,
        }


class Profiler:
    """Accumulates session analyses into attacker profiles + campaign clusters."""

    def __init__(self):
        self.profiles: Dict[str, AttackerProfile] = {}
        self._session_vectors: Dict[str, np.ndarray] = {}    # session_id -> vec
        self._session_owner: Dict[str, str] = {}             # session_id -> src_ip

    def update(self, session: Session, intent: str, intent_conf: float,
               ttp_ids: List[str], threat_score: int) -> AttackerProfile:
        """Fold one analysed session into its source's profile."""
        ip = session.src_ip
        p = self.profiles.get(ip)
        if p is None:
            p = AttackerProfile(src_ip=ip)
            self.profiles[ip] = p

        if session.session_id not in p.sessions:
            p.sessions.append(session.session_id)
        # timeline
        if session.start_ts:
            p.first_seen = min(filter(None, [p.first_seen, session.start_ts]))
        if session.end_ts or session.start_ts:
            cand = session.end_ts or session.start_ts
            p.last_seen = max(filter(None, [p.last_seen, cand])) if p.last_seen else cand
        # intent voting weighted by confidence
        p._intent_votes[intent] = p._intent_votes.get(intent, 0.0) + max(intent_conf, 0.01)
        p.classified_intent = max(p._intent_votes, key=p._intent_votes.get)
        p.intent_confidence = max(p.intent_confidence, intent_conf)
        # TTP union
        for tid in ttp_ids:
            if tid not in p.ttps:
                p.ttps.append(tid)
        # peak threat
        p.threat_score = max(p.threat_score, threat_score)

        # cache vector for campaign clustering
        self._session_vectors[session.session_id] = vectorize(session)
        self._session_owner[session.session_id] = ip
        return p

    # -- campaign clustering ----------------------------------------------
    def cluster_campaigns(self, eps: float = 0.6, min_samples: int = 2) -> Dict[str, int]:
        """Cluster all seen sessions into campaigns; stamp profiles.

        Returns ``{session_id: campaign_id}``. ``-1`` means noise/singleton.
        A profile's ``campaign_id`` is set to the campaign its sessions most
        commonly belong to.
        """
        sids = list(self._session_vectors)
        if len(sids) < min_samples:
            labels = {sid: -1 for sid in sids}
            self._stamp(labels)
            return labels

        X = np.vstack([self._session_vectors[s] for s in sids])
        if _HAVE_SKLEARN:
            Xs = StandardScaler().fit_transform(X)
            db = DBSCAN(eps=eps * np.sqrt(Xs.shape[1]), min_samples=min_samples)
            raw = db.fit_predict(Xs)
        else:                                            # pragma: no cover
            raw = _fallback_cluster(X, min_samples)

        labels = {sid: int(lbl) for sid, lbl in zip(sids, raw)}
        self._stamp(labels)
        return labels

    def _stamp(self, labels: Dict[str, int]):
        per_ip: Dict[str, List[int]] = {}
        for sid, lbl in labels.items():
            ip = self._session_owner.get(sid)
            if ip is None:
                continue
            per_ip.setdefault(ip, []).append(lbl)
        for ip, lbls in per_ip.items():
            real = [l for l in lbls if l != -1]
            if real:
                self.profiles[ip].campaign_id = max(set(real), key=real.count)
            else:
                self.profiles[ip].campaign_id = -1

    def get(self, src_ip: str) -> Optional[AttackerProfile]:
        return self.profiles.get(src_ip)

    def all(self) -> List[AttackerProfile]:
        return list(self.profiles.values())


def _fallback_cluster(X: np.ndarray, min_samples: int) -> List[int]:  # pragma: no cover
    """Greedy radius clustering when sklearn is missing (cosine distance)."""
    norms = np.linalg.norm(X, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    Xn = X / norms
    n = len(Xn)
    labels = [-1] * n
    cid = 0
    for i in range(n):
        if labels[i] != -1:
            continue
        members = [j for j in range(n) if float(Xn[i] @ Xn[j]) > 0.85]
        if len(members) >= min_samples:
            for j in members:
                labels[j] = cid
            cid += 1
    return labels
