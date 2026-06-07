"""Day 18 — TTP extraction (command sequence -> MITRE ATT&CK techniques).

Primary path is fast, deterministic regex matching against
:data:`behavior.mitre.RULES`. If ``sentence-transformers`` is installed an
optional fuzzy pass adds lower-confidence matches for commands that no rule
caught, by embedding the command and comparing it to technique descriptions
(this mirrors the plan's "sentence-transformer embeddings for fuzzy matching").
The extractor degrades gracefully to rule-only when the model is absent.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from .mitre import RULES


@dataclass
class TTP:
    technique_id: str
    name: str
    tactic: str
    confidence: float
    weight: float
    evidence: List[str] = field(default_factory=list)   # commands that matched

    def to_dict(self) -> dict:
        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "tactic": self.tactic,
            "confidence": round(self.confidence, 3),
            "weight": self.weight,
            "evidence": self.evidence[:5],
        }


def extract_ttps(commands: List[str], fuzzy: bool = False,
                 fuzzy_threshold: float = 0.45) -> List[TTP]:
    """Map a list of raw command strings to a deduplicated list of :class:`TTP`.

    Exact regex matches get confidence 1.0. Optional fuzzy matches (if enabled
    and the model is available) get their cosine similarity as confidence.
    Results are sorted by ``weight * confidence`` descending.
    """
    found: dict[str, TTP] = {}

    for cmd in commands:
        for rule in RULES:
            if rule.pattern.search(cmd):
                ttp = found.get(rule.technique_id)
                if ttp is None:
                    ttp = TTP(rule.technique_id, rule.name, rule.tactic,
                              confidence=1.0, weight=rule.weight)
                    found[rule.technique_id] = ttp
                if cmd not in ttp.evidence:
                    ttp.evidence.append(cmd)

    if fuzzy:
        _fuzzy_augment(commands, found, fuzzy_threshold)

    return sorted(found.values(), key=lambda t: t.weight * t.confidence, reverse=True)


# ---------------------------------------------------------------------------
# Optional embedding-based fuzzy matching
# ---------------------------------------------------------------------------
_MODEL = None
_TECH_EMB = None


def _load_model():
    global _MODEL, _TECH_EMB
    if _MODEL is not None:
        return _MODEL
    try:                                   # pragma: no cover - optional dep
        from sentence_transformers import SentenceTransformer, util  # noqa: F401
        _MODEL = SentenceTransformer("all-MiniLM-L6-v2")
        descs = [f"{r.name} ({r.tactic})" for r in RULES]
        _TECH_EMB = _MODEL.encode(descs, convert_to_tensor=True, normalize_embeddings=True)
    except Exception:
        _MODEL = None
    return _MODEL


def _fuzzy_augment(commands: List[str], found: dict, threshold: float):  # pragma: no cover
    model = _load_model()
    if model is None:
        return
    from sentence_transformers import util
    # only consider commands no rule already explained
    unmatched = [c for c in commands
                 if not any(r.pattern.search(c) for r in RULES)]
    if not unmatched:
        return
    emb = model.encode(unmatched, convert_to_tensor=True, normalize_embeddings=True)
    sims = util.cos_sim(emb, _TECH_EMB)        # [n_cmds, n_rules]
    for i, cmd in enumerate(unmatched):
        j = int(sims[i].argmax())
        score = float(sims[i][j])
        if score >= threshold:
            rule = RULES[j]
            ttp = found.get(rule.technique_id)
            if ttp is None:
                found[rule.technique_id] = TTP(
                    rule.technique_id, rule.name, rule.tactic,
                    confidence=score, weight=rule.weight, evidence=[cmd])
            else:
                ttp.confidence = max(ttp.confidence, score)
                if cmd not in ttp.evidence:
                    ttp.evidence.append(cmd)
