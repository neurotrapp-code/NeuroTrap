"""Day 17 — Attacker-intent classifier.

Multi-class classifier over six intent categories. Trains a RandomForest and an
SVM, keeps whichever scores the higher macro-F1 on a held-out split, and serves
predictions with a calibrated confidence.

If scikit-learn is unavailable (or no model has been trained yet) a transparent
rule-based :func:`heuristic_intent` is used instead, so the wider platform always
gets *some* classification.
"""
from __future__ import annotations

import os
from typing import List, Optional, Tuple

import numpy as np

from .features import Session, vectorize, FEATURE_NAMES

# Intent taxonomy — order is the canonical class order (plan §8.3 / Day 17).
INTENTS: List[str] = [
    "Reconnaissance",
    "Credential Harvesting",
    "Malware Deployment",
    "Lateral Movement",
    "Cryptomining",
    "Bot Enrollment",
]

DEFAULT_MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                  "models", "intent_clf.joblib")

try:                       # optional heavy dep
    import joblib          # noqa: F401
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.svm import SVC
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import f1_score, classification_report
    _HAVE_SKLEARN = True
except Exception:          # pragma: no cover - depends on environment
    _HAVE_SKLEARN = False


# ---------------------------------------------------------------------------
# Rule-based fallback / cold-start classifier
# ---------------------------------------------------------------------------
def heuristic_intent(session: Session) -> Tuple[str, float]:
    """Best-effort intent from simple, explainable rules. Returns (intent, conf)."""
    base = session.base_commands()
    joined = " ".join(session.commands).lower()
    miner = any(t in joined for t in ("xmrig", "minerd", "cpuminer", "stratum", "monero"))
    has_dl = bool(session.downloads) or "wget" in base or "curl" in base or "tftp" in base
    persistence = "crontab" in base or "rc.local" in joined or "authorized_keys" in joined
    secrets = session.sensitive_reads() > 0 or "shadow" in joined or ".aws" in joined
    lateral = any(c in base for c in ("ssh", "scp")) or len(session.tcpip_requests) > 0

    if miner:
        return "Cryptomining", 0.8
    if persistence and has_dl:
        return "Bot Enrollment", 0.7
    if has_dl and ("chmod" in base or "./" in joined or "| sh" in joined or "|sh" in joined):
        return "Malware Deployment", 0.75
    if secrets:
        return "Credential Harvesting", 0.7
    if lateral:
        return "Lateral Movement", 0.65
    return "Reconnaissance", 0.55


# ---------------------------------------------------------------------------
# Trainable classifier
# ---------------------------------------------------------------------------
class IntentClassifier:
    """Wraps the trained sklearn model (with a heuristic fallback)."""

    def __init__(self, model=None, algo: str = "heuristic"):
        self._model = model
        self.algo = algo
        self.feature_names = list(FEATURE_NAMES)

    # -- training ----------------------------------------------------------
    def fit(self, X: np.ndarray, y: List[str], test_size: float = 0.25,
            seed: int = 42, verbose: bool = False) -> dict:
        """Train RF + SVM, keep the better one. Returns a metrics report dict."""
        if not _HAVE_SKLEARN:
            raise RuntimeError("scikit-learn not installed; cannot train. "
                               "Heuristic classification is still available.")
        X = np.asarray(X, dtype=float)
        X_tr, X_te, y_tr, y_te = train_test_split(
            X, y, test_size=test_size, random_state=seed, stratify=y)

        candidates = {
            "random_forest": RandomForestClassifier(
                n_estimators=300, max_depth=None, class_weight="balanced",
                random_state=seed, n_jobs=-1),
            "svm": make_pipeline(
                StandardScaler(),
                SVC(kernel="rbf", C=10, gamma="scale", probability=True,
                    class_weight="balanced", random_state=seed)),
        }

        results = {}
        best_name, best_f1, best_model = None, -1.0, None
        for name, model in candidates.items():
            model.fit(X_tr, y_tr)
            pred = model.predict(X_te)
            f1 = f1_score(y_te, pred, average="macro")
            results[name] = {"macro_f1": float(f1)}
            if verbose:
                print(f"\n=== {name}  macro-F1={f1:.3f} ===")
                print(classification_report(y_te, pred, zero_division=0))
            if f1 > best_f1:
                best_name, best_f1, best_model = name, f1, model

        self._model = best_model
        self.algo = best_name
        return {"best": best_name, "best_macro_f1": float(best_f1), "all": results}

    # -- serving -----------------------------------------------------------
    def predict(self, session: Session) -> Tuple[str, float]:
        """Return (intent, confidence) for one session."""
        if self._model is None:
            return heuristic_intent(session)
        vec = vectorize(session).reshape(1, -1)
        intent = str(self._model.predict(vec)[0])
        conf = self._confidence(vec, intent)
        return intent, conf

    def predict_batch(self, sessions: List[Session]) -> List[Tuple[str, float]]:
        return [self.predict(s) for s in sessions]

    def _confidence(self, vec: np.ndarray, intent: str) -> float:
        if hasattr(self._model, "predict_proba"):
            proba = self._model.predict_proba(vec)[0]
            classes = list(self._model.classes_)
            return float(proba[classes.index(intent)])
        return 1.0

    @property
    def is_trained(self) -> bool:
        return self._model is not None

    # -- persistence -------------------------------------------------------
    def save(self, path: str = DEFAULT_MODEL_PATH):
        if not _HAVE_SKLEARN:
            raise RuntimeError("joblib/sklearn not available; nothing to save.")
        if self._model is None:
            raise RuntimeError("no trained model to save.")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump({"model": self._model, "algo": self.algo,
                     "features": self.feature_names}, path)
        return path

    @classmethod
    def load(cls, path: str = DEFAULT_MODEL_PATH) -> "IntentClassifier":
        """Load a trained model; fall back to heuristic if missing/unavailable."""
        if not _HAVE_SKLEARN or not os.path.exists(path):
            return cls(model=None, algo="heuristic")
        blob = joblib.load(path)
        clf = cls(model=blob["model"], algo=blob.get("algo", "loaded"))
        clf.feature_names = blob.get("features", list(FEATURE_NAMES))
        return clf
