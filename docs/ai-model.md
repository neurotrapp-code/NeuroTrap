# CADN AI / ML Model Card (Week 3 engine, consumed by Weeks 4–5)

## Task
Multi-class classification of an attacker SSH/Telnet **session** into intent:
Reconnaissance · Credential Harvesting · Malware Deployment · Lateral Movement ·
Cryptomining · Bot Enrollment.

## Features (`behavior/features.py`)
Per session: behavioural aggregates (command count/uniqueness, duration, login
success, downloads + distinct hosts, outbound pivots, sensitive-file reads,
chmod/persistence flags, command cadence) concatenated with a **bag-of-commands**
count vector over a fixed attacker-command vocabulary. Vector length and column
names are exposed as `FEATURE_NAMES`.

## Models (`behavior/classifier.py`)
Trains a **RandomForest** (300 trees, balanced) and an **SVM** (RBF, standardized)
and keeps the higher macro-F1. Persisted to `behavior/models/intent_clf.joblib`.
A transparent rule-based `heuristic_intent()` serves when no model/sklearn is
present, so the platform is always operable.

## Training (`behavior/train_model.py`)
```bash
python behavior/train_model.py --n 120
```
Currently trained on **labeled synthetic sessions** (`behavior/synthetic.py`) that
encode realistic command sequences per intent. Reported macro-F1 is **> 0.85** (the
plan's target; on the separable synthetic split it reaches ~1.0).

> **Honesty note:** synthetic-data F1 measures separability of the bootstrap set,
> **not** real-world accuracy. Retrain on labeled captured sessions before quoting
> production numbers. The feature/serving pipeline is identical for real data.

## TTP extraction (`behavior/ttp_extractor.py`, `mitre.py`)
Rule-based mapping of commands → MITRE ATT&CK technique IDs (exact-match
confidence 1.0). Optional embedding fuzzy-match if `sentence-transformers` is
installed. Confidence and matching evidence are attached to each technique.

## Threat score (`behavior/threat_score.py`)
`0.40·intent + 0.35·TTP + 0.25·behaviour`, scaled 0–100, mapped to response bands.

## Profiling (`behavior/profiler.py`)
Per-IP aggregation + DBSCAN clustering of session vectors into campaigns.

## Retraining checklist
1. Export labeled sessions (cowrie JSON + intent label).
2. Replace/augment `synthetic.py` with the real data loader.
3. `python behavior/train_model.py`; confirm macro-F1 on a held-out **real** split.
4. Commit the new `intent_clf.joblib` (or ship via release artifact).
