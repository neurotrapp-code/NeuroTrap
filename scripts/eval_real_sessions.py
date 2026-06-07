#!/usr/bin/env python3
"""Evaluate the intent classifier on REAL captured Cowrie sessions (Phase 8).

Two steps:

  1) Export model predictions on real sessions to a CSV for human labelling:
       python scripts/eval_real_sessions.py --export real_eval.csv
     Open the CSV, read each session's commands, and fill the empty `label`
     column with the correct intent (see the printed list of valid labels).

  2) Score the model against your labels (real precision/recall/F1):
       python scripts/eval_real_sessions.py --score real_eval.csv

This turns the model card's "synthetic F1" into a real-world number. Run in the
portal container for Mongo deployments only if reading from DB; by default it
reads the Cowrie JSON log directly, so it works anywhere the log is mounted.
"""
import argparse
import csv
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from behavior.features import parse_sessions                 # noqa: E402
from behavior.classifier import IntentClassifier, INTENTS    # noqa: E402
from behavior.ttp_extractor import extract_ttps              # noqa: E402

DEFAULT_LOG = os.path.join(ROOT, "honeypots/cowrie/var/log/cowrie/cowrie.json")


def _load_events(path):
    events = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def do_export(args):
    events = _load_events(args.log)
    sessions = parse_sessions(events)
    clf = IntentClassifier.load()
    rows = []
    for s in sessions.values():
        if len(s.commands) < args.min_commands:
            continue
        intent, conf = clf.predict(s)
        ttps = extract_ttps(s.commands)
        rows.append({
            "session_id": s.session_id,
            "src_ip": s.src_ip,
            "n_commands": len(s.commands),
            "duration_s": round(s.duration_s, 1),
            "predicted_intent": intent,
            "confidence": round(conf, 3),
            "ttps": ";".join(t.technique_id for t in ttps),
            "commands": " || ".join(s.commands)[:800],
            "label": "",
        })
    if not rows:
        print(f"[!] no sessions with >= {args.min_commands} commands in {args.log}. "
              "Capture more interactive traffic first.")
        return
    with open(args.export, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)
    print(f"[*] wrote {len(rows)} sessions -> {args.export}")
    print(f"[*] model: {'trained:'+clf.algo if clf.is_trained else 'HEURISTIC (no trained model)'}")
    print("[*] fill the empty 'label' column with one of:")
    for i in INTENTS:
        print(f"      - {i}")


def do_score(args):
    pairs = []
    bad = 0
    with open(args.score, "r", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            label = (r.get("label") or "").strip()
            pred = (r.get("predicted_intent") or "").strip()
            if not label:
                continue
            if label not in INTENTS:
                bad += 1
                continue
            pairs.append((pred, label))
    if not pairs:
        print("[!] no labelled rows. Fill the 'label' column with valid intents first.")
        return
    preds = [p for p, _ in pairs]
    labels = [l for _, l in pairs]
    acc = sum(p == l for p, l in pairs) / len(pairs)
    print(f"[*] scored {len(pairs)} labelled sessions"
          + (f" ({bad} skipped: invalid label)" if bad else ""))
    print(f"[*] accuracy = {acc:.3f}")
    try:
        from sklearn.metrics import classification_report, f1_score
        macro = f1_score(labels, preds, average="macro", zero_division=0)
        print(f"[*] macro-F1 = {macro:.3f}  (plan target > 0.85)")
        print(classification_report(labels, preds, zero_division=0))
    except Exception:
        # manual per-class counts if sklearn unavailable
        print("[*] sklearn not available — per-class accuracy only:")
        for intent in INTENTS:
            n = sum(1 for _, l in pairs if l == intent)
            ok = sum(1 for p, l in pairs if l == intent and p == l)
            if n:
                print(f"    {intent:24s} {ok}/{n}")
    print("\nRecord this number (and the date/sample size) in docs/ai-model.md.")


def main():
    ap = argparse.ArgumentParser(description="Evaluate classifier on real sessions")
    ap.add_argument("--log", default=DEFAULT_LOG, help="path to cowrie.json")
    ap.add_argument("--min-commands", type=int, default=1,
                    help="skip sessions with fewer commands")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--export", metavar="CSV", help="write predictions for labelling")
    g.add_argument("--score", metavar="CSV", help="score labelled CSV")
    args = ap.parse_args()
    (do_export if args.export else do_score)(args)


if __name__ == "__main__":
    main()
