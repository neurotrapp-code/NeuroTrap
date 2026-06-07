#!/usr/bin/env python3
"""Day 17 — Train & persist the attacker-intent classifier.

Generates labeled synthetic sessions, trains RandomForest + SVM, reports macro-F1
(target > 0.85 per the plan), and saves the better model to
``behavior/models/intent_clf.joblib`` for the BehaviorEngine to serve.

Usage:
    python behavior/train_model.py [--n 120] [--out PATH]
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from behavior.classifier import IntentClassifier, DEFAULT_MODEL_PATH, _HAVE_SKLEARN
from behavior.features import feature_matrix
from behavior.synthetic import synthetic_sessions


def main():
    ap = argparse.ArgumentParser(description="Train the CADN intent classifier")
    ap.add_argument("--n", type=int, default=120, help="samples per intent class")
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--out", default=DEFAULT_MODEL_PATH)
    args = ap.parse_args()

    if not _HAVE_SKLEARN:
        print("[!] scikit-learn not installed. Install behavior/requirements.txt first.")
        sys.exit(1)

    print(f"[*] generating {args.n} synthetic sessions per class "
          f"({args.n * 6} total) ...")
    sessions, labels = synthetic_sessions(n_per_class=args.n, seed=args.seed)
    X = feature_matrix(sessions)

    clf = IntentClassifier()
    report = clf.fit(X, labels, verbose=True)

    print("\n================ summary ================")
    for name, m in report["all"].items():
        print(f"  {name:14s} macro-F1 = {m['macro_f1']:.3f}")
    print(f"  best model    = {report['best']} "
          f"(macro-F1 = {report['best_macro_f1']:.3f})")

    if report["best_macro_f1"] < 0.85:
        print("[!] WARNING: macro-F1 below the 0.85 target — review features/data.")
    else:
        print("[OK] macro-F1 target (>0.85) met.")

    path = clf.save(args.out)
    print(f"[*] model saved -> {path}")


if __name__ == "__main__":
    main()
