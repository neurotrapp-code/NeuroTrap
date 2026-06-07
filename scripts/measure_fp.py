#!/usr/bin/env python3
"""False-positive estimate over a recent time window (SQLite or MongoDB).

FP estimate = detection alerts / all events seen in the window. Run it during a
mix of benign + attack traffic; a low ratio on benign-heavy traffic indicates few
false positives (plan target < 5%).

Backend is chosen by DB_BACKEND (sqlite|mongodb), matching pipeline/db.py.

  # SQLite (host):
  python scripts/measure_fp.py --window 5

  # MongoDB: run INSIDE the portal container (mongo isn't published to the host):
  docker exec -w /app cadn-portal python scripts/measure_fp.py --window 5
  # ...or whole-capture totals:
  docker exec -w /app cadn-portal python scripts/measure_fp.py --all
"""
import argparse
import os
from datetime import datetime, timedelta, timezone

ALERT_TYPES = ("port_scan", "brute_force", "protocol_anomaly", "automated_tool")


def _cutoff_iso(minutes: int) -> str:
    # ISO-8601 UTC string; our stored timestamps are ISO UTC, so lexical > works
    # (and avoids sqlite datetime() vs 'T'-separated ISO mismatch).
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()


def _counts_sqlite(cutoff):
    import sqlite3
    default_db = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "..", "data", "cadn.sqlite")
    path = os.environ.get("SQLITE_PATH", default_db)
    c = sqlite3.connect(path)
    where = "" if cutoff is None else "WHERE timestamp > ?"
    args = () if cutoff is None else (cutoff,)
    total = c.execute(f"SELECT COUNT(*) FROM events {where}", args).fetchone()[0]
    qmarks = ",".join("?" * len(ALERT_TYPES))
    a_where = f"attack_type IN ({qmarks})" + ("" if cutoff is None else " AND timestamp > ?")
    a_args = ALERT_TYPES + ((cutoff,) if cutoff else ())
    alerts = c.execute(f"SELECT COUNT(*) FROM events WHERE {a_where}", a_args).fetchone()[0]
    return total, alerts


def _counts_mongo(cutoff):
    from pymongo import MongoClient
    client = MongoClient(os.environ["MONGO_URI"], serverSelectionTimeoutMS=5000)
    col = client.get_default_database()["events"]
    base = {} if cutoff is None else {"timestamp": {"$gt": cutoff}}
    total = col.count_documents(base)
    a_query = dict(base); a_query["attack_type"] = {"$in": list(ALERT_TYPES)}
    alerts = col.count_documents(a_query)
    return total, alerts


def main():
    ap = argparse.ArgumentParser(description="CADN false-positive estimate")
    ap.add_argument("--window", type=int, default=5, help="minutes to look back")
    ap.add_argument("--all", action="store_true", help="ignore window; use all events")
    args = ap.parse_args()

    cutoff = None if args.all else _cutoff_iso(args.window)
    backend = os.environ.get("DB_BACKEND", "sqlite")
    total, alerts = (_counts_mongo if backend == "mongodb" else _counts_sqlite)(cutoff)

    rate = (alerts / total * 100) if total else 0.0
    scope = "all-time" if args.all else f"last {args.window} min"
    print(f"backend={backend} scope={scope} events={total} alerts={alerts} "
          f"fp_rate={rate:.1f}%")
    if total and rate >= 5.0:
        print("[!] above 5% target - review thresholds (detection/detectors/*) "
              "and ensure benign traffic is included in the window.")


if __name__ == "__main__":
    main()
