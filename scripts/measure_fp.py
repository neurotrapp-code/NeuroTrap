"""Crude false-positive estimate: alerts as a fraction of all events in a window."""
import os
import sqlite3

default_db = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "cadn.sqlite")
db = os.environ.get("SQLITE_PATH", default_db)
c = sqlite3.connect(db)
total = c.execute(
    "SELECT COUNT(*) FROM events WHERE timestamp > datetime('now','-5 minutes')"
).fetchone()[0]
alerts = c.execute(
    """SELECT COUNT(*) FROM events
       WHERE attack_type IN ('port_scan','brute_force','protocol_anomaly','automated_tool')
       AND timestamp > datetime('now','-5 minutes')"""
).fetchone()[0]
rate = (alerts / total * 100) if total else 0
print(f"events={total} alerts={alerts} fp_rate={rate:.1f}%")
