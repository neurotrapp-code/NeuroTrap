"""Event store for CADN. Backend chosen via DB_BACKEND env (sqlite|mongodb).

Holds four collections/tables:
  * events            — normalized detection alerts (Weeks 1-2)
  * session_analysis  — per-session behaviour verdicts (Week 3)
  * profiles          — aggregated attacker profiles    (Week 3)
  * responses         — autonomous response actions taken (Week 5)

The read queries (get_events / get_stats / get_attacker / get_responses) are what
the Week-5 API serves to the dashboard — they read the LIVE store the pipeline
populates from real honeypot/IDS traffic; there is no demo/sample data path.
"""
import json
import os
import sqlite3

BACKEND = os.environ.get("DB_BACKEND", "sqlite")


class EventStore:
    def __init__(self):
        if BACKEND == "mongodb":
            from pymongo import MongoClient, ASCENDING
            self.client = MongoClient(os.environ["MONGO_URI"])
            self.col = self.client.get_default_database()["events"]
            self.col.create_index([("src_ip", ASCENDING)])
            self.col.create_index([("timestamp", ASCENDING)])
            self.col.create_index([("attack_type", ASCENDING)])
            db = self.client.get_default_database()
            self.sessions_col = db["session_analysis"]
            self.sessions_col.create_index([("src_ip", ASCENDING)])
            self.sessions_col.create_index([("session_id", ASCENDING)], unique=True)
            self.profiles_col = db["profiles"]
            self.profiles_col.create_index([("src_ip", ASCENDING)], unique=True)
            self.responses_col = db["responses"]
            self.responses_col.create_index([("src_ip", ASCENDING)])
            self.responses_col.create_index([("ts", ASCENDING)])
            self._mode = "mongo"
        else:
            default_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "..", "data", "cadn.sqlite")
            path = os.environ.get("SQLITE_PATH", default_path)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            self.conn = sqlite3.connect(path, check_same_thread=False)
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_port INTEGER,
                    attack_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    raw_payload TEXT,
                    honeypot_source TEXT NOT NULL,
                    detail TEXT
                )""")
            # REQUIRED indexes (plan): src_ip and timestamp, plus attack_type
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_src_ip ON events(src_ip)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_ts ON events(timestamp)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_type ON events(attack_type)")
            # Week 3: behaviour analysis tables
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS session_analysis (
                    session_id TEXT PRIMARY KEY,
                    src_ip TEXT NOT NULL,
                    intent TEXT,
                    intent_confidence REAL,
                    threat_score INTEGER,
                    band TEXT,
                    ttps TEXT,
                    analyzed_at TEXT
                )""")
            self.conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_sa_ip ON session_analysis(src_ip)")
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS profiles (
                    src_ip TEXT PRIMARY KEY,
                    first_seen TEXT,
                    last_seen TEXT,
                    session_count INTEGER,
                    classified_intent TEXT,
                    intent_confidence REAL,
                    ttps TEXT,
                    threat_score INTEGER,
                    campaign_id INTEGER
                )""")
            # Week 5: autonomous response actions taken
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS responses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    action TEXT NOT NULL,
                    threat_score INTEGER,
                    band TEXT,
                    success INTEGER,
                    detail TEXT
                )""")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_resp_ip ON responses(src_ip)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_resp_ts ON responses(ts)")
            self.conn.commit()
            self._mode = "sqlite"

    def write(self, event_dict: dict):
        if self._mode == "mongo":
            self.col.insert_one(event_dict)
        else:
            self.conn.execute(
                """INSERT INTO events
                   (timestamp,src_ip,dst_port,attack_type,severity,raw_payload,honeypot_source,detail)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (event_dict["timestamp"], event_dict["src_ip"], event_dict.get("dst_port"),
                 event_dict["attack_type"], event_dict["severity"], event_dict.get("raw_payload"),
                 event_dict["honeypot_source"], event_dict.get("detail")))
            self.conn.commit()

    # -- Week 3: behaviour persistence ------------------------------------
    def write_session_analysis(self, sa: dict):
        """Upsert one per-session behaviour verdict (dict from SessionAnalysis)."""
        if self._mode == "mongo":
            self.sessions_col.replace_one(
                {"session_id": sa["session_id"]}, sa, upsert=True)
        else:
            self.conn.execute(
                """INSERT INTO session_analysis
                   (session_id,src_ip,intent,intent_confidence,threat_score,band,ttps,analyzed_at)
                   VALUES (?,?,?,?,?,?,?,?)
                   ON CONFLICT(session_id) DO UPDATE SET
                     src_ip=excluded.src_ip, intent=excluded.intent,
                     intent_confidence=excluded.intent_confidence,
                     threat_score=excluded.threat_score, band=excluded.band,
                     ttps=excluded.ttps, analyzed_at=excluded.analyzed_at""",
                (sa["session_id"], sa["src_ip"], sa.get("intent"),
                 sa.get("intent_confidence"), sa.get("threat_score"), sa.get("band"),
                 json.dumps(sa.get("ttps", [])), sa.get("analyzed_at")))
            self.conn.commit()

    def upsert_profile(self, p: dict):
        """Upsert one attacker profile (dict from AttackerProfile.to_dict())."""
        if self._mode == "mongo":
            self.profiles_col.replace_one({"src_ip": p["src_ip"]}, p, upsert=True)
        else:
            self.conn.execute(
                """INSERT INTO profiles
                   (src_ip,first_seen,last_seen,session_count,classified_intent,
                    intent_confidence,ttps,threat_score,campaign_id)
                   VALUES (?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(src_ip) DO UPDATE SET
                     first_seen=excluded.first_seen, last_seen=excluded.last_seen,
                     session_count=excluded.session_count,
                     classified_intent=excluded.classified_intent,
                     intent_confidence=excluded.intent_confidence,
                     ttps=excluded.ttps, threat_score=excluded.threat_score,
                     campaign_id=excluded.campaign_id""",
                (p["src_ip"], p.get("first_seen"), p.get("last_seen"),
                 p.get("session_count"), p.get("classified_intent"),
                 p.get("intent_confidence"), json.dumps(p.get("ttps", [])),
                 p.get("threat_score"), p.get("campaign_id")))
            self.conn.commit()

    def get_profile(self, src_ip: str):
        """Return one profile dict or None."""
        if self._mode == "mongo":
            doc = self.profiles_col.find_one({"src_ip": src_ip}, {"_id": 0})
            return doc
        cur = self.conn.execute("SELECT * FROM profiles WHERE src_ip=?", (src_ip,))
        row = cur.fetchone()
        if not row:
            return None
        cols = [c[0] for c in cur.description]
        d = dict(zip(cols, row))
        d["ttps"] = json.loads(d.get("ttps") or "[]")
        return d

    def get_profiles(self):
        """Return all profile dicts."""
        if self._mode == "mongo":
            return list(self.profiles_col.find({}, {"_id": 0}))
        cur = self.conn.execute("SELECT * FROM profiles")
        cols = [c[0] for c in cur.description]
        out = []
        for row in cur.fetchall():
            d = dict(zip(cols, row))
            d["ttps"] = json.loads(d.get("ttps") or "[]")
            out.append(d)
        return out

    # -- Week 5: read queries for the API (live store) --------------------
    def get_events(self, limit: int = 100, since_id: int = None,
                   src_ip: str = None, attack_type: str = None,
                   severity: str = None):
        """Return recent events (newest first), optionally filtered.

        ``since_id`` returns only events with id > since_id (oldest first) — used
        by the live feed to stream new rows as the pipeline inserts them.
        """
        if self._mode == "mongo":
            q = {}
            if src_ip:
                q["src_ip"] = src_ip
            if attack_type:
                q["attack_type"] = attack_type
            if severity:
                q["severity"] = severity
            cur = self.col.find(q, {"_id": 0}).sort("timestamp", -1).limit(limit)
            return list(cur)
        clauses, params = [], []
        if since_id is not None:
            clauses.append("id > ?"); params.append(since_id)
        if src_ip:
            clauses.append("src_ip = ?"); params.append(src_ip)
        if attack_type:
            clauses.append("attack_type = ?"); params.append(attack_type)
        if severity:
            clauses.append("severity = ?"); params.append(severity)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        order = "ASC" if since_id is not None else "DESC"
        cur = self.conn.execute(
            f"SELECT * FROM events {where} ORDER BY id {order} LIMIT ?",
            (*params, limit))
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def latest_event_id(self) -> int:
        """Highest event id currently stored (0 if empty). sqlite only."""
        if self._mode == "mongo":
            return 0
        row = self.conn.execute("SELECT MAX(id) FROM events").fetchone()
        return row[0] or 0

    def get_stats(self) -> dict:
        """Aggregate counts for the dashboard (all from the live store)."""
        if self._mode == "mongo":
            total = self.col.count_documents({})
            by_type = {d["_id"]: d["count"] for d in self.col.aggregate([
                {"$group": {"_id": "$attack_type", "count": {"$sum": 1}}}])}
            by_sev = {d["_id"]: d["count"] for d in self.col.aggregate([
                {"$group": {"_id": "$severity", "count": {"$sum": 1}}}])}
            top = [{"src_ip": d["_id"], "count": d["count"]} for d in self.col.aggregate([
                {"$group": {"_id": "$src_ip", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}}, {"$limit": 10}])]
            profiles = self.profiles_col.count_documents({})
            responses = self.responses_col.count_documents({})
        else:
            total = self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            by_type = dict(self.conn.execute(
                "SELECT attack_type, COUNT(*) FROM events GROUP BY attack_type").fetchall())
            by_sev = dict(self.conn.execute(
                "SELECT severity, COUNT(*) FROM events GROUP BY severity").fetchall())
            top = [{"src_ip": ip, "count": c} for ip, c in self.conn.execute(
                "SELECT src_ip, COUNT(*) c FROM events GROUP BY src_ip "
                "ORDER BY c DESC LIMIT 10").fetchall()]
            profiles = self.conn.execute("SELECT COUNT(*) FROM profiles").fetchone()[0]
            responses = self.conn.execute("SELECT COUNT(*) FROM responses").fetchone()[0]
        return {
            "total_events": total,
            "by_attack_type": by_type,
            "by_severity": by_sev,
            "top_sources": top,
            "profiles": profiles,
            "responses": responses,
        }

    def get_attacker(self, src_ip: str) -> dict:
        """Full attacker view: profile + recent events + session verdicts."""
        profile = self.get_profile(src_ip)
        events = self.get_events(limit=50, src_ip=src_ip)
        if self._mode == "mongo":
            sessions = list(self.sessions_col.find({"src_ip": src_ip}, {"_id": 0}))
            responses = list(self.responses_col.find({"src_ip": src_ip}, {"_id": 0}))
        else:
            cur = self.conn.execute(
                "SELECT * FROM session_analysis WHERE src_ip=?", (src_ip,))
            cols = [c[0] for c in cur.description]
            sessions = [dict(zip(cols, r)) for r in cur.fetchall()]
            for s in sessions:
                s["ttps"] = json.loads(s.get("ttps") or "[]")
            cur = self.conn.execute(
                "SELECT * FROM responses WHERE src_ip=? ORDER BY id DESC", (src_ip,))
            cols = [c[0] for c in cur.description]
            responses = [dict(zip(cols, r)) for r in cur.fetchall()]
        return {"src_ip": src_ip, "profile": profile, "events": events,
                "sessions": sessions, "responses": responses}

    def write_response(self, r: dict):
        """Record one autonomous response action."""
        if self._mode == "mongo":
            self.responses_col.insert_one(dict(r))
        else:
            self.conn.execute(
                """INSERT INTO responses (ts,src_ip,action,threat_score,band,success,detail)
                   VALUES (?,?,?,?,?,?,?)""",
                (r["ts"], r["src_ip"], r["action"], r.get("threat_score"),
                 r.get("band"), 1 if r.get("success") else 0, r.get("detail")))
            self.conn.commit()

    def get_responses(self, limit: int = 100):
        """Recent response actions (newest first)."""
        if self._mode == "mongo":
            return list(self.responses_col.find({}, {"_id": 0})
                        .sort("ts", -1).limit(limit))
        cur = self.conn.execute(
            "SELECT * FROM responses ORDER BY id DESC LIMIT ?", (limit,))
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]
