"""Event store for CADN. Backend chosen via DB_BACKEND env (sqlite|mongodb).

Holds three collections/tables:
  * events            — normalized detection alerts (Weeks 1-2)
  * session_analysis  — per-session behaviour verdicts (Week 3)
  * profiles          — aggregated attacker profiles    (Week 3)
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
