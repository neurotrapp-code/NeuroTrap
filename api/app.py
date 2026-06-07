"""Day 31 — Flask REST API + WebSocket, serving the live dashboard.

Endpoints (all data from the live event store):
    POST /api/auth/login            -> { token }
    GET  /api/health                (public)
    GET  /api/stats                 (auth)
    GET  /api/events                (auth)  ?limit&src_ip&attack_type&severity
    GET  /api/attackers/<ip>        (auth)
    GET  /api/responses             (auth)
    POST /api/response/block        (auth)  { "ip": "..." }
    WS   /ws/live-feed?token=...            live geo-enriched event stream
    GET  /                                  dashboard UI
"""
from __future__ import annotations

import os
import sys

from flask import (Flask, g, jsonify, request, send_from_directory)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "pipeline"))

from db import EventStore                                   # noqa: E402
from . import geoip                                         # noqa: E402
from .auth import (check_credentials, issue_token, require_auth, verify_token)  # noqa: E402
from .live import LiveFeed                                  # noqa: E402

DASHBOARD_DIR = os.path.join(ROOT, "dashboard")


def create_app(store=None, response_engine=None, start_feed: bool = True) -> Flask:
    app = Flask(__name__, static_folder=os.path.join(DASHBOARD_DIR, "static"),
                static_url_path="/static")
    store = store or EventStore()

    # response engine is optional (POST /api/response/block). Imported lazily so
    # the API can run without the response package present.
    if response_engine is None:
        try:
            from response import ResponseEngine
            response_engine = ResponseEngine(store=store)
        except Exception:
            response_engine = None

    feed = LiveFeed(store)
    if start_feed:
        feed.start()
    app.config["CADN_STORE"] = store
    app.config["CADN_FEED"] = feed

    # -- websocket (registered if flask-sock is available) ----------------
    try:
        from flask_sock import Sock
        sock = Sock(app)

        @sock.route("/ws/live-feed")
        def live_feed(ws):
            token = request.args.get("token", "")
            if not verify_token(token):
                ws.close()
                return
            feed.register(ws)
            try:
                while True:
                    if ws.receive(timeout=30) is None:
                        # keepalive ping; loop continues while client connected
                        pass
            except Exception:
                pass
            finally:
                feed.unregister(ws)
    except Exception:
        pass

    # -- auth --------------------------------------------------------------
    @app.post("/api/auth/login")
    def login():
        body = request.get_json(silent=True) or {}
        if not check_credentials(body.get("username"), body.get("password")):
            return jsonify({"error": "invalid credentials"}), 401
        return jsonify({"token": issue_token(body.get("username"))})

    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok", "geoip": geoip.available(),
                        "ws_clients": feed.client_count()})

    # -- read endpoints (live store) --------------------------------------
    @app.get("/api/stats")
    @require_auth
    def stats():
        return jsonify(store.get_stats())

    @app.get("/api/events")
    @require_auth
    def events():
        limit = min(int(request.args.get("limit", 100)), 1000)
        evs = store.get_events(
            limit=limit, src_ip=request.args.get("src_ip"),
            attack_type=request.args.get("attack_type"),
            severity=request.args.get("severity"))
        for e in evs:
            e["geo"] = geoip.locate(e.get("src_ip", ""))
        return jsonify({"count": len(evs), "events": evs})

    @app.get("/api/attackers/<ip>")
    @require_auth
    def attacker(ip):
        data = store.get_attacker(ip)
        data["geo"] = geoip.locate(ip)
        return jsonify(data)

    @app.get("/api/responses")
    @require_auth
    def responses():
        return jsonify({"responses": store.get_responses(
            limit=min(int(request.args.get("limit", 100)), 1000))})

    # -- action endpoint ---------------------------------------------------
    @app.post("/api/response/block")
    @require_auth
    def block():
        ip = (request.get_json(silent=True) or {}).get("ip")
        if not ip:
            return jsonify({"error": "ip required"}), 400
        if response_engine is None:
            return jsonify({"error": "response engine unavailable"}), 503
        outcome = response_engine.actuator.block(ip)
        response_engine._record(  # reuse the engine's recorder
            __import__("datetime").datetime.utcnow().isoformat(), ip, outcome, 100, "block")
        return jsonify({"action": "block", "ip": ip,
                        "success": outcome.success, "detail": outcome.detail})

    # -- dashboard ---------------------------------------------------------
    @app.get("/")
    def index():
        return send_from_directory(DASHBOARD_DIR, "index.html")

    return app


if __name__ == "__main__":
    application = create_app()
    port = int(os.environ.get("PORT", "8000"))
    application.run(host="0.0.0.0", port=port)
