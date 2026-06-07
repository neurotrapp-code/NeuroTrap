"""Live event broadcaster for the dashboard WebSocket (Day 32-33).

A background thread polls the LIVE event store for newly-inserted rows (by
auto-increment id) and pushes each — geo-enriched — to every connected WebSocket
client. Because it tails the same table the pipeline writes to, the dashboard
reflects real traffic within ``poll_interval`` seconds; nothing is generated here.
"""
from __future__ import annotations

import json
import threading
import time
from functools import lru_cache
from typing import Set

from . import geoip


@lru_cache(maxsize=4096)
def _geo(ip: str):
    return geoip.locate(ip)


class LiveFeed:
    def __init__(self, store, poll_interval: float = 1.0):
        self.store = store
        self.poll_interval = poll_interval
        self._clients: Set = set()
        self._lock = threading.Lock()
        self._last_id = store.latest_event_id()
        self._thread = None
        self._stop = threading.Event()

    # -- client management -------------------------------------------------
    def register(self, ws):
        with self._lock:
            self._clients.add(ws)

    def unregister(self, ws):
        with self._lock:
            self._clients.discard(ws)

    def client_count(self) -> int:
        with self._lock:
            return len(self._clients)

    # -- pump --------------------------------------------------------------
    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _run(self):
        while not self._stop.is_set():
            try:
                self._tick()
            except Exception:
                pass
            time.sleep(self.poll_interval)

    def _tick(self):
        new = self.store.get_events(limit=200, since_id=self._last_id)
        if not new:
            return
        for ev in new:
            self._last_id = max(self._last_id, ev.get("id", self._last_id))
            ev["geo"] = _geo(ev.get("src_ip", ""))
            self.broadcast({"type": "event", "data": ev})

    def broadcast(self, message: dict):
        payload = json.dumps(message, default=str)
        dead = []
        with self._lock:
            clients = list(self._clients)
        for ws in clients:
            try:
                ws.send(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.unregister(ws)
