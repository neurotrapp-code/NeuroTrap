"""Days 27-28 — Environment lifecycle management.

Tracks every spawned deception :class:`Environment`, exposes health, and reaps
environments whose TTL has elapsed or whose attacker session has ended (deploy ->
monitor -> tear down). ``tick()`` is called periodically (e.g. by the Week-5
scheduler) to auto-teardown expired environments.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from .credentials import CredentialSet
from .fake_server import FakeServer


@dataclass
class Environment:
    env_id: str
    src_ip: str
    tier: str
    template_name: str
    created_at: float
    ttl_seconds: int
    servers: List[FakeServer] = field(default_factory=list)
    credentials: Optional[CredentialSet] = None
    filesystem_path: str = ""
    manifest: Dict[str, str] = field(default_factory=dict)
    status: str = "deploying"          # deploying|active|expired|torndown
    session_open: bool = True

    @property
    def expires_at(self) -> float:
        return self.created_at + self.ttl_seconds

    def remaining(self, now: Optional[float] = None) -> float:
        return max(0.0, self.expires_at - (now or time.time()))

    def to_dict(self) -> dict:
        return {
            "env_id": self.env_id,
            "src_ip": self.src_ip,
            "tier": self.tier,
            "template": self.template_name,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "remaining_s": round(self.remaining(), 1),
            "status": self.status,
            "servers": [s.to_dict() for s in self.servers],
            "filesystem_path": self.filesystem_path,
            "files": sorted(self.manifest.keys()),
        }


class LifecycleManager:
    def __init__(self, dry_run: bool = True,
                 teardown_fs: Optional[Callable[[Environment], None]] = None):
        self.dry_run = dry_run
        self._teardown_fs = teardown_fs
        self.environments: Dict[str, Environment] = {}

    def register(self, env: Environment) -> Environment:
        for s in env.servers:
            s.start(dry_run=self.dry_run)
        env.status = "active"
        self.environments[env.env_id] = env
        return env

    def get(self, env_id: str) -> Optional[Environment]:
        return self.environments.get(env_id)

    def active(self) -> List[Environment]:
        return [e for e in self.environments.values() if e.status == "active"]

    def health(self, env_id: str) -> dict:
        env = self.environments.get(env_id)
        if not env:
            return {"env_id": env_id, "exists": False}
        running = sum(1 for s in env.servers if s.status == "running")
        return {
            "env_id": env_id,
            "exists": True,
            "status": env.status,
            "remaining_s": round(env.remaining(), 1),
            "servers_running": running,
            "servers_total": len(env.servers),
            "healthy": env.status == "active" and running == len(env.servers),
        }

    def mark_session_closed(self, env_id: str):
        env = self.environments.get(env_id)
        if env:
            env.session_open = False

    def teardown(self, env_id: str) -> bool:
        env = self.environments.get(env_id)
        if not env:
            return False
        for s in env.servers:
            s.stop(dry_run=self.dry_run)
        if self._teardown_fs:
            try:
                self._teardown_fs(env)
            except Exception:
                pass
        env.status = "torndown"
        return True

    def tick(self, now: Optional[float] = None, reap_closed: bool = True) -> List[str]:
        """Tear down expired (and optionally session-closed) environments.

        Returns the list of env_ids that were reaped.
        """
        now = now or time.time()
        reaped: List[str] = []
        for env_id, env in list(self.environments.items()):
            if env.status != "active":
                continue
            expired = env.remaining(now) <= 0
            closed = reap_closed and not env.session_open
            if expired or closed:
                env.status = "expired"
                self.teardown(env_id)
                reaped.append(env_id)
        return reaped
