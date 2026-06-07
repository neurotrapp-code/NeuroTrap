"""Days 22-23 — Deception Engine core (the project's central innovation).

`DeceptionEngine` ingests a Week-3 attacker classification and spawns a tailored,
fully-monitored honeypot environment:

    profile/analysis -> pick skill tier (personalization)
                     -> load YAML template
                     -> generate fake credentials & data
                     -> build a believable fake filesystem
                     -> instantiate fake servers
                     -> register + deploy via the lifecycle manager

Public API mirrors the plan (Day 22-23):
    generate_environment(attacker_profile)  -> Environment
    get_active_environments()               -> list[Environment]
    teardown(env_id)                        -> bool

Designed to spawn in well under the 30-second target (it is effectively instant
in dry-run; real container starts dominate when Docker is enabled).
"""
from __future__ import annotations

import os
import shutil
import time
import uuid
from typing import List, Optional

from .credentials import CredentialGenerator
from .fake_server import build_servers
from .filesystem_factory import FilesystemFactory
from .lifecycle import Environment, LifecycleManager
from .personalization import classify_skill_tier
from .templates_loader import load_template

DEFAULT_WORKDIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "deception")


class DeceptionEngine:
    def __init__(self, workdir: str = DEFAULT_WORKDIR, dry_run: bool = True,
                 seed: Optional[int] = None):
        self.workdir = workdir
        self.dry_run = dry_run
        self.seed = seed
        self.fs_factory = FilesystemFactory()
        self.lifecycle = LifecycleManager(dry_run=dry_run, teardown_fs=self._rm_fs)
        os.makedirs(workdir, exist_ok=True)

    # -- main entry point --------------------------------------------------
    def generate_environment(self, *, src_ip: str, intent: str = "Reconnaissance",
                             threat_score: int = 0, n_ttps: int = 0,
                             cmds_per_second: Optional[float] = None,
                             tier: Optional[str] = None) -> Environment:
        """Spawn a personalized environment for one attacker.

        Pass an explicit ``tier`` to override personalization, or supply the
        Week-3 signals (``intent``/``threat_score``/``n_ttps``/``cmds_per_second``)
        and let :func:`classify_skill_tier` decide.
        """
        t0 = time.time()
        tier = tier or classify_skill_tier(intent, threat_score, n_ttps, cmds_per_second)
        template = load_template(tier)

        env_id = uuid.uuid4().hex
        dec = template.get("decoy_data", {})
        cprof = template.get("credential_profile", {})

        creds = CredentialGenerator(seed=self.seed).generate_set(
            count=cprof.get("count", 3),
            weak=cprof.get("weak", False),
            common=cprof.get("common", False),
            aws=dec.get("aws_keys", False),
            fake_db=dec.get("fake_db", False),
            private_keys=dec.get("private_ssh_keys", False),
        )

        fs_path = os.path.join(self.workdir, env_id, "honeyfs")
        manifest = self.fs_factory.build(template, creds, fs_path)
        servers = build_servers(template, env_id, seed=self.seed)

        env = Environment(
            env_id=env_id,
            src_ip=src_ip,
            tier=tier,
            template_name=template.get("name", tier),
            created_at=time.time(),
            ttl_seconds=int(template.get("ttl_seconds", 1800)),
            servers=servers,
            credentials=creds,
            filesystem_path=fs_path,
            manifest=manifest,
        )
        self.lifecycle.register(env)
        env.spawn_seconds = round(time.time() - t0, 3)   # observability
        return env

    @classmethod
    def from_analysis(cls, analysis, session=None, **kwargs):
        """Helper: build the engine call args from a Week-3 SessionAnalysis."""
        cps = None
        if session is not None and getattr(session, "duration_s", 0):
            n = len(session.base_commands())
            cps = n / session.duration_s if session.duration_s > 0 else None
        engine = kwargs.pop("engine", None) or cls(**kwargs)
        return engine.generate_environment(
            src_ip=analysis.src_ip, intent=analysis.intent,
            threat_score=analysis.threat_score,
            n_ttps=len(getattr(analysis, "ttps", [])), cmds_per_second=cps)

    # -- lifecycle passthroughs -------------------------------------------
    def get_active_environments(self) -> List[Environment]:
        return self.lifecycle.active()

    def get(self, env_id: str) -> Optional[Environment]:
        return self.lifecycle.get(env_id)

    def health(self, env_id: str) -> dict:
        return self.lifecycle.health(env_id)

    def teardown(self, env_id: str) -> bool:
        return self.lifecycle.teardown(env_id)

    def tick(self, now: Optional[float] = None) -> List[str]:
        return self.lifecycle.tick(now=now)

    # -- internals ---------------------------------------------------------
    def _rm_fs(self, env: Environment):
        envdir = os.path.join(self.workdir, env.env_id)
        if os.path.isdir(envdir):
            shutil.rmtree(envdir, ignore_errors=True)
