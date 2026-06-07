"""CADN Week 4 — Deception Engine (Layer 4).

Generates dynamic, personalized honeypot environments tailored to each attacker
classified by the Week-3 Behavior Engine:

    DeceptionEngine.generate_environment(...) -> Environment

Pieces:
    personalization   — attacker class -> skill tier -> template
    templates_loader  — YAML environment templates (beginner/bot/advanced)
    credentials       — fake users, AWS keys, API keys, DB rows (Faker optional)
    filesystem_factory— believable fake filesystem (honeyfs)
    fake_server       — per-service decoy servers (Docker optional, dry-run safe)
    lifecycle         — deploy / monitor / auto-teardown
"""
from .engine import DeceptionEngine
from .lifecycle import Environment, LifecycleManager
from .fake_server import FakeServer, build_servers
from .credentials import CredentialGenerator, CredentialSet
from .filesystem_factory import FilesystemFactory
from .personalization import classify_skill_tier, select_template, SKILL_TIERS
from .templates_loader import load_template, available_templates

__all__ = [
    "DeceptionEngine", "Environment", "LifecycleManager",
    "FakeServer", "build_servers",
    "CredentialGenerator", "CredentialSet", "FilesystemFactory",
    "classify_skill_tier", "select_template", "SKILL_TIERS",
    "load_template", "available_templates",
]
