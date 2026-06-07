"""CADN Week 5 — Autonomous Response Engine (Layer 5, response half).

Consumes Week-3 verdicts and takes real protective action on the host:

    threat_score <40  -> log only
    40-70             -> slow + redirect to a deeper honeypot
    70-90             -> isolate session + alert
    >90               -> block IP + emergency alert + forensic (pcap) capture

Actions hit the real network stack (iptables / tc / tcpdump); alerts go out over
real email / Slack / Telegram. Every action is recorded to the live event store.
"""
from .engine import ResponseEngine, ResponseResult, decide
from .actions import ResponseActuator, CommandRunner, RecordingRunner
from .alerting import AlertManager, AlertRule

__all__ = [
    "ResponseEngine", "ResponseResult", "decide",
    "ResponseActuator", "CommandRunner", "RecordingRunner",
    "AlertManager", "AlertRule",
]
