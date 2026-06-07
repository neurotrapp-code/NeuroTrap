"""Days 29-30 — Autonomous response decision engine.

Maps a live threat score onto concrete actions and executes them via the
:class:`ResponseActuator`, records each to the live store, fires alerts, and (on
the redirect band) asks the Week-4 Deception Engine to spin up a deeper honeypot.

Decision matrix (from the plan):
    score < 40   -> log only
    40 - 70      -> slow + redirect to deeper honeypot
    70 - 90      -> isolate session + alert
    > 90         -> block IP + emergency alert + forensic capture
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

from .actions import ActionOutcome, ResponseActuator
from .alerting import AlertManager


def decide(score: int) -> List[str]:
    """Return the ordered list of action names for a threat score."""
    if score < 40:
        return ["log"]
    if score < 70:
        return ["slow", "redirect"]
    if score < 90:
        return ["isolate", "alert"]
    return ["block", "alert", "forensic_capture"]


@dataclass
class ResponseResult:
    src_ip: str
    threat_score: int
    band: str
    actions: List[str]
    outcomes: List[dict] = field(default_factory=list)
    alerts: List[dict] = field(default_factory=list)
    deception_env_id: Optional[str] = None
    ts: str = ""

    def to_dict(self) -> dict:
        return {
            "src_ip": self.src_ip, "threat_score": self.threat_score,
            "band": self.band, "actions": self.actions, "outcomes": self.outcomes,
            "alerts": self.alerts, "deception_env_id": self.deception_env_id,
            "ts": self.ts,
        }


_BAND = {"log": "log", "slow": "slow_redirect", "redirect": "slow_redirect",
         "isolate": "isolate", "alert": "isolate", "block": "block",
         "forensic_capture": "block"}


class ResponseEngine:
    def __init__(self, actuator: ResponseActuator = None,
                 alerter: AlertManager = None, store=None,
                 deception_engine=None):
        self.actuator = actuator or ResponseActuator()
        self.alerter = alerter or AlertManager()
        self.store = store
        self.deception = deception_engine

    def respond(self, *, src_ip: str, threat_score: int, severity: str = "high",
                intent: str = None, band: str = None,
                cmds_per_second: float = None, n_ttps: int = 0) -> ResponseResult:
        """Execute the response policy for one live verdict."""
        actions = decide(threat_score)
        band = band or _score_band(threat_score)
        now = datetime.now(timezone.utc).isoformat()
        result = ResponseResult(src_ip=src_ip, threat_score=threat_score,
                                band=band, actions=actions, ts=now)

        for action in actions:
            outcome = self._do(action, src_ip, threat_score, intent, n_ttps,
                               cmds_per_second, result)
            if outcome is not None:
                result.outcomes.append(outcome.__dict__ if isinstance(outcome, ActionOutcome)
                                       else outcome)
                self._record(now, src_ip, outcome, threat_score, band)
        return result

    # -- per-action dispatch ----------------------------------------------
    def _do(self, action, ip, score, intent, n_ttps, cps, result):
        if action == "log":
            return ActionOutcome("log", True, f"logged threat {score} from {ip}")
        if action == "slow":
            return self.actuator.slow(ip)
        if action == "redirect":
            env_id = self._spawn_deeper_honeypot(ip, intent, score, n_ttps, cps)
            result.deception_env_id = env_id
            oc = self.actuator.redirect(ip)
            if env_id:
                oc.detail += f" | deeper honeypot env={env_id}"
            return oc
        if action == "isolate":
            return self.actuator.isolate(ip)
        if action == "block":
            return self.actuator.block(ip)
        if action == "forensic_capture":
            return self.actuator.forensic_capture(ip)
        if action == "alert":
            res = self.alerter.notify(src_ip=ip, score=score, severity="high",
                                      attack_type=intent)
            result.alerts.extend(res)
            sent = sum(1 for r in res if r.get("status") == "sent")
            return ActionOutcome("alert", True, f"{sent}/{len(res)} channels sent")
        return None

    def _spawn_deeper_honeypot(self, ip, intent, score, n_ttps, cps):
        if self.deception is None:
            return None
        try:
            env = self.deception.generate_environment(
                src_ip=ip, intent=intent or "Reconnaissance",
                threat_score=score, n_ttps=n_ttps, cmds_per_second=cps)
            return env.env_id
        except Exception:
            return None

    def _record(self, ts, ip, outcome: ActionOutcome, score, band):
        if self.store is None:
            return
        self.store.write_response({
            "ts": ts, "src_ip": ip, "action": outcome.action,
            "threat_score": score, "band": band,
            "success": outcome.success, "detail": outcome.detail,
        })


def _score_band(score: int) -> str:
    if score < 40:
        return "log"
    if score < 70:
        return "slow_redirect"
    if score < 90:
        return "isolate"
    return "block"
