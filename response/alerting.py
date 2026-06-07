"""Day 34 — Alerting system (real email / Slack / Telegram + rule engine).

Channels are configured purely from environment variables; an unconfigured
channel is reported as ``skipped`` (never faked). Sends use stdlib only
(``smtplib`` + ``urllib``) so no extra runtime dependency is required.

Severity / score thresholds are expressed as :class:`AlertRule`s; ``notify()``
evaluates them against a verdict and fans out to the matching channels.
"""
from __future__ import annotations

import json
import os
import smtplib
import urllib.request
from dataclasses import dataclass, field
from email.mime.text import MIMEText
from typing import List, Optional

_SEV_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass
class AlertRule:
    name: str
    min_score: int = 0
    min_severity: str = "low"
    attack_types: Optional[List[str]] = None       # None = any
    channels: List[str] = field(default_factory=lambda: ["email", "slack", "telegram"])

    def matches(self, *, score: int, severity: str = "low",
                attack_type: str = None) -> bool:
        if score < self.min_score:
            return False
        if _SEV_ORDER.get(severity, 0) < _SEV_ORDER.get(self.min_severity, 0):
            return False
        if self.attack_types and attack_type not in self.attack_types:
            return False
        return True


# Default policy: alert on isolate-band (>=70) and emergency on block-band (>=90).
DEFAULT_RULES = [
    AlertRule("high-threat", min_score=70, channels=["email", "slack", "telegram"]),
]


class AlertManager:
    def __init__(self, rules: List[AlertRule] = None):
        self.rules = rules or DEFAULT_RULES
        # email
        self.smtp_host = os.environ.get("SMTP_HOST", "")
        self.smtp_port = int(os.environ.get("SMTP_PORT", "587"))
        self.smtp_user = os.environ.get("SMTP_USER", "")
        self.smtp_pass = os.environ.get("SMTP_PASS", "")
        self.alert_from = os.environ.get("ALERT_FROM", self.smtp_user)
        self.alert_to = [a for a in os.environ.get("ALERT_TO", "").split(",") if a]
        # slack / telegram
        self.slack_webhook = os.environ.get("SLACK_WEBHOOK", "")
        self.tg_token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
        self.tg_chat = os.environ.get("TELEGRAM_CHAT_ID", "")

    # -- channel status ----------------------------------------------------
    def configured_channels(self) -> List[str]:
        out = []
        if self.smtp_host and self.alert_to:
            out.append("email")
        if self.slack_webhook:
            out.append("slack")
        if self.tg_token and self.tg_chat:
            out.append("telegram")
        return out

    # -- senders -----------------------------------------------------------
    def send_email(self, subject: str, body: str) -> dict:
        if not (self.smtp_host and self.alert_to):
            return {"channel": "email", "status": "skipped", "reason": "not configured"}
        try:
            msg = MIMEText(body)
            msg["Subject"] = subject
            msg["From"] = self.alert_from
            msg["To"] = ", ".join(self.alert_to)
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10) as s:
                s.starttls()
                if self.smtp_user:
                    s.login(self.smtp_user, self.smtp_pass)
                s.sendmail(self.alert_from, self.alert_to, msg.as_string())
            return {"channel": "email", "status": "sent"}
        except Exception as e:                       # pragma: no cover - network
            return {"channel": "email", "status": "error", "reason": str(e)}

    def send_slack(self, text: str) -> dict:
        if not self.slack_webhook:
            return {"channel": "slack", "status": "skipped", "reason": "not configured"}
        return self._post_json(self.slack_webhook, {"text": text}, "slack")

    def send_telegram(self, text: str) -> dict:
        if not (self.tg_token and self.tg_chat):
            return {"channel": "telegram", "status": "skipped", "reason": "not configured"}
        url = f"https://api.telegram.org/bot{self.tg_token}/sendMessage"
        return self._post_json(url, {"chat_id": self.tg_chat, "text": text}, "telegram")

    def _post_json(self, url: str, payload: dict, channel: str) -> dict:
        try:
            data = json.dumps(payload).encode()
            req = urllib.request.Request(url, data=data,
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=10) as r:   # pragma: no cover
                return {"channel": channel, "status": "sent", "code": r.status}
        except Exception as e:                       # pragma: no cover - network
            return {"channel": channel, "status": "error", "reason": str(e)}

    # -- high level --------------------------------------------------------
    def send(self, subject: str, body: str, channels: List[str]) -> List[dict]:
        results = []
        for ch in channels:
            if ch == "email":
                results.append(self.send_email(subject, body))
            elif ch == "slack":
                results.append(self.send_slack(f"*{subject}*\n{body}"))
            elif ch == "telegram":
                results.append(self.send_telegram(f"{subject}\n{body}"))
        return results

    def notify(self, *, src_ip: str, score: int, severity: str = "high",
               attack_type: str = None, subject: str = None,
               body: str = None) -> List[dict]:
        """Evaluate rules for a verdict and dispatch to matching channels."""
        channels = set()
        for rule in self.rules:
            if rule.matches(score=score, severity=severity, attack_type=attack_type):
                channels.update(rule.channels)
        if not channels:
            return []
        subject = subject or f"[CADN] {severity.upper()} threat {score}/100 from {src_ip}"
        body = body or f"Attacker {src_ip} scored {score}/100 ({attack_type or 'n/a'})."
        # only attempt channels that are actually configured
        active = [c for c in channels if c in self.configured_channels()]
        skipped = [c for c in channels if c not in active]
        results = self.send(subject, body, active)
        for c in skipped:
            results.append({"channel": c, "status": "skipped", "reason": "not configured"})
        return results
