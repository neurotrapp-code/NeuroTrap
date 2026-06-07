"""Day 26 — Environment personalization.

Maps an attacker's Week-3 classification onto a skill tier and therefore an
environment template:

    Beginner -> simple Linux server          (templates/beginner.yaml)
    Bot      -> hardened-looking, common creds(templates/bot.yaml)
    Advanced -> corporate env, fake secrets   (templates/advanced.yaml)

The decision blends the classified *intent*, the *threat score*, the breadth of
*TTPs*, and (when available) the session's command cadence (bots fire many
commands per second; humans pause).
"""
from __future__ import annotations

from typing import Optional

SKILL_TIERS = ("beginner", "bot", "advanced")

# Intent -> the tier it most strongly implies.
_ADVANCED_INTENTS = {"Lateral Movement", "Credential Harvesting"}
_BOT_INTENTS = {"Bot Enrollment", "Cryptomining"}


def classify_skill_tier(intent: str, threat_score: int = 0, n_ttps: int = 0,
                        cmds_per_second: Optional[float] = None) -> str:
    """Return one of ``SKILL_TIERS`` for the given classification signals."""
    # Strong automation signal overrides intent: relentless command cadence = bot.
    if cmds_per_second is not None and cmds_per_second >= 2.0:
        return "bot"

    if intent in _ADVANCED_INTENTS:
        return "advanced"
    if threat_score >= 75 or n_ttps >= 5:
        return "advanced"
    if intent in _BOT_INTENTS:
        return "bot"
    if intent == "Malware Deployment":
        return "advanced" if threat_score >= 70 else "bot"
    # Reconnaissance / unknown -> beginner unless it already looks dangerous.
    return "beginner"


def select_template(intent: str, threat_score: int = 0, n_ttps: int = 0,
                    cmds_per_second: Optional[float] = None) -> str:
    """Template name to load for these signals (same as the tier name)."""
    return classify_skill_tier(intent, threat_score, n_ttps, cmds_per_second)


def tier_for_analysis(analysis, session=None) -> str:
    """Convenience: derive the tier from a :class:`SessionAnalysis` (+ optional
    :class:`Session` for command cadence)."""
    cps = None
    if session is not None and getattr(session, "duration_s", 0):
        n = len(session.base_commands())
        cps = n / session.duration_s if session.duration_s > 0 else None
    return classify_skill_tier(
        intent=getattr(analysis, "intent", "Reconnaissance"),
        threat_score=getattr(analysis, "threat_score", 0),
        n_ttps=len(getattr(analysis, "ttps", [])),
        cmds_per_second=cps,
    )
