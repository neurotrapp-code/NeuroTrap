#!/usr/bin/env python3
"""Day 35 — Live responder daemon (ties Weeks 1-5 together).

Tails the **real** Cowrie JSON log, reconstructs each session as it closes, runs
the Week-3 behaviour engine on it, persists the verdict, and lets the Week-5
response engine act — blocking / redirecting / isolating / alerting on live
attacker traffic. Nothing here is simulated: input is the live honeypot log,
output is real firewall actions + DB rows the dashboard reads.

    sudo .venv/bin/python response/run_responder.py        # root for iptables

Env overrides: COWRIE_LOG, RESPONDER_FROM_START=1 (replay existing log).
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "pipeline"))

from collectors.cowrie_collector import tail_json          # noqa: E402
from db import EventStore                                   # noqa: E402
from behavior import BehaviorEngine                         # noqa: E402
from behavior.features import parse_sessions                # noqa: E402
from deception import DeceptionEngine                       # noqa: E402
from response import ResponseEngine                         # noqa: E402

COWRIE = os.environ.get(
    "COWRIE_LOG", os.path.join(ROOT, "honeypots/cowrie/var/log/cowrie/cowrie.json"))
FROM_START = os.environ.get("RESPONDER_FROM_START") == "1"


def main():
    store = EventStore()
    behavior = BehaviorEngine(store=store)
    deception = DeceptionEngine(dry_run=False)               # real environments
    responder = ResponseEngine(store=store, deception_engine=deception)

    if not responder.actuator.available():
        print("[!] iptables not available here — response actions will report "
              "failure. Run on the Ubuntu honeypot host as root for live blocking.",
              flush=True)

    print(f"[*] responder watching {COWRIE} (from_start={FROM_START})", flush=True)
    buffers = {}            # session_id -> list[event]
    for ev in tail_json(COWRIE, from_start=FROM_START):
        sid = ev.get("session") or ev.get("src_ip")
        if not sid:
            continue
        buffers.setdefault(sid, []).append(ev)
        if ev.get("eventid") != "cowrie.session.closed":
            continue

        # session finished -> analyse the real session and respond
        events = buffers.pop(sid, [])
        session = parse_sessions(events).get(sid)
        if session is None:
            continue
        analysis = behavior.analyze_session(session, persist=True)
        cps = (len(session.base_commands()) / session.duration_s
               if session.duration_s > 0 else None)
        result = responder.respond(
            src_ip=analysis.src_ip, threat_score=analysis.threat_score,
            intent=analysis.intent, band=analysis.band,
            n_ttps=len(analysis.ttps), cmds_per_second=cps)
        print(f"[{analysis.src_ip}] {analysis.intent} score={analysis.threat_score} "
              f"-> {result.actions}", flush=True)


if __name__ == "__main__":
    main()
