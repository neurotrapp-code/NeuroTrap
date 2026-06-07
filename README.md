# NeuroTrap — CADN (Cognitive Adaptive Deception Network)
### Complete implementation (Weeks 1–6, all 5 layers)

This repository is the full NeuroTrap/CADN graduation project: live honeypots
(Cowrie, Dionaea, Honeyd), a Scapy + Zeek detection layer with a unified alert
schema and indexed event store (Weeks 1–2), an ML **behavior analysis engine**
(intent classification, MITRE ATT&CK TTPs, threat scoring, campaign clustering —
Week 3), a **deception engine** that spawns personalized honeypots per attacker
(Week 4), and an **autonomous response engine + real-time dashboard** (firewall
actions, alerting, JWT API, WebSocket live feed, GeoIP heatmap — Week 5), all
hardened, documented, CI-tested and one-command deployable (Week 6).

> **Live data, not demo:** the dashboard/API read only the live event store the
> pipeline fills from real traffic; responses hit the real firewall; the heatmap
> uses a real GeoIP DB. See `docs/NeuroTrap_CADN_Weeks5-6_Execution_Manual.md`.

> **This is a security lab, not a one-click web app.** It needs an Ubuntu 22.04 host,
> Docker, host SSH moved off port 22, Zeek/Honeyd installed on the host, and a **separate
> attacker VM** to generate test traffic. Follow the full step-by-step in
> `docs/NeuroTrap_CADN_Weeks1-2_Execution_Manual.md`.

## Layout
```
docker-compose.yml      Cowrie + Dionaea (+ optional Mongo), 3 isolated networks
.env.example            copy to .env and edit
honeypots/              Cowrie cfg + userdb + fake filesystem; Dionaea + Honeyd configs
detection/              Scapy monitor + detectors (port-scan/brute-force/anomaly/tool-fingerprint) + AlertEvent schema
pipeline/               collectors, normalizer, indexed SQLite/Mongo event store
behavior/               Week 3: feature eng, intent classifier, TTP/MITRE, profiler, threat score
deception/              Week 4: deception engine, env templates, fake creds/fs/servers, lifecycle
response/               Week 5: response engine (iptables/tc/tcpdump), alerting, live responder
api/                    Week 5: Flask REST API + JWT + WebSocket + GeoIP (serves live store)
dashboard/              Week 5: real-time console (Chart.js timeline, Leaflet heatmap, gauge)
deploy/                 Week 6: Nginx (TLS/headers), portal Dockerfile, hardened compose overlay
zeek/local.zeek         Zeek JSON logging policy
scripts/                host bootstrap, attack simulation, FP measurement, demo
tests/                  unit + integration + e2e tests (run: pytest)
docs/                   architecture, network diagram, 3 execution manuals, api/operator/install/model docs
.github/workflows/      CI (train model + run tests + build portal image)
```

## Weeks 5–6 (Response, Dashboard, Delivery)
```bash
pip install -r api/requirements.txt
export ADMIN_PASS=... JWT_SECRET=$(python -c "import os;print(os.urandom(32).hex())")
python -m api.app                      # dashboard at http://localhost:8000
sudo python response/run_responder.py  # live behaviour + autonomous response (host)
make deploy                            # one-command full stack (honeypots + portal + nginx)
```

## Weeks 3–4 (Behavior Analysis + Deception)
See `docs/NeuroTrap_CADN_Weeks3-4_Execution_Manual.md`. Quick start:
```bash
pip install -r behavior/requirements.txt -r deception/requirements.txt
python behavior/train_model.py          # train intent classifier (macro-F1 > 0.85)
pytest tests/test_behavior.py tests/test_deception.py tests/test_integration_w3_w4.py -v
```
```python
from behavior import BehaviorEngine
from deception import DeceptionEngine
analyses = BehaviorEngine().analyze_events(cowrie_events)   # classify + TTPs + score
env = DeceptionEngine.from_analysis(analyses[0])            # spawn tailored honeypot
```

## Quick start (on the Ubuntu 22.04 honeypot host)

1. **Read the manual first** — `docs/NeuroTrap_CADN_Weeks1-2_Execution_Manual.md`.
   It explains hardening, moving SSH to port 2222, and the per-day validation gates.

2. **Bootstrap the host** (review the script before running):
   ```bash
   ./scripts/setup_host.sh
   ```
   Then manually move management SSH to port 2222 (see Day 1 in the manual) so Cowrie
   can own port 22.

3. **Install Docker** (official repo — see Day 2 in the manual), then:
   ```bash
   cp .env.example .env          # edit secrets
   # Cowrie needs its full config; generate from the image then keep our overrides:
   docker run --rm cowrie/cowrie:latest cat /cowrie/cowrie-git/etc/cowrie.cfg.dist \
       > honeypots/cowrie/etc/cowrie.cfg.dist   # reference only
   sudo chown -R 999:999 honeypots/cowrie/var
   docker compose up -d
   docker compose ps
   ```

4. **Python detection environment:**
   ```bash
   python3 -m venv .venv && source .venv/bin/activate
   pip install -r detection/requirements.txt
   pytest tests/ -v               # should be all green
   ```

5. **Run the detection stack** (3 terminals):
   ```bash
   # 1) Scapy monitor (root for raw sockets)
   sudo .venv/bin/python detection/packet_monitor.py -i eth0
   # 2) Log pipeline -> indexed SQLite at data/cadn.sqlite
   source .venv/bin/activate && python pipeline/run_pipeline.py
   # 3) Zeek (install per manual Day 13)
   sudo /opt/zeek/bin/zeek -i eth0 zeek/local.zeek
   ```

6. **Generate attacks from the ATTACKER VM** and watch events land:
   ```bash
   ./scripts/simulate_attack.sh <HONEYPOT_HOST_IP>
   sqlite3 data/cadn.sqlite "SELECT attack_type,honeypot_source,COUNT(*) FROM events GROUP BY 1,2;"
   python scripts/measure_fp.py        # false-positive rate (<5% target)
   ```

## Database backend
Default is SQLite (`data/cadn.sqlite`). For MongoDB:
```bash
export DB_BACKEND=mongodb
export MONGO_URI="mongodb://cadn:<pass>@localhost:27017/cadn?authSource=admin"
docker compose --profile mongo up -d mongo
```

## Safety
Run only in an isolated lab. You deliberately attract/run attacker traffic — never on a
machine you care about, and generate the test traffic yourself from a controlled VM.

## What's verified out of the box
`pytest tests/` passes (schema validation, port-scan + brute-force detectors, all three
normalizers). The honeypots/Zeek require the host environment described in the manual.
