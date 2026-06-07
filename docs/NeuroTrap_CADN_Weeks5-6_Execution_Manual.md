# NeuroTrap / CADN — Weeks 5–6 Execution Manual
### Layer 5 (Autonomous Response + Dashboard) and Project Hardening/Delivery

Covers **Week 5 (Days 29–35)** and **Week 6 (Days 36–42)**: how the response
engine, REST API, WebSocket dashboard and alerting work, plus hardening, testing,
CI, packaging and the v1.0.0 release.

> **Live data, not demo.** The API and dashboard read only from the live event
> store the pipeline fills from real honeypot/IDS traffic. Response actions hit the
> real `iptables`/`tc`/`tcpdump`; alerts use real SMTP/Slack/Telegram; the heatmap
> uses a real MaxMind GeoIP DB. There is no synthetic/sample data path in the
> product. (Unit tests inject test input through the *real* code paths — that is
> testing, not a demo data source.)

---

## Week 5 — Autonomous Response Engine & Dashboard (Days 29–35)

### Module map
| Component | File | Plan day |
|---|---|---|
| Decision matrix + orchestration | `response/engine.py` | 29–30 |
| Real actions (iptables/tc/tcpdump) | `response/actions.py` | 29–30 |
| Alerting (email/Slack/Telegram + rules) | `response/alerting.py` | 34 |
| Live responder daemon | `response/run_responder.py` | 35 |
| REST API + JWT + WebSocket | `api/app.py`, `api/auth.py`, `api/live.py` | 31 |
| Real GeoIP | `api/geoip.py` | 32–33 |
| Dashboard UI | `dashboard/` | 32–33 |
| DB read queries + responses table | `pipeline/db.py` | 31 |

### Decision matrix (Day 29–30)
| Threat score | Band | Actions |
|---|---|---|
| `< 40` | `log` | log only |
| `40–70` | `slow_redirect` | rate-limit (slow) + DNAT redirect to a deeper honeypot |
| `70–90` | `isolate` | drop forwarded/pivot traffic + alert |
| `> 90` | `block` | DROP source IP + emergency alert + tcpdump forensic capture |

On the redirect band the engine also calls the Week-4 Deception Engine to spawn a
deeper, personalized honeypot for that attacker.

### Running the live response loop
```bash
sudo .venv/bin/python response/run_responder.py     # root for iptables
```
It tails the real `cowrie.json`, analyses each session as it closes (Week 3),
persists the verdict, and acts. `make responder` is the shortcut.

### Running the dashboard/API
```bash
# dev:
ADMIN_PASS=... JWT_SECRET=$(python -c "import os;print(os.urandom(32).hex())") \
  .venv/bin/python -m api.app           # http://localhost:8000
# prod (behind Nginx TLS, Day 42):
make deploy                             # honeypots + portal + nginx
```
See `api-reference.md` for endpoints and `operator-manual.md` for day-to-day use.

### Alerting (Day 34)
Configure any subset of email / Slack / Telegram via `.env`. Unconfigured channels
are reported `skipped` — never silently treated as sent. Rules
(`response/alerting.py: AlertRule`) decide which scores/severities fan out to which
channels (default: alert at score ≥ 70).

---

## Week 6 — Testing, Hardening & Delivery (Days 36–42)

### Day 36–37 — End-to-end testing
`tests/test_e2e.py` drives a **5-stage campaign** (recon → brute-force → login+exec
→ malware download → lateral movement) through the *real* detectors, normalizer,
store, behaviour engine, response engine and API, and asserts the campaign is
visible across every layer. Run:
```bash
python -m pytest tests/test_e2e.py -v
```

### Day 38 — Security hardening
- **Nginx** (`deploy/nginx.conf`): TLS, HSTS, `X-Frame-Options`, `X-Content-Type-Options`,
  CSP, referrer/permissions policy, API rate-limiting, WebSocket upgrade.
- **Docker** (`deploy/docker-compose.portal.yml`, `docker-compose.yml`):
  `no-new-privileges`, `cap_drop`, read-only portal rootfs + tmpfs, portal/DB kept
  off `honeypot-net`.
- **Auth:** JWT (HS256) with constant-time credential check; password from env.
- **Lynis:** run `lynis audit system` on the host and resolve high-priority findings
  (target hardening index > 70).

### Day 39 — Documentation
`README.md`, `architecture.md`, `network_diagram.md`, `installation.md`,
`api-reference.md`, `operator-manual.md`, `ai-model.md`, and the three execution
manuals (Weeks 1-2, 3-4, 5-6).

### Day 40–41 — Demo & presentation
`scripts/demo_w3_w4.py` shows behaviour→deception; bring up `make deploy` and run a
campaign from the attacker VM (`scripts/simulate_attack.sh`) to show the dashboard
updating live, the attacker profile + MITRE mapping, and the automated response.

### Day 42 — Packaging & release
- **One-command deploy:** `make deploy` (honeypots + portal + Nginx).
- **CI:** `.github/workflows/ci.yml` installs deps, trains the model (F1 gate), runs
  the full test suite, and builds the portal image on every push/PR.
- **Release:** tag `v1.0.0` (`git tag -a v1.0.0 -m "..." && git push origin v1.0.0`).

### Week 5 & 6 deliverable gates
| Deliverable | How it's met |
|---|---|
| Response engine operational | `decide()` matrix + real actuator; acts in ms |
| REST API serving all endpoints | `/api/events|attackers|stats|responses|response/block` + JWT |
| Real-time dashboard live | WebSocket feed tails live DB inserts; map/timeline/gauge |
| Alerting configured | email/Slack/Telegram + rule engine (`response/alerting.py`) |
| Full pipeline integration | `tests/test_e2e.py` (5-stage campaign through live layers) |
| Security hardening | Nginx TLS/headers/rate-limit + Docker hardening + JWT |
| Complete documentation | this manual + the docs listed under Day 39 |
| One-command deploy | `make deploy` |
| CI | GitHub Actions (`.github/workflows/ci.yml`) |
```
```
