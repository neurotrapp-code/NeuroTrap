# CADN Deliverable Validation Checklist (Weeks 1–6)

Status legend: ✅ verified here (code/tests) · 🧪 verified by automated test ·
🖥️ requires the Ubuntu lab host to validate at runtime.

## Week 1 — Infrastructure & Honeypots
| Deliverable | Check | Status |
|---|---|---|
| Docker Compose stack | `docker compose config` valid; `make up`; `docker compose ps` | 🖥️ |
| 3 isolated networks | `docker-compose.yml` (honeypot/elk/management); elk `internal` | ✅ |
| Cowrie captures SSH | login from attacker VM → `cowrie.json` | 🖥️ |
| Dionaea captures malware | SMB/HTTP probe → `dionaea.json` | 🖥️ |
| Network isolation | DB off `honeypot-net`; `network_diagram.md` | ✅ |
| Git repo + .gitignore | `git log`; secrets ignored | ✅ |

## Week 2 — Detection
| Deliverable | Check | Status |
|---|---|---|
| Packet monitor (<5s) | `detection/packet_monitor.py`; detector tests | 🧪 |
| Port-scan/brute-force/anomaly | `tests/test_detectors.py` | 🧪 |
| Automated-tool fingerprint | `tests/test_tool_fingerprint.py` | 🧪 |
| Unified event schema | `tests/test_detectors.py` (AlertEvent validation) | 🧪 |
| Event DB populated + indexed | `pipeline/db.py`; `tests/test_normalizer.py` | 🧪 |
| Zeek conn/http/ssh/dns ingest | `from_zeek_*` + `run_pipeline.py` | 🧪/🖥️ |
| FP < 5% | `scripts/measure_fp.py` on real traffic | 🖥️ |

## Week 3 — Behavior Analysis
| Deliverable | Check | Status |
|---|---|---|
| Classifier macro-F1 > 0.85 | `python behavior/train_model.py` | 🧪 |
| TTP → MITRE mapping | `tests/test_behavior.py` | 🧪 |
| Attacker profiles stored | `tests/test_integration_w3_w4.py` | 🧪 |
| Session clustering (campaigns) | `Profiler.cluster_campaigns` | 🧪 |

## Week 4 — Deception
| Deliverable | Check | Status |
|---|---|---|
| Env spawns < 30s | `tests/test_deception.py` (`spawn_seconds`) | 🧪 |
| Fake servers/creds/fs | `tests/test_deception.py` | 🧪 |
| Personalization by tier | `tests/test_deception.py` | 🧪 |
| Lifecycle auto-teardown | `tests/test_deception.py` | 🧪 |

## Week 5 — Response & Dashboard
| Deliverable | Check | Status |
|---|---|---|
| Response decision matrix | `tests/test_response.py` | 🧪 |
| Real actions (iptables/tc/tcpdump) | command-build tests; runtime on host | 🧪/🖥️ |
| REST API + JWT | `tests/test_api.py` | 🧪 |
| WebSocket live feed | `tests/test_api.py` (live tail) | 🧪 |
| Real GeoIP heatmap | needs `GeoLite2-City.mmdb` | 🖥️ |
| Alerting (email/Slack/Telegram) | `tests/test_response.py` (rules/skip); real send | 🧪/🖥️ |
| Full pipeline integration | `tests/test_e2e.py` | 🧪 |

## Week 6 — Hardening & Delivery
| Deliverable | Check | Status |
|---|---|---|
| E2E 5-stage campaign | `tests/test_e2e.py` | 🧪 |
| Nginx TLS/headers/rate-limit | `deploy/nginx.conf`; live curl headers | ✅/🖥️ |
| Docker hardening | `no-new-privileges`, `cap_drop`, read-only portal | ✅ |
| Lynis index > 70 | `lynis audit system` on host | 🖥️ |
| Documentation | this `docs/` set | ✅ |
| GitHub Actions CI | `.github/workflows/ci.yml` | ✅ |
| One-command deploy | `make deploy` on host | 🖥️ |
| v1.0.0 release | `git tag v1.0.0` | ✅ |

## Run all automated checks
```bash
python behavior/train_model.py        # F1 gate
python -m pytest tests/ -v            # full suite (all 🧪 items)
```
The 🖥️ items are runtime validations that need the Ubuntu lab host with Docker,
Zeek, a GeoIP DB, and a separate attacker VM — they are environment-dependent, not
missing code.
