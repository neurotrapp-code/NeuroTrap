# NeuroTrap / CADN — Weeks 3–4 Execution Manual
### Layer 3 (Behavior Analysis Engine) + Layer 4 (Deception Engine)

This manual covers the implementation delivered for **Week 3 (Days 15–21)** and
**Week 4 (Days 22–28)** of the project plan, how to run it, and the per-day
validation gates from the plan's deliverable tables.

> Builds directly on the Weeks 1–2 detection pipeline. Layer 3 consumes Cowrie
> sessions; Layer 4 consumes Layer 3's classifications.

---

## 0. Install

```bash
source .venv/bin/activate                      # the env from Weeks 1-2
pip install -r behavior/requirements.txt       # numpy, scikit-learn, joblib
pip install -r deception/requirements.txt      # PyYAML, Faker
# optional extras:
#   pip install sentence-transformers          # fuzzy TTP matching (Day 18)
#   pip install docker                          # real fake-server containers (Day 24)
```

Everything degrades gracefully: without sklearn the classifier uses heuristics,
without Faker credentials use bundled wordlists, without Docker fake servers run
in dry-run mode, without PyYAML the templates load from a built-in copy.

---

## Week 3 — Behavior Analysis Engine (Days 15–21)

### Module map (`behavior/`)
| File | Plan day | Responsibility |
|---|---|---|
| `features.py` | 15–16 | Session reconstruction + feature engineering (bag-of-commands + aggregates) |
| `synthetic.py` | 17 | Labeled synthetic sessions for training/testing |
| `classifier.py` | 17 | RandomForest/SVM intent classifier (+ heuristic fallback) |
| `train_model.py` | 17 | Train, evaluate (macro-F1), persist model |
| `mitre.py` + `ttp_extractor.py` | 18 | Command → MITRE ATT&CK technique mapping |
| `profiler.py` | 19–20 | `AttackerProfile` + DBSCAN campaign clustering |
| `threat_score.py` | — | Composite 0–100 threat score + response band |
| `engine.py` | 21 | `BehaviorEngine` integration + persistence |

### Day-by-day

**Days 15–16 — Feature engineering.** `parse_sessions()` groups raw Cowrie JSON by
`session` id into `Session` objects (commands, login activity, downloads, outbound
connects, duration). `vectorize()` produces a fixed-length vector: behavioural
aggregates (duration, login success, downloads, sensitive-file reads, chmod,
persistence, command cadence …) concatenated with a **bag-of-commands** count over
a fixed attacker-command vocabulary. `FEATURE_NAMES` documents every column.

**Day 17 — Classifier.** `python behavior/train_model.py` generates synthetic
labeled sessions, trains a RandomForest and an SVM, keeps the higher macro-F1, and
saves `behavior/models/intent_clf.joblib`. Six intents: Reconnaissance, Credential
Harvesting, Malware Deployment, Lateral Movement, Cryptomining, Bot Enrollment.

**Day 18 — TTP extraction.** `extract_ttps(commands)` maps commands to MITRE
ATT&CK technique IDs via the regex rules in `mitre.py`
(e.g. `wget`→T1105, `crontab`→T1053.003, `cat /etc/shadow`→T1003.008). Each TTP
carries a tactic, confidence and the matching evidence. With
`sentence-transformers` installed, `extract_ttps(..., fuzzy=True)` adds
lower-confidence embedding matches for unmatched commands.

**Days 19–20 — Profiling.** `Profiler.update()` folds each analysed session into a
per-`src_ip` `AttackerProfile` (first/last seen, dominant intent by confidence-
weighted vote, union of TTPs, peak threat score). `cluster_campaigns()` runs DBSCAN
over session vectors to group related sessions under a campaign id.

**Day 21 — Integration.** `BehaviorEngine.analyze_events(events)` runs the whole
chain and (with an `EventStore`) persists `session_analysis` + `profiles` rows.

### Usage
```python
from behavior import BehaviorEngine
eng = BehaviorEngine()                       # loads trained model if present
analyses = eng.analyze_events(cowrie_events) # list[SessionAnalysis]
a = analyses[0]
print(a.intent, a.intent_confidence, a.threat_score, a.band)
print([t.technique_id for t in a.ttps])
print(eng.profile(a.src_ip).to_dict())
```

### Week 3 deliverable gates (from the plan)
| Deliverable | How it's met |
|---|---|
| ML classifier trained & served | `train_model.py` → macro-F1 > 0.85; `IntentClassifier.predict()` |
| TTP extraction operational | `extract_ttps()` → MITRE technique IDs with evidence |
| Attacker profiles stored | `profiles` table; `EventStore.get_profile()` |
| MITRE ATT&CK mapping active | technique IDs + confidence on each session |
| Session clustering working | `Profiler.cluster_campaigns()` (DBSCAN) → campaign ids |

---

## Week 4 — Deception Engine (Days 22–28)

### Module map (`deception/`)
| File | Plan day | Responsibility |
|---|---|---|
| `engine.py` | 22–23 | `DeceptionEngine` core: generate / list / teardown |
| `templates/*.yaml` + `templates_loader.py` | 22–23 | Per-tier environment templates |
| `fake_server.py` | 24 | Per-service decoy servers (compose/Docker, dry-run safe) |
| `credentials.py` | 25 | Fake users/AWS keys/API keys/DB rows (Faker optional) |
| `filesystem_factory.py` | 25 | Believable fake filesystem (honeyfs) |
| `personalization.py` | 26 | Attacker class → skill tier → template |
| `lifecycle.py` | 27–28 | Deploy / monitor / health / auto-teardown |

### Day-by-day

**Days 22–23 — Engine core.** `DeceptionEngine.generate_environment(...)` →
`Environment`; `get_active_environments()`; `teardown(env_id)`. Templates are
YAML, one per attacker tier.

**Day 24 — Fake server generator.** `build_servers(template)` creates a
`FakeServer` per service with a randomized realistic hostname, OS banner and
service version. `to_compose_service()` renders a docker-compose fragment;
`start()/stop()` drive the Docker SDK when installed, else dry-run.

**Day 25 — Fake credentials & data.** `CredentialGenerator.generate_set()` makes
usernames, passwords (weak/common for bots), emails, AWS-style keys, API keys, a
private-key stub and seeded fake DB tables. `FilesystemFactory.build()` writes a
believable tree (`/etc/passwd`, `.bash_history`, `/opt/app/.env`, `wp-config.php`,
`~/.aws/credentials`, `id_rsa`, DB dumps) scaled to the template.

**Day 26 — Personalization.** `classify_skill_tier(intent, threat_score, n_ttps,
cmds_per_second)` → `beginner | bot | advanced`:
- **Beginner** → simple Linux server (recon/low score).
- **Bot** → hardened-looking server seeded with the common creds botnets spray
  (Bot Enrollment / Cryptomining, or relentless command cadence).
- **Advanced** → corporate server with fake sensitive data — canary AWS keys,
  `.env` secrets, private keys, fake customer/employee DB (Lateral Movement /
  Credential Harvesting / high threat / many TTPs).

**Days 27–28 — Lifecycle & testing.** `LifecycleManager` deploys servers, exposes
`health()`, and `tick()` auto-tears-down environments past their TTL or whose
session has closed (also deleting the fake filesystem).

### Usage
```python
from deception import DeceptionEngine
dec = DeceptionEngine(dry_run=True)                  # dry_run=False to launch containers
env = dec.generate_environment(src_ip="203.0.113.7",
                               intent="Credential Harvesting",
                               threat_score=85, n_ttps=5)
print(env.tier, [s.service for s in env.servers], sorted(env.manifest))
dec.tick()            # call periodically to reap expired environments
```

End-to-end from a Week-3 analysis:
```python
from deception import DeceptionEngine
env = DeceptionEngine.from_analysis(analysis, session=session)  # analysis from BehaviorEngine
```

### Week 4 deliverable gates (from the plan)
| Deliverable | How it's met |
|---|---|
| Deception Engine operational | spawns env in ≪ 30 s (`env.spawn_seconds`) |
| Fake server generator working | `FakeServer` per service, realistic banners, compose/Docker |
| Fake data populated | `.env`, AWS creds, DB dumps, private keys in the honeyfs |
| Personalization active | `classify_skill_tier()` → tier-specific template |
| Lifecycle management complete | `tick()` auto-teardown on TTL / session close |

---

## Validate everything
```bash
# train the model (Day 17 gate)
python behavior/train_model.py            # expect macro-F1 > 0.85

# unit + integration tests for Layers 3 and 4
python -m pytest tests/test_behavior.py tests/test_deception.py \
                 tests/test_integration_w3_w4.py -v
```

## What's next (Week 5)
`SessionAnalysis.band` is exactly the input the Week-5 autonomous response engine
thresholds on (`log / slow_redirect / isolate / block`), and `DeceptionEngine` is
what the response engine calls to redirect an attacker into a deeper honeypot.
