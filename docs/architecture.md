# CADN Architecture (Weeks 1-4 scope)

CADN is organized into five logical layers. **Weeks 1-4 implement Layers 1-4.**

| Layer | Responsibility | Status |
|---|---|---|
| 1 — Capture | Cowrie (SSH/Telnet), Dionaea (multi-proto), Honeyd virtual hosts | Implemented (W1) |
| 2 — Detection | Scapy packet monitor, Zeek IDS, unified alert schema, event DB | Implemented (W2) |
| 3 — Behavior Analysis | ML intent classifier, MITRE TTP extraction, profiling, campaign clustering, threat score | Implemented (W3) |
| 4 — Deception Engine | Personalized honeypot environment generator (templates, fake creds/fs/servers, lifecycle) | Implemented (W4) |
| 5 — Response & Viz | Autonomous response, Flask API, dashboard | Week 5 |

See `NeuroTrap_CADN_Weeks3-4_Execution_Manual.md` for the full Layer 3/4 design,
data flow, and per-day validation gates.

## Networks
- `honeypot-net` (172.30.0.0/24): external-facing honeypots.
- `elk-net` (172.31.0.0/24): internal, no egress; event store.
- `management-net` (172.32.0.0/24): portal + enrichment.

Honeypot containers cannot reach the management/elk databases — isolation is verified on Day 2.

## Detection thresholds (tune on Day 14)
- Port scan: > 10 distinct dst ports / 5 s per src IP.
- Brute force: > 5 auth-port attempts / 60 s per src IP.
- Protocol anomaly: NULL / FIN / Xmas / SYN+FIN TCP flag combos.
- Target false-positive rate: < 5%.

## Unified event schema
`{timestamp, src_ip, dst_port, attack_type, severity, raw_payload, honeypot_source}`
Stored in SQLite (default) or MongoDB, indexed on `src_ip`, `timestamp`, `attack_type`.

## Layer 3 — Behavior Analysis (Week 3)
Pipeline: `parse_sessions → vectorize → IntentClassifier → extract_ttps → score_session → Profiler`.
- **Intents:** Reconnaissance, Credential Harvesting, Malware Deployment, Lateral Movement, Cryptomining, Bot Enrollment. Trained RandomForest/SVM (`behavior/models/intent_clf.joblib`), macro-F1 > 0.85; rule-based fallback when no model/sklearn.
- **TTPs:** command → MITRE ATT&CK technique IDs (rule-based, optional embedding fuzzy match).
- **Threat score (0-100):** `0.40*intent + 0.35*ttp + 0.25*behavior`; bands `<40 log · 40-70 slow/redirect · 70-90 isolate · >90 block`.
- **Profiles & campaigns:** per-`src_ip` `AttackerProfile`; DBSCAN clusters sessions into campaigns.
- **Storage:** `session_analysis` and `profiles` tables/collections.

## Layer 4 — Deception Engine (Week 4)
`DeceptionEngine.generate_environment()` maps the attacker class → skill tier → YAML
template (`beginner|bot|advanced`), generates fake credentials/data (Faker optional),
builds a believable fake filesystem, instantiates per-service fake servers (Docker
optional; dry-run safe), and registers it with the lifecycle manager (deploy → monitor
→ auto-teardown on TTL or session close). Advanced environments seed canary AWS keys,
`.env` secrets, private keys and fake DB dumps. Spawns in ≪ 30 s.
