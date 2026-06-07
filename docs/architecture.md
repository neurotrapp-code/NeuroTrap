# CADN Architecture (Weeks 1-6 — complete)

CADN is organized into five logical layers. **All five are implemented.**

| Layer | Responsibility | Status |
|---|---|---|
| 1 — Capture | Cowrie (SSH/Telnet), Dionaea (multi-proto), Honeyd virtual hosts | Implemented (W1) |
| 2 — Detection | Scapy packet monitor, Zeek IDS, tool fingerprinting, unified alert schema, event DB | Implemented (W2) |
| 3 — Behavior Analysis | ML intent classifier, MITRE TTP extraction, profiling, campaign clustering, threat score | Implemented (W3) |
| 4 — Deception Engine | Personalized honeypot environment generator (templates, fake creds/fs/servers, lifecycle) | Implemented (W4) |
| 5 — Response & Viz | Autonomous response (iptables/tc/tcpdump), alerting, Flask API + JWT, real-time dashboard | Implemented (W5) |

Week 6 adds end-to-end testing, Nginx/Docker hardening, full docs, CI, and
one-command deployment. See the per-phase execution manuals
(`NeuroTrap_CADN_Weeks{1-2,3-4,5-6}_Execution_Manual.md`) and
`validation_checklist.md`.

## Networks
- `honeypot-net` (172.30.0.0/24): external-facing honeypots.
- `elk-net` (172.31.0.0/24): internal, no egress; event store.
- `management-net` (172.32.0.0/24): portal + enrichment.

Honeypot containers cannot reach the management/elk databases — isolation is verified on Day 2.

## Detection thresholds (tune on Day 14)
- Port scan: > 10 distinct dst ports / 5 s per src IP.
- Brute force: > 5 auth-port attempts / 60 s per src IP.
- Protocol anomaly: NULL / FIN / Xmas / SYN+FIN TCP flag combos.
- Automated-tool fingerprint: HTTP User-Agent / SSH client banner / payload markers
  (nmap, masscan, hydra, sqlmap, nikto, paramiko, libssh, mirai, …) → `automated_tool`.
- Target false-positive rate: < 5%.

See `network_diagram.md` for the lab topology, network isolation, and data flow.

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

## Layer 5 — Response & Visualization (Week 5)
`ResponseEngine` thresholds the threat score into actions executed against the real
host: `log` / `slow` (tc/iptables) / `redirect` (iptables DNAT + spawn deeper
deception) / `isolate` / `block` (iptables DROP) / `forensic_capture` (tcpdump),
plus email/Slack/Telegram alerting. The Flask API (`api/`) exposes JWT-protected
`/api/events|attackers|stats|responses|response/block` and a `/ws/live-feed`
WebSocket that tails the live event store; the dashboard (`dashboard/`) renders a
geo heatmap (real MaxMind GeoIP), live timeline, threat gauge and attacker profile
cards. All dashboard/API data is live — no demo source. `run_responder.py` ties
Cowrie → behaviour → response on live traffic.
