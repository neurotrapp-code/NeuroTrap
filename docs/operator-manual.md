# CADN Operator Manual

Day-to-day operation of a running NeuroTrap/CADN deployment.

## Processes
| Process | Command | Role |
|---|---|---|
| Honeypots | `make up` (Docker) | capture attacker traffic (Cowrie/Dionaea) |
| Scapy monitor | `make monitor` (sudo) | packet-level detections |
| Log pipeline | `make pipeline` | normalize + store events |
| Responder | `make responder` (sudo) | behaviour analysis + autonomous response |
| Portal | `make deploy` or `make api` | dashboard + API |

## The dashboard
Open `https://<host>` (or `http://localhost:8000` in dev), log in with `ADMIN_USER`/
`ADMIN_PASS`. Panels:
- **Cards:** total events, attacker profiles, responses taken, peak threat gauge.
- **Attack origins:** live GeoIP map of public source IPs (private/lab IPs aren't plotted).
- **Events/min:** live timeline.
- **Live event feed:** new events stream in over WebSocket.
- **Top attackers:** profile cards (intent, TTP count, threat score band).
- **Autonomous responses:** actions the engine has taken.

## Reading a verdict
Each session gets an intent (e.g. *Credential Harvesting*), MITRE TTPs, and a
0–100 threat score that maps to a band:
`log (<40) · slow_redirect (40–70) · isolate (70–90) · block (>90)`.

## Manual actions
Block an IP immediately:
```bash
curl -X POST https://<host>/api/response/block -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' -d '{"ip":"1.2.3.4"}'
```
Unblock (host): `sudo iptables -D INPUT -s 1.2.3.4 -j DROP`.
List firewall rules added by CADN: `sudo iptables -L INPUT -n --line-numbers`.

## Forensics
On the block band the responder starts a `tcpdump` capture into `data/forensics/`.
Analyse with Wireshark/tshark.

## Alerting
Configure `.env` (SMTP / Slack / Telegram). Test a high-severity path by running the
5-stage campaign from the attacker VM and confirming an alert arrives. Unconfigured
channels are skipped (the response record's `detail` says so).

## Health & troubleshooting
- `GET /api/health` → `{status, geoip, ws_clients}`.
- No map points? GeoIP DB missing or only private IPs seen (`geoip:false`).
- Dashboard not updating? Check the WebSocket (`ws_clients` > 0); falls back to
  3-second polling automatically.
- Responder logs "iptables not available" → you're not on Linux/root; actions
  are recorded as failed but verdicts still flow.

## Backups
Back up `data/cadn.sqlite` (or the Mongo volume) and `data/forensics/`.
