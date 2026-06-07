# CADN Management API Reference (Week 5)

Base URL (dev): `http://localhost:8000` · (prod) `https://<host>` behind Nginx.
All responses are JSON. All data comes from the **live event store**.

## Authentication
JWT bearer tokens (HS256). Obtain a token, then send `Authorization: Bearer <token>`.

### `POST /api/auth/login`
Body: `{"username": "...", "password": "..."}`
→ `200 {"token": "<jwt>"}` · `401 {"error": "invalid credentials"}`
Credentials come from `ADMIN_USER` / `ADMIN_PASS`. If `ADMIN_PASS` is unset, login
always fails (auth is "closed by default").

## Endpoints

### `GET /api/health`  *(public)*
→ `{"status":"ok","geoip":true|false,"ws_clients":N}`

### `GET /api/stats`  *(auth)*
Aggregates over the live store:
```json
{"total_events":1234,"by_attack_type":{"brute_force":40,...},
 "by_severity":{"high":12,...},"top_sources":[{"src_ip":"1.2.3.4","count":88}],
 "profiles":17,"responses":9}
```

### `GET /api/events`  *(auth)*
Query: `limit` (≤1000), `src_ip`, `attack_type`, `severity`.
→ `{"count":N,"events":[{id,timestamp,src_ip,dst_port,attack_type,severity,
   raw_payload,honeypot_source,detail,geo}]}`
`geo` is a real GeoIP `{lat,lon,country,city}` or `null` (private/unknown IPs).

### `GET /api/attackers/<ip>`  *(auth)*
Full attacker view: `{src_ip, profile, events, sessions, responses, geo}`.
`profile` includes `classified_intent`, `threat_score`, `ttps`, `campaign_id`.

### `GET /api/responses`  *(auth)*
Query: `limit`. → `{"responses":[{ts,src_ip,action,threat_score,band,success,detail}]}`

### `POST /api/response/block`  *(auth)*
Body: `{"ip":"1.2.3.4"}` → blocks the IP via the real firewall and records it.
→ `{"action":"block","ip":"...","success":true|false,"detail":"..."}`
`503` if the response engine is unavailable on this host.

### `WS /ws/live-feed?token=<jwt>`
WebSocket. Streams `{"type":"event","data":{...event..., "geo":{...}}}` for every
new row the pipeline inserts (live tail of the event store). Invalid token → closed.

## Status codes
`200` ok · `400` bad request · `401` unauthorized · `503` action backend unavailable.

## Example
```bash
TOKEN=$(curl -s localhost:8000/api/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"'"$ADMIN_PASS"'"}' | jq -r .token)
curl -s localhost:8000/api/stats -H "Authorization: Bearer $TOKEN" | jq
curl -s localhost:8000/api/attackers/45.9.1.2 -H "Authorization: Bearer $TOKEN" | jq
```
