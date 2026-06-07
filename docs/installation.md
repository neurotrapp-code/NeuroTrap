# CADN Installation Guide

Two ways to run: a **dev/test** setup (any OS, no honeypots) and the **full lab**
(Ubuntu 22.04 host) where live attacker traffic is captured.

## A. Dev / test (run the code + tests anywhere)
```bash
python3 -m venv .venv && source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -r detection/requirements.txt \
            -r behavior/requirements.txt \
            -r deception/requirements.txt \
            -r api/requirements.txt pydantic
python behavior/train_model.py            # trains intent model (macro-F1 > 0.85)
pytest tests/ -v                          # full suite should pass
python -m api.app                         # dashboard at http://localhost:8000
```
Set `ADMIN_PASS` and `JWT_SECRET` before logging into the dashboard:
```bash
export ADMIN_PASS='choose-a-strong-pass'
export JWT_SECRET="$(python -c 'import os;print(os.urandom(32).hex())')"
```

## B. Full lab (Ubuntu 22.04 honeypot host)
1. **Harden the host** (Week 1): `./scripts/setup_host.sh`, then move admin SSH to
   port 2222 (see Weeks 1-2 manual) so Cowrie can own port 22.
2. **Install Docker** (official repo) and copy env: `cp .env.example .env` and fill in
   `ADMIN_PASS`, `JWT_SECRET`, alerting + GeoIP.
3. **GeoIP (real heatmap):** create a free MaxMind account, download
   `GeoLite2-City.mmdb` into `./data/`.
4. **TLS certs:** put `cadn.crt` / `cadn.key` in `deploy/certs/` (self-signed for lab,
   or certbot).
5. **One-command deploy** (honeypots + portal + Nginx):
   ```bash
   make deploy            # docker compose -f docker-compose.yml -f deploy/docker-compose.portal.yml up -d --build
   ```
6. **Detection + live response** (host side, in the venv):
   ```bash
   sudo .venv/bin/python detection/packet_monitor.py -i eth0   # Scapy monitor
   .venv/bin/python pipeline/run_pipeline.py                   # log pipeline
   sudo .venv/bin/python response/run_responder.py             # behaviour + response
   ```
7. **Generate test traffic** from a separate attacker VM:
   `./scripts/simulate_attack.sh <HONEYPOT_IP>` and watch the dashboard update live.

## Database backend
SQLite by default (`data/cadn.sqlite`). For MongoDB set `DB_BACKEND=mongodb` and
`MONGO_URI`, then `docker compose --profile mongo up -d mongo`.

## Safety
Run only in an isolated lab. You deliberately attract real attacker traffic — never
on a machine you care about. Response actions modify the host firewall.
