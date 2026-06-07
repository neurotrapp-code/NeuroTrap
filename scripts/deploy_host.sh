#!/usr/bin/env bash
# One-command host deploy for the FULL CADN stack (honeypots + Mongo + portal +
# nginx). Encapsulates the exact compose flags so it can't be run half-way.
#
#   sudo bash scripts/deploy_host.sh
#
# Safe to re-run. Cleans known stray one-off containers, validates the merged
# compose, deploys, then prints status and the logs of anything not running.
set -uo pipefail
cd "$(cd "$(dirname "$0")/.." && pwd)"
echo "[*] repo: $(pwd)"

COMPOSE=(-f docker-compose.yml -f deploy/docker-compose.portal.yml --profile mongo)

echo "===== 1. pre-flight: .env ====="
if [ ! -f .env ]; then
  echo "[X] .env missing. Run: cp .env.example .env  then set the keys below."; exit 1
fi
missing=0
for k in DB_BACKEND MONGO_PASS ADMIN_PASS JWT_SECRET; do
  if ! grep -qE "^${k}=.+" .env; then echo "[!] $k is NOT set in .env"; missing=1; fi
done
if grep -qE "^DB_BACKEND=mongodb" .env; then echo "[ok] DB_BACKEND=mongodb"; else
  echo "[!] DB_BACKEND is not 'mongodb' — the portal will use SQLite."; fi
[ "$missing" = 1 ] && echo "[!] Set the missing keys in .env (nano .env), then re-run."

echo "===== 2. remove stray one-off containers (safe) ====="
sudo docker rm -f dionaea-temp win-fs 2>/dev/null && echo "removed strays" || echo "no strays"

echo "===== 3. validate merged compose ====="
if ! sudo docker compose "${COMPOSE[@]}" config >/dev/null 2>/tmp/cadn_cfg.err; then
  echo "[X] compose config INVALID — likely your local docker-compose.yml edit:"
  cat /tmp/cadn_cfg.err
  echo "    Fix: cp docker-compose.yml docker-compose.yml.mine && git checkout -- docker-compose.yml"
  exit 1
fi
echo "[ok] compose config valid"

echo "===== 3b. ensure TLS cert for nginx (self-signed for lab) ====="
if [ ! -f deploy/certs/cadn.crt ]; then
  mkdir -p deploy/certs
  if openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
       -keyout deploy/certs/cadn.key -out deploy/certs/cadn.crt \
       -subj "/CN=neurotrap-cadn" >/dev/null 2>&1; then
    echo "[ok] generated self-signed cert in deploy/certs/"
  else
    echo "[!] openssl failed — install it (sudo apt-get install -y openssl); nginx will not start without a cert"
  fi
else
  echo "[ok] cert present"
fi

echo "===== 4. deploy (build may take a few minutes) ====="
sudo docker compose "${COMPOSE[@]}" up -d --build

echo "===== 5. status ====="
sudo docker ps -a --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'

echo "===== 6. logs of any container NOT running ====="
for c in cadn-cowrie cadn-dionaea cadn-mongo cadn-portal cadn-nginx; do
  st=$(sudo docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null) || { echo "[$c] MISSING"; continue; }
  if [ "$st" != "running" ]; then
    echo "----- $c ($st) last 30 log lines -----"
    sudo docker logs --tail 30 "$c" 2>&1
  fi
done
echo "[*] done. Paste this entire output."
