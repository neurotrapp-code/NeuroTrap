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

echo "===== 0. conflict check: T-Pot / other honeypot platforms ====="
TPOT=$(sudo docker ps -a --format '{{.Names}}' | grep -E \
  '^(tpotinit|tanner|tanner_api|tanner_redis|tanner_phpox|suricata|cowrie|dionaea|conpot.*|heralding|honeytrap|elasticpot|mailoney|medpot|adbhoney|ipphoney|dicompot|sentrypeer|wordpot|miniprint|redishoneypot|ciscoasa|h0neytr4p|snare|ewsposter|fatt|p0f|logstash|ddospot|honeyaml)$' 2>/dev/null || true)
if [ -n "$TPOT" ]; then
  echo "[X] T-Pot (or another honeypot platform) is present:"
  echo "$TPOT" | tr '\n' ' '; echo
  echo "    It binds the SAME ports as CADN (22/80/445/...) and will conflict."
  echo "    Stop it first, e.g.:"
  echo "      sudo systemctl stop tpot 2>/dev/null"
  echo "      sudo docker stop \$(sudo docker ps -q) 2>/dev/null   # or: cd /opt/tpot* && sudo docker compose down"
  echo "    Then re-run this script.  (Override at your own risk: CADN_IGNORE_TPOT=1)"
  [ "${CADN_IGNORE_TPOT:-0}" = "1" ] || exit 2
  echo "[!] CADN_IGNORE_TPOT=1 set — continuing despite conflict."
fi

echo "===== 1. provision .env (auto: creates/fills missing keys) ====="
[ -f .env ] || cp .env.example .env 2>/dev/null || touch .env
getval(){ grep -E "^$1=" .env | head -1 | cut -d= -f2-; }
set_env(){ # set_env KEY VALUE  (replace line if present, else append)
  if grep -qE "^$1=" .env; then sed -i "s|^$1=.*|$1=$2|" .env; else printf '%s=%s\n' "$1" "$2" >> .env; fi; }
gen(){ openssl rand -hex "${1:-12}" 2>/dev/null || head -c "$((${1:-12}*2))" /dev/urandom | od -An -tx1 | tr -d ' \n'; }

set_env DB_BACKEND mongodb
mp=$(getval MONGO_PASS); case "$mp" in ""|CHANGE_ME) mp=$(gen 12); set_env MONGO_PASS "$mp";; esac
set_env MONGO_URI "mongodb://cadn:${mp}@localhost:27017/cadn?authSource=admin"
if [ -z "$(getval ADMIN_PASS)" ]; then ap=$(gen 12); set_env ADMIN_PASS "$ap";
  echo "  [*] generated ADMIN_PASS = $ap   <<< SAVE THIS (dashboard login) >>>"; fi
[ -z "$(getval JWT_SECRET)" ] && set_env JWT_SECRET "$(gen 32)"
[ -z "$(getval ADMIN_USER)" ] && set_env ADMIN_USER admin
echo "[ok] .env keys:"; grep -E '^(DB_BACKEND|MONGO_PASS|ADMIN_USER|ADMIN_PASS|JWT_SECRET)=' .env | sed -E 's/=(.{0,3}).*/=\1***/'

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
