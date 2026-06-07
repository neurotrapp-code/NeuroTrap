#!/usr/bin/env bash
# Deploy the CADN ANALYSIS-ONLY stack (Mongo + portal + nginx) for hosts where
# T-Pot (or another platform) is the capture layer. No honeypots are started.
#
#   sudo bash scripts/deploy_analysis.sh
#
# Auto-provisions .env, generates a self-signed cert, and brings up the brain.
# Then run CADN's pipeline + responder against T-Pot's Cowrie JSON (printed below).
set -uo pipefail
cd "$(cd "$(dirname "$0")/.." && pwd)"
echo "[*] repo: $(pwd)"

COMPOSE=(--project-directory . -f deploy/docker-compose.analysis.yml)

echo "===== 1. provision .env ====="
[ -f .env ] || cp .env.example .env 2>/dev/null || touch .env
getval(){ grep -E "^$1=" .env | head -1 | cut -d= -f2-; }
set_env(){ if grep -qE "^$1=" .env; then sed -i "s|^$1=.*|$1=$2|" .env; else printf '%s=%s\n' "$1" "$2" >> .env; fi; }
gen(){ openssl rand -hex "${1:-12}" 2>/dev/null || head -c "$((${1:-12}*2))" /dev/urandom | od -An -tx1 | tr -d ' \n'; }

set_env DB_BACKEND mongodb
mp=$(getval MONGO_PASS); case "$mp" in ""|CHANGE_ME) mp=$(gen 12); set_env MONGO_PASS "$mp";; esac
set_env MONGO_URI "mongodb://cadn:${mp}@localhost:27017/cadn?authSource=admin"
if [ -z "$(getval ADMIN_PASS)" ]; then ap=$(gen 12); set_env ADMIN_PASS "$ap";
  echo "  [*] generated ADMIN_PASS = $ap   <<< SAVE THIS (dashboard login) >>>"; fi
[ -z "$(getval JWT_SECRET)" ] && set_env JWT_SECRET "$(gen 32)"
[ -z "$(getval ADMIN_USER)" ] && set_env ADMIN_USER admin
# T-Pot log locations (adjust if your T-Pot stores data elsewhere)
[ -z "$(getval COWRIE_LOG)" ]  && set_env COWRIE_LOG  /data/cowrie/log/cowrie.json
[ -z "$(getval DIONAEA_LOG)" ] && set_env DIONAEA_LOG /data/dionaea/log/dionaea.json
echo "[ok] .env:"; grep -E '^(DB_BACKEND|MONGO_PASS|ADMIN_USER|ADMIN_PASS|JWT_SECRET|COWRIE_LOG|DIONAEA_LOG)=' .env | sed -E 's/(PASS|SECRET)=(.{0,3}).*/\1=\2***/'

echo "===== 2. TLS cert ====="
if [ ! -f deploy/certs/cadn.crt ]; then
  mkdir -p deploy/certs
  openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
    -keyout deploy/certs/cadn.key -out deploy/certs/cadn.crt \
    -subj "/CN=neurotrap-cadn" >/dev/null 2>&1 && echo "[ok] generated cert" || echo "[!] openssl missing"
else echo "[ok] cert present"; fi

echo "===== 3. validate compose ====="
sudo docker compose "${COMPOSE[@]}" config >/dev/null 2>/tmp/cadn_cfg.err && echo "[ok] valid" || { echo "[X] invalid:"; cat /tmp/cadn_cfg.err; exit 1; }

echo "===== 4. deploy analysis stack (mongo + portal + nginx) ====="
sudo docker compose "${COMPOSE[@]}" up -d --build

echo "===== 5. status ====="
sudo docker ps --filter name=cadn- --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'

echo "===== 6. logs of any cadn-* not running ====="
for c in cadn-mongo cadn-portal cadn-nginx; do
  st=$(sudo docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null) || { echo "[$c] MISSING"; continue; }
  [ "$st" != "running" ] && { echo "----- $c ($st) -----"; sudo docker logs --tail 30 "$c" 2>&1; }
done

cat <<EONEXT

================ NEXT: feed T-Pot data into CADN ================
1) Confirm T-Pot's Cowrie log path (edit COWRIE_LOG in .env if different):
     sudo ls -la $(getval COWRIE_LOG)
2) Backfill existing T-Pot captures + keep tailing (host venv):
     set -a; . ./.env; set +a
     sudo -E .venv/bin/python pipeline/run_pipeline.py        # COWRIE_LOG honored
3) Live behaviour analysis + OBSERVE-mode response on T-Pot sessions:
     sudo -E .venv/bin/python response/run_responder.py       # RESPONDER_ENFORCE=1 to actually block
4) Dashboard:  https://<HOST_IP>:8443   (login admin / ADMIN_PASS)
================================================================
EONEXT
echo "[*] done. Paste this entire output."
