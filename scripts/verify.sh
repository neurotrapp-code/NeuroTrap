#!/usr/bin/env bash
# CADN runtime verification (analysis / T-Pot mode). Read-only. Produces a single
# PASS/FAIL report proving the brain is up, the API serves the LIVE store, the
# T-Pot data source exists, and whether CADN has ingested events.
#
#   sudo bash scripts/verify.sh
set -uo pipefail
cd "$(cd "$(dirname "$0")/.." && pwd)"
pass=0; fail=0
ok(){ echo "  [PASS] $1"; pass=$((pass+1)); }
no(){ echo "  [FAIL] $1"; fail=$((fail+1)); }

echo "===== A. CADN brain containers ====="
for c in cadn-mongo cadn-portal cadn-nginx; do
  st=$(sudo docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null || echo missing)
  [ "$st" = running ] && ok "$c running" || no "$c is $st"
done

echo "===== B. portal API (https://localhost:8443) ====="
H=$(curl -sk --max-time 6 https://localhost:8443/api/health 2>/dev/null || true)
echo "  health: ${H:-<no response>}"
echo "$H" | grep -q '"status":"ok"' && ok "API health ok" || no "API not reachable on 8443"

echo "===== C. auth + live store ====="
set -a; . ./.env 2>/dev/null || true; set +a
TOK=$(curl -sk --max-time 6 https://localhost:8443/api/auth/login \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"${ADMIN_USER:-admin}\",\"password\":\"${ADMIN_PASS:-}\"}" 2>/dev/null \
  | python3 -c 'import sys,json;print(json.load(sys.stdin).get("token",""))' 2>/dev/null || true)
if [ -n "$TOK" ]; then
  ok "login -> JWT token"
  STATS=$(curl -sk --max-time 6 https://localhost:8443/api/stats -H "Authorization: Bearer $TOK" 2>/dev/null)
  echo "  stats: ${STATS:-<none>}"
  echo "$STATS" | grep -q 'total_events' && ok "stats served from live store" || no "stats endpoint"
else
  no "login failed (check ADMIN_PASS in .env)"
fi

echo "===== D. T-Pot Cowrie data source ====="
CL="${COWRIE_LOG:-/data/cowrie/log/cowrie.json}"
if sudo test -f "$CL"; then
  n=$(sudo wc -l < "$CL" 2>/dev/null || echo 0)
  ok "cowrie log present: $CL ($n lines)"
else
  no "cowrie log NOT found at $CL — set COWRIE_LOG in .env to T-Pot's path"
fi

echo "===== E. events ingested into CADN Mongo ====="
EC=$(sudo docker exec cadn-portal python3 -c "import os;from pymongo import MongoClient;print(MongoClient(os.environ['MONGO_URI'],serverSelectionTimeoutMS=4000).get_default_database().events.count_documents({}))" 2>/dev/null || echo ERR)
echo "  mongo events: $EC"
case "$EC" in
  ''|ERR|0) no "no events ingested yet (run the pipeline — see below)";;
  *)        ok "$EC events in CADN store";;
esac

echo
echo "================= SUMMARY: ${pass} PASS / ${fail} FAIL ================="
if [ "${EC:-0}" = 0 ] || [ "${EC:-ERR}" = ERR ]; then
cat <<'EOT'
To ingest T-Pot's captured sessions into CADN, on the host:
  python3 -m venv .venv 2>/dev/null; \
  .venv/bin/pip install -q -r detection/requirements.txt -r behavior/requirements.txt -r deception/requirements.txt pymongo
  set -a; . ./.env; set +a
  sudo -E .venv/bin/python pipeline/run_pipeline.py     # Ctrl+C after "stored ..." lines
  sudo -E .venv/bin/python response/run_responder.py    # live verdicts (observe mode)
Then re-run: sudo bash scripts/verify.sh
EOT
fi
echo "[*] Paste this entire report."
