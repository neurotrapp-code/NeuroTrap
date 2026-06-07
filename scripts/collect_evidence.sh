#!/usr/bin/env bash
# NeuroTrap/CADN runtime evidence collector (read-only).
# Gathers Phase 0/1/3/6/9 validation evidence into one redacted report you can
# paste back. It NEVER prints secret values (.env values, JWT, Mongo password,
# TLS keys) — only whether a key is set and non-sensitive facts.
#
#   sudo bash scripts/collect_evidence.sh            # sudo: iptables/ss need root
#   # then paste the printed report file
#
# Safe to re-run. Does not modify anything.
set +e
OUT="cadn_evidence_$(date +%Y%m%d_%H%M%S).txt"
COMPOSE="-f docker-compose.yml -f deploy/docker-compose.portal.yml"
exec > >(tee "$OUT") 2>&1

sec(){ echo; echo "==================== $1 ===================="; }
have(){ command -v "$1" >/dev/null 2>&1; }

sec "0. HOST FACTS"
uname -a; (lsb_release -d 2>/dev/null || cat /etc/os-release | head -2)
have docker && docker --version
have docker && docker compose version 2>/dev/null | head -1
echo "--- interfaces ---"; ip -br a 2>/dev/null
echo "--- zeek ---"; (command -v zeek || command -v /opt/zeek/bin/zeek) 2>/dev/null; zeek --version 2>/dev/null | head -1
echo "--- honeyd ---"; command -v honeyd 2>/dev/null || echo "honeyd not in PATH"
echo "--- data/ (DB + GeoIP presence) ---"; ls -l data/ 2>/dev/null | grep -iE "sqlite|mmdb" || echo "no sqlite/mmdb in data/"
echo "--- .env keys set (values redacted) ---"
if [ -f .env ]; then
  awk -F= '/^[A-Z]/{print $1"="($2==""?"<empty>":"<set>")}' .env
  grep '^MONGO_URI' .env | sed -E 's#mongodb://[^@]*@([^:/]+).*#MONGO_URI_HOST=\1 (should be "mongo" for Docker, "localhost" only if portal runs on host)#'
else echo "no .env file"; fi

sec "1. DOCKER INFRA & HEALTH"
docker compose $COMPOSE config >/dev/null 2>&1 && echo "COMPOSE_VALID" || echo "COMPOSE_INVALID (run: docker compose $COMPOSE config)"
docker compose $COMPOSE ps 2>/dev/null
echo "--- docker ps ---"; docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
echo "--- networks ---"; docker network ls | grep -E 'honeypot-net|elk-net|management-net'
for c in cadn-cowrie cadn-dionaea cadn-mongo cadn-portal cadn-nginx; do
  echo "----- logs: $c (tail 25) -----"
  docker logs --tail 25 "$c" 2>&1 | sed -E 's/(password|secret|token)=[^ ]+/\1=<redacted>/Ig'
done

sec "1b. PORTAL <-> MONGO CONNECTIVITY"
docker exec cadn-portal python3 -c "import os; from pymongo import MongoClient; \
c=MongoClient(os.environ.get('MONGO_URI','MISSING'),serverSelectionTimeoutMS=4000); \
print('mongo_ping', c.admin.command('ping'))" 2>&1 | tail -3

sec "3. NETWORK ISOLATION / FIREWALL / IPTABLES"
echo "--- ufw ---"; ufw status verbose 2>/dev/null || echo "ufw not available / need sudo"
for n in honeypot-net elk-net management-net; do
  echo "-- $n -- containers:"; docker network inspect "$n" --format '{{range .Containers}}{{.Name}} {{end}}' 2>/dev/null
  docker network inspect "$n" --format 'subnet={{range .IPAM.Config}}{{.Subnet}}{{end}} internal={{.Internal}}' 2>/dev/null
done
MONGO_ELK_IP=$(docker inspect -f '{{(index .NetworkSettings.Networks "elk-net").IPAddress}}' cadn-mongo 2>/dev/null)
echo "mongo elk-net IP: ${MONGO_ELK_IP:-<none>}"
if [ -n "$MONGO_ELK_IP" ]; then
  echo "isolation test (cowrie -> mongo:27017, expect NON-zero rc):"
  docker exec cadn-cowrie python3 -c "import socket;s=socket.socket();s.settimeout(3);print('cowrie_to_mongo_rc=',s.connect_ex(('$MONGO_ELK_IP',27017)))" 2>&1 \
    || echo "no python3 in cowrie image - run /dev/tcp variant manually"
fi
echo "--- iptables filter ---"; iptables -S 2>/dev/null | head -40 || echo "need sudo for iptables"
echo "--- iptables nat ---"; iptables -t nat -S 2>/dev/null | head -25
echo "--- listening ports ---"; ss -tlnp 2>/dev/null | grep -E ':22|:23|:21|:80|:443|:445|:3306|:8000' ; ss -ulnp 2>/dev/null | grep ':5060'

sec "2/Zeek. PROCESSES & LOGS"
echo "--- honeyd proc ---"; ps aux | grep -i '[h]oneyd' || echo "honeyd not running"
echo "--- zeek proc ---"; ps aux | grep -i '[z]eek' || echo "zeek not running"
ZD="${ZEEK_LOG_DIR:-/opt/zeek/logs/cadn}"
echo "--- zeek logs in $ZD ---"; ls -l "$ZD"/{conn,http,ssh,dns}.log 2>/dev/null || echo "zeek logs missing"
echo "--- conn.log head (expect JSON starting '{') ---"; head -c 300 "$ZD/conn.log" 2>/dev/null; echo
echo "--- cowrie.json size ---"; wc -l honeypots/cowrie/var/log/cowrie/cowrie.json 2>/dev/null || echo "no cowrie.json yet"
echo "--- dionaea.json ---"; ls -l honeypots/dionaea/var/log/dionaea.json 2>/dev/null || echo "no dionaea.json yet"

sec "6. GEOIP / API HEALTH"
curl -s --max-time 5 localhost:8000/api/health 2>/dev/null || echo "portal :8000 not reachable from host (ok if only via nginx) — try: docker exec cadn-portal curl -s localhost:8000/api/health"

sec "9. HARDENING"
echo "--- nginx security headers (https, -k for self-signed) ---"
curl -skI --max-time 5 https://localhost/ 2>/dev/null | grep -iE 'strict-transport|x-frame|x-content-type|content-security|referrer|permissions-policy' || echo "no headers / nginx not reachable on 443"
echo "--- portal container hardening ---"
docker inspect cadn-portal --format 'readonly={{.HostConfig.ReadonlyRootfs}} caps_dropped={{.HostConfig.CapDrop}} sec={{.HostConfig.SecurityOpt}}' 2>/dev/null
echo "--- lynis (if installed) ---"; lynis audit system --quick 2>/dev/null | grep -i "Hardening index" || echo "lynis not installed (sudo apt-get install -y lynis)"

echo
echo "==================== DONE -> $OUT ===================="
echo "Review for anything sensitive, then paste $OUT back."
