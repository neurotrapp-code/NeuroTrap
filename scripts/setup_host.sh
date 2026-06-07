#!/usr/bin/env bash
# NeuroTrap/CADN host bootstrap (Ubuntu 22.04). Review before running.
# Idempotent-ish: safe to re-run. Run as a sudo-capable non-root user.
set -euo pipefail

echo "[*] Updating packages..."
sudo apt update && sudo apt -y full-upgrade
sudo apt -y install ufw fail2ban chrony curl git vim net-tools htop unzip jq \
                    smbclient hydra nmap python3-venv

echo "[*] Time sync (UTC)..."
sudo systemctl enable --now chrony
sudo timedatectl set-timezone UTC

echo "[*] NOTE: moving management SSH to 2222 is a manual edit of /etc/ssh/sshd_config"
echo "    Set: Port 2222 / PermitRootLogin no / PasswordAuthentication no / AllowUsers \$USER"
echo "    Then: sudo systemctl restart ssh   (keep a session open!)"

echo "[*] UFW (management ssh 2222 + honeypot ports)..."
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 2222/tcp comment 'mgmt-ssh'
sudo ufw allow 22/tcp   comment 'cowrie-ssh'
sudo ufw allow 23/tcp   comment 'cowrie-telnet'
sudo ufw allow 21/tcp   comment 'dionaea-ftp'
sudo ufw allow 80/tcp   comment 'dionaea-http'
sudo ufw allow 445/tcp  comment 'dionaea-smb'
sudo ufw allow 3306/tcp comment 'dionaea-mysql'
sudo ufw allow 5060/udp comment 'dionaea-sip'
sudo ufw --force enable
sudo ufw status verbose

echo "[*] fail2ban jail for management ssh (2222) ..."
sudo tee /etc/fail2ban/jail.local >/dev/null <<'JAIL'
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
backend  = systemd

[sshd]
enabled  = true
port     = 2222
filter   = sshd
maxretry = 4
JAIL
sudo systemctl enable --now fail2ban

echo "[*] Cowrie log dir ownership (container uid 999) ..."
sudo chown -R 999:999 "$(dirname "$0")/../honeypots/cowrie/var" || true

echo "[*] Done. Next: install Docker (see README), then 'docker compose up -d'."
