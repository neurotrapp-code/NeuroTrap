"""Day 25 — Fake filesystem factory.

Writes a believable directory tree (Cowrie-style ``honeyfs``) into a target dir
so that when an attacker `cat`s around they find plausible content. The depth of
the deception scales with the template's ``filesystem_profile``:

    minimal   -> beginner : motd, passwd, one app, an auth.log
    iot       -> bot      : busybox-ish edge box + thin .env bait
    corporate -> advanced : .env with DB/API secrets, ~/.aws/credentials,
                            id_rsa, wp-config.php, customer DB dump, backup script

Returns a manifest mapping in-honeypot paths -> on-disk files.
"""
from __future__ import annotations

import json
import os
from typing import Dict

from .credentials import CredentialSet


def _write(dest: str, relpath: str, content: str, manifest: Dict[str, str]):
    full = os.path.join(dest, relpath.lstrip("/"))
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)
    manifest["/" + relpath.lstrip("/")] = full


class FilesystemFactory:
    """Build a fake filesystem for a given template + credentials."""

    def build(self, template: dict, creds: CredentialSet, dest_dir: str) -> Dict[str, str]:
        os.makedirs(dest_dir, exist_ok=True)
        manifest: Dict[str, str] = {}
        profile = template.get("filesystem_profile", "minimal")
        hostname = template.get("name", "server") + "-prod-01"

        # --- common baseline (every box has these) ---
        self._baseline(dest_dir, hostname, template, creds, manifest)

        if profile == "iot":
            self._iot(dest_dir, creds, manifest)
        elif profile == "corporate":
            self._corporate(dest_dir, creds, manifest)
        # minimal == baseline only

        # decoy_data flags can add extras on top of any profile
        decoy = template.get("decoy_data", {})
        if decoy.get("aws_keys") and creds.aws_access_key_id:
            self._aws(dest_dir, creds, manifest)
        if decoy.get("private_ssh_keys") and creds.ssh_private_key:
            _write(dest_dir, "root/.ssh/id_rsa", creds.ssh_private_key, manifest)
        if decoy.get("fake_db") and creds.db_tables:
            self._db_dump(dest_dir, creds, manifest)

        return manifest

    # -- layers ------------------------------------------------------------
    def _baseline(self, dest, hostname, template, creds, manifest):
        users = creds.users or [{"username": "admin", "password": "admin"}]
        primary = users[0]["username"]

        passwd = ["root:x:0:0:root:/root:/bin/bash",
                  "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
                  "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin"]
        for i, u in enumerate(users):
            uid = 1000 + i
            passwd.append(f"{u['username']}:x:{uid}:{uid}::/home/{u['username']}:/bin/bash")
        _write(dest, "etc/passwd", "\n".join(passwd) + "\n", manifest)
        _write(dest, "etc/hostname", hostname + "\n", manifest)
        _write(dest, "etc/motd",
               f"Welcome to {template.get('os_banner','Linux')}\n"
               "Unauthorized access is prohibited.\n", manifest)

        # a believable shell history for the primary user
        history = [
            "ls -la", "sudo apt update", "cd /var/www/html", "git pull",
            "systemctl restart nginx", "tail -f /var/log/syslog", "df -h", "exit",
        ]
        _write(dest, f"home/{primary}/.bash_history", "\n".join(history) + "\n", manifest)

        # auth.log showing prior "legit" logins
        _write(dest, "var/log/auth.log",
               f"Jun  6 09:14:22 {hostname} sshd[2211]: Accepted password for "
               f"{primary} from 10.0.0.14 port 51234 ssh2\n"
               f"Jun  6 09:40:01 {hostname} CRON[2299]: pam_unix(cron:session): "
               "session opened for user root\n", manifest)

        _write(dest, "var/www/html/index.html",
               f"<html><head><title>{hostname}</title></head>"
               "<body><h1>It works!</h1></body></html>\n", manifest)

    def _iot(self, dest, creds, manifest):
        _write(dest, "etc/issue", "BusyBox Edge OS v1.31.1\n", manifest)
        _write(dest, "bin/busybox", "#!/bin/sh\n# (binary placeholder)\n", manifest)
        if creds.api_keys:
            _write(dest, "opt/app/.env",
                   f"DEVICE_TOKEN={creds.jwt_secret}\n"
                   f"MQTT_PASS={creds.users[0]['password']}\n", manifest)

    def _corporate(self, dest, creds, manifest):
        env_lines = [
            "APP_ENV=production",
            f"DB_HOST=10.0.5.21",
            "DB_NAME=globex_prod",
            f"DB_USER={creds.users[0]['username']}",
            f"DB_PASSWORD={creds.db_password}",
            f"JWT_SECRET={creds.jwt_secret}",
        ]
        for name, key in creds.api_keys.items():
            env_lines.append(f"{name.upper()}_API_KEY={key}")
        _write(dest, "opt/app/.env", "\n".join(env_lines) + "\n", manifest)

        _write(dest, "var/www/html/wp-config.php",
               "<?php\n"
               "define('DB_NAME', 'globex_prod');\n"
               f"define('DB_USER', '{creds.users[0]['username']}');\n"
               f"define('DB_PASSWORD', '{creds.db_password}');\n"
               "define('DB_HOST', '10.0.5.21');\n", manifest)

        _write(dest, "opt/scripts/backup.sh",
               "#!/bin/bash\n# nightly DB backup\n"
               "mysqldump -u root -p$DB_PASSWORD globex_prod | "
               "gzip > /backups/db-$(date +%F).sql.gz\n", manifest)

    def _aws(self, dest, creds, manifest):
        _write(dest, "root/.aws/credentials",
               "[default]\n"
               f"aws_access_key_id = {creds.aws_access_key_id}\n"
               f"aws_secret_access_key = {creds.aws_secret_access_key}\n", manifest)
        _write(dest, "root/.aws/config",
               "[default]\nregion = us-east-1\noutput = json\n", manifest)

    def _db_dump(self, dest, creds, manifest):
        for table, rows in creds.db_tables.items():
            _write(dest, f"opt/app/dumps/{table}.json",
                   json.dumps(rows, indent=2) + "\n", manifest)
