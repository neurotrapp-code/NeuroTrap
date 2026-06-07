# NeuroTrap — CADN
## Weeks 1–2 Execution Manual (Days 1–14)
### Cognitive Adaptive Deception Network — Step-by-Step Build Guide

> **Scope of this document.** This is a complete, zero-ambiguity execution manual covering **only the first two weeks** of the NeuroTrap/CADN roadmap:
> - **Week 1 (Days 1–7):** Infrastructure & Honeypot Deployment
> - **Week 2 (Days 8–14):** Detection & Traffic Analysis
>
> Everything below is grounded strictly in the project plan: the same networks (`honeypot-net`, `elk-net`, `management-net`), the same honeypots (Cowrie, Dionaea, Honeyd), the same detection thresholds (port scan `>10 ports/5s`, brute-force `>5 failed logins/min`), the same alert schema, and the same success criteria the plan defines for each week.
>
> Follow it top to bottom. Every day has objectives, exact files to create, exact commands to run, the code to write, expected results, a validation checklist, and a troubleshooting section.

---

## Table of Contents

- [Part 0 — Before You Start](#part-0--before-you-start)
  - [0.1 What you are building in 2 weeks](#01-what-you-are-building-in-2-weeks)
  - [0.2 Hardware / VM requirements](#02-hardware--vm-requirements)
  - [0.3 The canonical project directory layout](#03-the-canonical-project-directory-layout)
  - [0.4 Conventions used in this manual](#04-conventions-used-in-this-manual)
- [WEEK 1 — Infrastructure & Honeypot Deployment](#week-1--infrastructure--honeypot-deployment)
  - [Day 1 — Server Hardening](#day-1--server-hardening)
  - [Day 2 — Docker Architecture & Networks](#day-2--docker-architecture--networks)
  - [Day 3 — Cowrie Deployment (Part 1: Build & Config)](#day-3--cowrie-deployment-part-1-build--config)
  - [Day 4 — Cowrie Deployment (Part 2: Fake Filesystem & Testing)](#day-4--cowrie-deployment-part-2-fake-filesystem--testing)
  - [Day 5 — Dionaea Deployment](#day-5--dionaea-deployment)
  - [Day 6 — Honeyd & GNS3 Virtual Subnet](#day-6--honeyd--gns3-virtual-subnet)
  - [Day 7 — Verification & Network Diagram](#day-7--verification--network-diagram)
  - [Week 1 Deliverables Gate](#week-1-deliverables-gate)
- [WEEK 2 — Detection & Traffic Analysis](#week-2--detection--traffic-analysis)
  - [Day 8 — Scapy Packet Monitor (Part 1: Capture & Port-Scan Detection)](#day-8--scapy-packet-monitor-part-1-capture--port-scan-detection)
  - [Day 9 — Scapy Packet Monitor (Part 2: Brute-Force & Anomalies)](#day-9--scapy-packet-monitor-part-2-brute-force--anomalies)
  - [Day 10 — Unified Alert Event Schema](#day-10--unified-alert-event-schema)
  - [Day 11 — Log Pipeline (Part 1: Collectors & Normalizers)](#day-11--log-pipeline-part-1-collectors--normalizers)
  - [Day 12 — Log Pipeline (Part 2: Database & Indexing)](#day-12--log-pipeline-part-2-database--indexing)
  - [Day 13 — Zeek IDS Integration](#day-13--zeek-ids-integration)
  - [Day 14 — Detection Tuning & Testing](#day-14--detection-tuning--testing)
  - [Week 2 Deliverables Gate](#week-2-deliverables-gate)
- [Appendix A — Master Troubleshooting Index](#appendix-a--master-troubleshooting-index)
- [Appendix B — Daily Git Commit Checklist](#appendix-b--daily-git-commit-checklist)
- [Appendix C — Quick Command Reference Card](#appendix-c--quick-command-reference-card)

---

# Part 0 — Before You Start

## 0.1 What you are building in 2 weeks

By the end of Day 14 you will have, running on a single hardened Ubuntu host:

1. **A hardened host** with management SSH moved off port 22 (so Cowrie can own port 22).
2. **A three-network Docker stack** (`honeypot-net`, `elk-net`, `management-net`) with verified isolation.
3. **Cowrie** capturing SSH/Telnet sessions to structured JSON.
4. **Dionaea** capturing multi-protocol (SMB/HTTP/FTP/MySQL) connections to JSON.
5. **Honeyd** simulating a subnet of fake hosts with different OS fingerprints.
6. **A Scapy packet monitor** detecting port scans, brute-force, and protocol anomalies in under 5 seconds.
7. **A unified JSON alert schema** with a validating `AlertEvent` class.
8. **A log pipeline** normalizing Cowrie + Dionaea + Scapy + Zeek events into one database (SQLite by default, MongoDB optional), indexed by `src_ip` and `timestamp`.
9. **Zeek** producing connection-level JSON logs feeding the same pipeline.
10. **Tuned detection** validated with nmap + Hydra at a false-positive rate under 5%.

This is the foundation the remaining four weeks (behavior analysis, deception engine, response, dashboard) build on. **Do not skip the validation gates** — Week 3's ML classifier consumes the JSON Cowrie produces here, so if the logs are malformed now, everything downstream breaks.

## 0.2 Hardware / VM requirements

The plan names Ubuntu 22.04 LTS as the host. Use a dedicated VM (VirtualBox/VMware/Proxmox/cloud) — **never your daily machine**, because you will deliberately attract and run attacker traffic.

| Resource | Minimum | Recommended |
|---|---|---|
| OS | Ubuntu 22.04 LTS (Server) | Ubuntu 22.04 LTS (Server) |
| vCPU | 2 | 4 |
| RAM | 4 GB | 8 GB |
| Disk | 40 GB | 80 GB (PCAP + logs grow fast) |
| Network | 1 NIC, bridged or NAT with port forwards | 1–2 NICs |
| Snapshots | Take one after Day 1, Day 2, and Day 7 | Same |

> **Critical safety note.** Only expose this host to untrusted networks (the real internet) if your institution permits it and you understand the legal implications. For a graduation project, the safest setup is an **isolated lab network** where *you* generate the attack traffic with nmap/Hydra from a second "attacker" VM. This manual assumes a lab; every test uses traffic you generate yourself.

## 0.3 The canonical project directory layout

You will create this exact tree on Day 2 and fill it in over the two weeks. Keep to these paths — every command in this manual assumes them.

```
~/neurotrap/
├── docker-compose.yml
├── .env                      # secrets — gitignored
├── .env.example              # committed template
├── .gitignore
├── README.md
├── honeypots/
│   ├── cowrie/
│   │   ├── etc/
│   │   │   ├── cowrie.cfg
│   │   │   └── userdb.txt
│   │   ├── honeyfs/          # fake filesystem contents
│   │   ├── share/
│   │   └── var/log/cowrie/   # cowrie.json lands here
│   ├── dionaea/
│   │   ├── etc/
│   │   └── var/log/          # dionaea.json lands here
│   └── honeyd/
│       ├── honeyd.conf
│       └── nmap.prints
├── detection/
│   ├── packet_monitor.py     # Week 2, Days 8–9
│   ├── alert_event.py        # Week 2, Day 10
│   ├── detectors/
│   │   ├── __init__.py
│   │   ├── port_scan.py
│   │   ├── brute_force.py
│   │   └── anomaly.py
│   └── requirements.txt
├── pipeline/
│   ├── collectors/
│   │   ├── cowrie_collector.py
│   │   ├── dionaea_collector.py
│   │   └── zeek_collector.py
│   ├── normalizer.py
│   ├── db.py                 # SQLite/MongoDB writer
│   └── run_pipeline.py
├── zeek/
│   └── local.zeek            # Week 2, Day 13
├── scripts/
│   ├── setup_host.sh
│   └── simulate_attack.sh
├── docs/
│   ├── architecture.md
│   └── network-diagram.png
└── tests/
    ├── test_detectors.py
    └── test_normalizer.py
```

## 0.4 Conventions used in this manual

- Commands prefixed with `$` run as your **non-root admin user**; `#` means **root/sudo**.
- `🔴 ON ATTACKER VM` marks commands you run from the second (attacker) machine, not the honeypot host.
- **Expected result** blocks tell you exactly what success looks like.
- **Validation checklist** at the end of each day is a hard gate — do not proceed until every box passes.
- **Time estimate** assumes one person of intermediate Linux/Python skill. Double it if you are learning the tools for the first time.
- Replace every `CHANGE_ME` placeholder. Never commit real secrets.

---

# WEEK 1 — Infrastructure & Honeypot Deployment

**Week goal (from the plan):** A live Docker stack where Cowrie and Dionaea capture traffic to structured JSON, networks are isolated, and the Git repo is initialized. By Friday, `docker compose ps` shows all containers healthy.

---

## Day 1 — Server Hardening

**Estimated time:** 3–4 hours

### Objectives
- Bring Ubuntu 22.04 fully up to date.
- Create a non-root admin user with sudo.
- Configure the UFW firewall.
- Install and configure fail2ban.
- Enable time sync (NTP) — required so log timestamps across honeypots line up.
- **Move management SSH from port 22 to 2222** so that port 22 is free for Cowrie to occupy later.

### Files/folders to work on
- `/etc/ssh/sshd_config`
- `/etc/fail2ban/jail.local`
- `~/neurotrap/scripts/setup_host.sh` (you will save your steps here for reproducibility)

### Step-by-step

**1. Log in and update the system.**
```bash
$ sudo apt update && sudo apt -y full-upgrade
$ sudo apt -y install ufw fail2ban chrony curl git vim net-tools htop unzip jq
$ sudo reboot   # if a kernel update was installed
```
> `jq` is used constantly later to read JSON logs. Install it now.

**2. Create a non-root admin user** (skip if your VM already has one that is *not* root).
```bash
# as root, or with sudo:
$ sudo adduser cadn-admin
$ sudo usermod -aG sudo cadn-admin
```
Log out and back in as `cadn-admin`. Confirm sudo works:
```bash
$ sudo whoami        # must print: root
```

**3. Set up SSH key auth (do this BEFORE changing the port, so you don't lock yourself out).**
🔴 ON YOUR LAPTOP (the machine you connect *from*):
```bash
ssh-keygen -t ed25519 -C "cadn-admin"        # press enter through prompts
ssh-copy-id cadn-admin@<HONEYPOT_VM_IP>      # still on port 22 right now
```
Verify you can log in with the key without a password, then continue.

**4. Move management SSH to port 2222.** Edit the daemon config:
```bash
$ sudo vim /etc/ssh/sshd_config
```
Set/uncomment exactly these lines:
```
Port 2222
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
LoginGraceTime 30
AllowUsers cadn-admin
```
Apply and verify the daemon restarts cleanly:
```bash
$ sudo systemctl restart ssh
$ sudo ss -tlnp | grep -E ':2222|sshd'
```
> **Expected result:** `sshd` is listening on `2222`, NOT on `22`. Keep your current session open. Open a **new** terminal and confirm `ssh -p 2222 cadn-admin@<VM_IP>` works before closing the old one.

**5. Configure UFW.** Allow only management SSH on 2222 for now; honeypot ports are opened per-service later.
```bash
$ sudo ufw default deny incoming
$ sudo ufw default allow outgoing
$ sudo ufw allow 2222/tcp comment 'mgmt-ssh'
$ sudo ufw enable
$ sudo ufw status verbose
```
> **Expected result:** UFW active, `2222/tcp ALLOW IN` present, default incoming = deny.

**6. Configure fail2ban** to protect the management SSH port (NOT port 22 — that's the honeypot's job, and we never want to ban honeypot visitors).
```bash
$ sudo vim /etc/fail2ban/jail.local
```
```ini
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
```
```bash
$ sudo systemctl enable --now fail2ban
$ sudo fail2ban-client status sshd
```
> **Expected result:** jail `sshd` is loaded, "Currently banned: 0".

**7. Enable time sync.**
```bash
$ sudo systemctl enable --now chrony
$ chronyc tracking
$ timedatectl set-timezone UTC      # use UTC everywhere; honeypot logs are UTC by default
$ timedatectl
```
> **Expected result:** `System clock synchronized: yes`, timezone UTC. Consistent UTC timestamps are mandatory for Week 2 event correlation.

**8. Record what you did.** Create `scripts/setup_host.sh` and paste the apt/ufw/fail2ban commands so the host is reproducible (needed for the Week 6 "fresh-VM deploy" criterion, but start it now).

### Expected results (end of Day 1)
- Management SSH only on 2222, key-only, root login disabled.
- Port 22 is completely free (nothing listening) — verify: `sudo ss -tlnp | grep ':22 '` returns nothing.
- UFW active, fail2ban running, clock synced to UTC.

### Validation checklist — Day 1
- [ ] `ssh -p 2222 cadn-admin@<VM_IP>` logs in with key, no password prompt.
- [ ] `ssh -p 22 cadn-admin@<VM_IP>` **fails** (connection refused) — proves 22 is free.
- [ ] `sudo ufw status` shows active with only 2222 allowed.
- [ ] `sudo fail2ban-client status sshd` shows the jail active.
- [ ] `timedatectl` shows synced + UTC.
- [ ] Took a VM snapshot named `day1-hardened`.

### Troubleshooting — Day 1
- **Locked out after port change.** Use the VM console (VirtualBox/Proxmox web console) to log in directly, re-check `sshd_config`, run `sudo systemctl restart ssh`. This is why step 3/4 told you to keep a session open.
- **`ssh: connect to host ... port 2222: Connection refused`.** The daemon didn't restart or UFW is blocking. Run `sudo systemctl status ssh` and `sudo ufw status`.
- **fail2ban won't start, "Failed to access socket".** Ensure `backend = systemd` matches Ubuntu 22.04; run `sudo systemctl restart fail2ban` and check `sudo journalctl -u fail2ban -n 50`.
- **`chronyc tracking` shows "Not synchronised".** Allow outbound UDP/123: `sudo ufw allow out 123/udp`, then `sudo systemctl restart chrony`.

---

## Day 2 — Docker Architecture & Networks

**Estimated time:** 4–5 hours

### Objectives
- Install Docker Engine + Docker Compose v2 (the official way, not the snap).
- Create the project directory tree from §0.3.
- Initialize Git with a `.gitignore` that excludes secrets and logs.
- Define the **three Docker networks** the plan specifies: `honeypot-net` (external-facing), `elk-net` (internal), `management-net` (portal + enrichment).
- Stand up a skeleton `docker-compose.yml` and prove the networks come up isolated.

### Files/folders to work on
- `~/neurotrap/` (entire tree)
- `~/neurotrap/docker-compose.yml`
- `~/neurotrap/.gitignore`, `.env.example`

### Step-by-step

**1. Install Docker Engine (official repo).**
```bash
$ sudo install -m 0755 -d /etc/apt/keyrings
$ curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
    sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
$ sudo chmod a+r /etc/apt/keyrings/docker.gpg
$ echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
$ sudo apt update
$ sudo apt -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

**2. Run Docker as your user (no sudo on every command).**
```bash
$ sudo usermod -aG docker $USER
$ newgrp docker        # or log out/in
$ docker run --rm hello-world
$ docker compose version
```
> **Expected result:** `hello-world` prints the welcome message; `docker compose version` prints v2.x.

**3. Create the project tree.**
```bash
$ mkdir -p ~/neurotrap/{honeypots/{cowrie/{etc,honeyfs,share,var/log/cowrie},dionaea/{etc,var/log},honeyd},detection/detectors,pipeline/collectors,zeek,scripts,docs,tests}
$ cd ~/neurotrap
$ touch detection/detectors/__init__.py pipeline/collectors/__init__.py
$ ls -R | head -40
```

**4. Initialize Git and protect secrets.**
```bash
$ cd ~/neurotrap
$ git init -b main
```
Create `.gitignore`:
```bash
$ cat > .gitignore << 'EOF'
# secrets
.env
*.key
*.pem
# logs & captured data (can contain malware/PII)
**/var/log/
*.json
*.log
*.pcap
captures/
# python
__pycache__/
*.pyc
.venv/
venv/
# db
*.sqlite
*.db
EOF
```
Create the committed template `.env.example`:
```bash
$ cat > .env.example << 'EOF'
# Cowrie
COWRIE_HOSTNAME=srv-db-prod-01
# Dionaea
DIONAEA_LISTEN=0.0.0.0
# Database (Week 2)
DB_BACKEND=sqlite           # sqlite | mongodb
SQLITE_PATH=/data/cadn.sqlite
MONGO_URI=mongodb://cadn:CHANGE_ME@mongo:27017/cadn
# Alerting (Week 5 — placeholders for now)
SMTP_HOST=
SLACK_WEBHOOK=
EOF
$ cp .env.example .env       # fill real values into .env later; .env is gitignored
```

**5. Define the three networks + skeleton compose file.** This file grows each day; today it just declares networks and a throwaway test container per network.
```bash
$ vim ~/neurotrap/docker-compose.yml
```
```yaml
# NeuroTrap / CADN — base stack
# Networks per project plan:
#   honeypot-net   : external-facing, where honeypots live
#   elk-net        : internal, log storage / processing (no internet egress later)
#   management-net : portal + enrichment services
networks:
  honeypot-net:
    name: honeypot-net
    driver: bridge
    ipam:
      config:
        - subnet: 172.30.0.0/24
  elk-net:
    name: elk-net
    driver: bridge
    internal: true          # <-- no outbound internet; storage stays isolated
    ipam:
      config:
        - subnet: 172.31.0.0/24
  management-net:
    name: management-net
    driver: bridge
    ipam:
      config:
        - subnet: 172.32.0.0/24

services:
  # Temporary probes — used ONLY to validate isolation on Day 2.
  netcheck-hp:
    image: nicolaka/netshoot
    container_name: netcheck-hp
    command: sleep 3600
    networks: [honeypot-net]
  netcheck-elk:
    image: nicolaka/netshoot
    container_name: netcheck-elk
    command: sleep 3600
    networks: [elk-net]
  netcheck-mgmt:
    image: nicolaka/netshoot
    container_name: netcheck-mgmt
    command: sleep 3600
    networks: [management-net]
```

**6. Bring it up and verify networks + isolation.**
```bash
$ cd ~/neurotrap
$ docker compose up -d
$ docker network ls | grep -E 'honeypot-net|elk-net|management-net'
$ docker compose ps
```
Test that the **honeypot network cannot reach the management network** (a core success criterion of Week 1):
```bash
# get the mgmt probe's IP
$ docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' netcheck-mgmt
# from the honeypot-net probe, try to ping it — this MUST fail
$ docker exec netcheck-hp ping -c 2 -W 2 <netcheck-mgmt-ip>
```
> **Expected result:** 100% packet loss / unreachable. Different bridge networks are isolated by default — proving this now satisfies the "Network isolation verified" deliverable.

Also confirm `elk-net` has no internet:
```bash
$ docker exec netcheck-elk ping -c 2 -W 2 8.8.8.8      # MUST fail (internal: true)
$ docker exec netcheck-hp  ping -c 2 -W 2 8.8.8.8      # succeeds (honeypot-net has egress)
```

**7. Tear down the probes (keep the networks defined for tomorrow).**
```bash
$ docker compose down
```
> The networks are recreated automatically when real services come up on Day 3.

**8. First commit.**
```bash
$ cd ~/neurotrap
$ git add .gitignore .env.example docker-compose.yml docs scripts
$ git commit -m "Day 2: project skeleton, three isolated docker networks"
```
> Connect a remote (GitHub) now if you have one: `git remote add origin <url> && git push -u origin main`.

### Expected results (end of Day 2)
- Docker + Compose v2 working without sudo.
- Three networks created; honeypot↔management isolation proven; elk-net has no egress.
- Git initialized, secrets gitignored, first commit done.

### Validation checklist — Day 2
- [ ] `docker run --rm hello-world` succeeds.
- [ ] `docker network ls` lists all three CADN networks.
- [ ] Honeypot→management ping **fails** (isolation proven).
- [ ] `elk-net` cannot reach 8.8.8.8; `honeypot-net` can.
- [ ] `.env` is gitignored (`git status` does NOT show `.env`).
- [ ] First commit exists (`git log --oneline`).

### Troubleshooting — Day 2
- **`permission denied ... /var/run/docker.sock`.** You skipped `newgrp docker` or didn't re-login after `usermod`. Run `newgrp docker` or log out/in.
- **`docker compose` says "command not found".** You installed the old `docker-compose` (hyphen) or the snap. Use the plugin: `docker compose` (space). Reinstall `docker-compose-plugin`.
- **Subnet overlap error on `up`.** Another network uses `172.30/31/32.0.0`. Change the subnets in the compose file to free ranges (e.g., `172.40.0.0/24`).
- **Honeypot→management ping unexpectedly succeeds.** A container is attached to multiple networks, or you tested the wrong IP. Re-run `docker inspect` and ensure each probe is on exactly one network.

---

## Day 3 — Cowrie Deployment (Part 1: Build & Config)

**Estimated time:** 4–6 hours

### Objectives
- Add the Cowrie service to `docker-compose.yml` on `honeypot-net`, exposing host port **22 → container 2222** (Cowrie listens internally on 2222 as a non-root process; the host forwards 22 to it).
- Configure `cowrie.cfg` with a realistic hostname, **JSON logging enabled**, and malware download enabled.
- Build `userdb.txt` defining which credentials succeed/fail.

### Files/folders to work on
- `~/neurotrap/docker-compose.yml`
- `~/neurotrap/honeypots/cowrie/etc/cowrie.cfg`
- `~/neurotrap/honeypots/cowrie/etc/userdb.txt`

### Step-by-step

**1. Add Cowrie to the compose file.** Append this service (keep the `networks:` block from Day 2; remove the three `netcheck-*` probes now):
```yaml
services:
  cowrie:
    image: cowrie/cowrie:latest
    container_name: cadn-cowrie
    restart: unless-stopped
    ports:
      - "22:2222"          # host SSH 22 -> cowrie 2222
      - "23:2223"          # host Telnet 23 -> cowrie 2223
    volumes:
      - ./honeypots/cowrie/etc/cowrie.cfg:/cowrie/cowrie-git/etc/cowrie.cfg:ro
      - ./honeypots/cowrie/etc/userdb.txt:/cowrie/cowrie-git/etc/userdb.txt:ro
      - ./honeypots/cowrie/honeyfs:/cowrie/cowrie-git/honeyfs
      - ./honeypots/cowrie/var/log/cowrie:/cowrie/cowrie-git/var/log/cowrie
    networks: [honeypot-net]
```

**2. Open host ports 22 and 23 in UFW** (management SSH stays on 2222, untouched):
```bash
$ sudo ufw allow 22/tcp comment 'cowrie-ssh'
$ sudo ufw allow 23/tcp comment 'cowrie-telnet'
$ sudo ufw status
```

**3. Pull the image and extract the default config to edit a copy.**
```bash
$ docker pull cowrie/cowrie:latest
# get the shipped default to use as a starting point:
$ docker run --rm cowrie/cowrie:latest cat /cowrie/cowrie-git/etc/cowrie.cfg.dist \
    > ~/neurotrap/honeypots/cowrie/etc/cowrie.cfg
```

**4. Edit `cowrie.cfg`.** Open it and set these keys (they exist in the dist file — find and change them; add the `[output_jsonlog]` block if missing):
```bash
$ vim ~/neurotrap/honeypots/cowrie/etc/cowrie.cfg
```
```ini
[honeypot]
hostname = srv-db-prod-01
# present a believable production box; matches COWRIE_HOSTNAME in .env
auth_class = UserDB
download_path = ${honeypot:state_path}/downloads
# malware download capture ENABLED (plan requirement):
download_limit_size = 10485760

[ssh]
enabled = true
version = SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
listen_endpoints = tcp:2223:interface=0.0.0.0

[telnet]
enabled = true
listen_endpoints = tcp:2223:interface=0.0.0.0

[output_jsonlog]
enabled = true
logfile = ${honeypot:log_path}/cowrie.json
epoch_timestamp = false
```
> **Why these matter:** JSON logging is what Week 2's pipeline ingests. The realistic SSH banner makes nmap/attacker tooling believe it's a real OpenSSH. Malware download capture feeds Dionaea-style binary collection.
>
> **Note on ports:** Inside the container Cowrie runs as non-root and listens on 2222 (SSH) / 2223 (Telnet). The compose `ports:` mapping forwards host 22→2222 and host 23→2223. Make sure the `listen_endpoints` above match the container-side ports (2222/2223). Adjust the SSH endpoint line to `tcp:2222:...` (shown as 2223 for telnet only — double check the `[ssh]` block uses 2222).

Correct the `[ssh]` endpoint explicitly:
```ini
[ssh]
listen_endpoints = tcp:2222:interface=0.0.0.0
```

**5. Create `userdb.txt`** — defines which logins Cowrie accepts. Format: `username:uid:password`. A `*` wildcard and `!` negation are supported.
```bash
$ vim ~/neurotrap/honeypots/cowrie/etc/userdb.txt
```
```
# username:x:password   (x is ignored; use 0)
# Accept a few common weak creds so attackers "get in" and we can watch them:
root:0:root
root:0:123456
root:0:password
root:0:admin
admin:0:admin
admin:0:password
ubuntu:0:ubuntu
# Accept any password for 'oracle' (wildcard):
oracle:0:*
# Explicitly REJECT the real strong password so nobody guesses the truth:
root:0:!S3cure-Real-Pw
```

### Validation checklist — Day 3
- [ ] `cowrie.cfg` has `[output_jsonlog] enabled = true`.
- [ ] `[ssh] listen_endpoints` uses container port **2222**; `[telnet]` uses **2223**.
- [ ] `userdb.txt` saved with at least 5 weak-credential entries.
- [ ] UFW now allows 22 and 23 (plus 2222 mgmt).
- [ ] Cowrie image pulled (`docker images | grep cowrie`).

### Troubleshooting — Day 3
- **Can't get `cowrie.cfg.dist`.** Some tags omit it; alternatively `docker run --rm cowrie/cowrie:latest ls /cowrie/cowrie-git/etc/` to find the exact filename, or copy the documented template from the Cowrie docs.
- **UFW blocks but you also want fail2ban to ignore port 22.** Do NOT add a fail2ban jail for 22 — those are honeypot visitors you want to keep, not ban.

---

## Day 4 — Cowrie Deployment (Part 2: Fake Filesystem & Testing)

**Estimated time:** 4–6 hours

### Objectives
- Create a believable fake filesystem under `honeyfs/` so the shell feels like a real server.
- Launch Cowrie and confirm it accepts a login.
- Verify structured JSON events are written to `cowrie.json` in real time (a Week 1 success criterion).

### Files/folders to work on
- `~/neurotrap/honeypots/cowrie/honeyfs/`
- `~/neurotrap/honeypots/cowrie/var/log/cowrie/cowrie.json`

### Step-by-step

**1. Seed the fake filesystem.** Cowrie ships a default `honeyfs`; we add believable production-looking files. Create a few decoy artifacts:
```bash
$ cd ~/neurotrap/honeypots/cowrie/honeyfs
$ mkdir -p etc home/oracle var/www/html opt/app
$ cat > etc/motd << 'EOF'
Welcome to srv-db-prod-01 (Ubuntu 22.04.3 LTS)
 * Documentation:  internal-wiki.corp.local
 Last login: from 10.0.4.12
EOF
$ cat > home/oracle/.bash_history << 'EOF'
ls -la
mysql -u root -p
cat /opt/app/config/database.yml
exit
EOF
$ cat > opt/app/.env << 'EOF'
DB_HOST=10.0.5.20
DB_USER=app_prod
DB_PASS=PrdMy$ql_2023!
API_KEY=sk_live_4eC39Hq...DECOY...
EOF
```
> These are **decoys** — fake credentials that look real. In Week 4 they become part of the deception engine; for now they make the honeypot convincing and give attackers something to `cat`.

**2. Fix permissions so the container (non-root, uid 999) can write logs.**
```bash
$ sudo chown -R 999:999 ~/neurotrap/honeypots/cowrie/var
$ chmod -R 755 ~/neurotrap/honeypots/cowrie/honeyfs
```

**3. Start Cowrie.**
```bash
$ cd ~/neurotrap
$ docker compose up -d cowrie
$ docker compose ps
$ docker compose logs --tail=30 cowrie
```
> **Expected result:** `cadn-cowrie` is `Up`; logs show `CowrieSSHFactory starting on 2222` and `telnet ... 2223`.

**4. Test an SSH login against the honeypot** (from your laptop or attacker VM):
```bash
🔴 ON ATTACKER VM:
$ ssh root@<HONEYPOT_VM_IP>          # port 22 = Cowrie
# password: 123456   (one of the accepted creds)
```
You should land in a fake shell with hostname `srv-db-prod-01`. Run a few commands:
```bash
$ whoami
$ uname -a
$ cat /opt/app/.env
$ wget http://example.com/x.sh        # tests malware-download capture
$ exit
```

**5. Verify JSON events were written — in real time.**
```bash
# back on the HONEYPOT host:
$ tail -f ~/neurotrap/honeypots/cowrie/var/log/cowrie/cowrie.json
```
While that tails, open another SSH login from the attacker VM and watch events appear instantly. Pretty-print to confirm structure:
```bash
$ tail -n 20 ~/neurotrap/honeypots/cowrie/var/log/cowrie/cowrie.json | jq '{eventid, src_ip, username, password, input}'
```
> **Expected result:** You see events such as `cowrie.session.connect`, `cowrie.login.success`, `cowrie.command.input` (with the exact commands you typed), and `cowrie.session.file_download`. Each line is valid JSON with `eventid`, `src_ip`, `timestamp`, `session`.

### Expected results (end of Day 4)
- Cowrie running, accepts weak creds, presents a believable shell.
- `cowrie.json` fills with structured events in real time.
- **Week 1 deliverable "Cowrie capturing SSH sessions" → PASS.**

### Validation checklist — Day 4
- [ ] SSH login with `root:123456` succeeds and drops into the fake shell.
- [ ] `cat /opt/app/.env` shows the decoy file.
- [ ] `cowrie.json` shows `cowrie.login.success` for your test IP.
- [ ] `cowrie.command.input` events contain the exact commands you typed.
- [ ] `jq` parses every line without error (`jq -c . cowrie.json > /dev/null` exits 0).
- [ ] Committed config (NOT logs): `git add honeypots/cowrie/etc && git commit -m "Day 3-4: Cowrie SSH/Telnet honeypot with JSON logging"`.

### Troubleshooting — Day 4
- **Login always rejected.** `userdb.txt` not mounted or wrong format. Check `docker compose exec cowrie cat /cowrie/cowrie-git/etc/userdb.txt`. Format is `user:0:password`, no spaces.
- **No `cowrie.json` file appears.** Either JSON output disabled (recheck `[output_jsonlog] enabled = true`) or the `var/log/cowrie` volume isn't writable. Fix ownership to `999:999` and `docker compose restart cowrie`.
- **`Permission denied` in container logs about var/log.** Same ownership fix as above.
- **Port 22 "address already in use".** The host's OpenSSH is still on 22 — you didn't move it to 2222 on Day 1. Fix `sshd_config`, restart ssh.
- **Login lands you in YOUR real shell, not Cowrie.** You connected on port 2222 (management) by habit. Cowrie is on **22**.

---

## Day 5 — Dionaea Deployment

**Estimated time:** 4–5 hours

### Objectives
- Deploy Dionaea, the multi-protocol malware collector, on `honeypot-net`.
- Expose SMB, HTTP, FTP, MySQL (and SIP) so it captures multi-protocol connections.
- Enable JSON logging and binary (malware) capture.
- Verify with an SMB client (a Week 1 deliverable: "Dionaea capturing malware requests").

### Files/folders to work on
- `~/neurotrap/docker-compose.yml`
- `~/neurotrap/honeypots/dionaea/etc/` (ihandler/json config)
- `~/neurotrap/honeypots/dionaea/var/log/dionaea.json`

### Step-by-step

**1. Add Dionaea to the compose file.** Append:
```yaml
  dionaea:
    image: dinotools/dionaea:latest
    container_name: cadn-dionaea
    restart: unless-stopped
    ports:
      - "21:21"        # FTP
      - "80:80"        # HTTP
      - "445:445"      # SMB
      - "3306:3306"    # MySQL
      - "5060:5060/udp" # SIP
    volumes:
      - ./honeypots/dionaea/etc:/opt/dionaea/etc/dionaea:ro
      - ./honeypots/dionaea/var/log:/opt/dionaea/var/log/dionaea
      - ./honeypots/dionaea/var/log:/opt/dionaea/var/lib/dionaea/binaries
    networks: [honeypot-net]
```
> Cowrie owns SSH(22)/Telnet(23); Dionaea owns the other services. No port collisions.

**2. Open the Dionaea ports in UFW.**
```bash
$ sudo ufw allow 21/tcp comment 'dionaea-ftp'
$ sudo ufw allow 80/tcp comment 'dionaea-http'
$ sudo ufw allow 445/tcp comment 'dionaea-smb'
$ sudo ufw allow 3306/tcp comment 'dionaea-mysql'
$ sudo ufw allow 5060/udp comment 'dionaea-sip'
$ sudo ufw status numbered
```

**3. Extract Dionaea's default config and enable JSON logging.**
```bash
$ docker pull dinotools/dionaea:latest
# copy the shipped config tree out so we can edit it:
$ docker run --rm dinotools/dionaea:latest tar -C /opt/dionaea/etc/dionaea -cf - . \
    | tar -C ~/neurotrap/honeypots/dionaea/etc -xf -
$ ls ~/neurotrap/honeypots/dionaea/etc
```
Enable the JSON ihandler. Edit the ihandlers config:
```bash
$ vim ~/neurotrap/honeypots/dionaea/etc/ihandlers-enabled/log_json.yaml
```
If it doesn't exist, create it:
```yaml
- name: log_json
  config:
    handlers:
      - file:///opt/dionaea/var/log/dionaea/dionaea.json
    flat_data: true
```
Ensure the symlink/enable is in place (Dionaea enables ihandlers by presence in `ihandlers-enabled/`).

**4. Start Dionaea.**
```bash
$ cd ~/neurotrap
$ docker compose up -d dionaea
$ docker compose ps
$ docker compose logs --tail=40 dionaea
```
> **Expected result:** `cadn-dionaea` is `Up`; logs show listeners binding on 21/80/445/3306.

**5. Test with an SMB client and an HTTP request** (from attacker VM):
```bash
🔴 ON ATTACKER VM:
$ sudo apt -y install smbclient curl
$ smbclient -L //<HONEYPOT_VM_IP> -N           # list SMB shares (anonymous)
$ curl -s http://<HONEYPOT_VM_IP>/ | head
$ curl -s "http://<HONEYPOT_VM_IP>/index.php?cmd=id"
```

**6. Verify JSON capture.**
```bash
# on the HONEYPOT host:
$ tail -n 20 ~/neurotrap/honeypots/dionaea/var/log/dionaea.json | jq '{connection, remote_host, remote_port, protocol}' 2>/dev/null \
  || tail -n 20 ~/neurotrap/honeypots/dionaea/var/log/dionaea.json
```
> **Expected result:** JSON lines describing the SMB and HTTP connections from your attacker IP. The plan's deliverable says: "`dionaea.json` logs SMB and HTTP connections." That's exactly what you should see.

### Expected results (end of Day 5)
- Dionaea up, listening on FTP/HTTP/SMB/MySQL/SIP.
- `dionaea.json` records multi-protocol connections.
- **Week 1 deliverable "Dionaea capturing malware requests" → PASS.**

### Validation checklist — Day 5
- [ ] `docker compose ps` shows `cadn-dionaea` healthy alongside `cadn-cowrie`.
- [ ] `smbclient -L` produces a response (even an error response means Dionaea answered).
- [ ] `dionaea.json` contains an entry with your attacker `remote_host`.
- [ ] HTTP request appears in the log.
- [ ] No UFW port conflicts (`sudo ufw status` shows 21/80/445/3306/5060 + 22/23 + 2222).
- [ ] Committed: `git add honeypots/dionaea/etc docker-compose.yml && git commit -m "Day 5: Dionaea multi-protocol collector with JSON logging"`.

### Troubleshooting — Day 5
- **Port 80/3306 "already in use".** A host nginx/MySQL is running. `sudo ss -tlnp | grep ':80\|:3306'`, then `sudo systemctl disable --now apache2 mysql` (or change the host-side port mapping).
- **No `dionaea.json`.** The `log_json` ihandler isn't enabled or the log dir isn't writable. Check `docker compose exec dionaea ls /opt/dionaea/var/log/dionaea/` and the container logs for ihandler load errors.
- **`smbclient` hangs.** SMB (445) blocked by UFW or the container didn't bind 445. Recheck UFW and `docker compose logs dionaea`.
- **Config extraction tar fails.** Run `docker run --rm dinotools/dionaea:latest find /opt/dionaea/etc -maxdepth 2` to confirm the path, adjust if the image layout differs.

---

## Day 6 — Honeyd & GNS3 Virtual Subnet

**Estimated time:** 4–6 hours

### Objectives
- Deploy Honeyd to simulate a **subnet of virtual hosts** with different OS fingerprints (low-interaction breadth to complement Cowrie/Dionaea's depth).
- Integrate the topology with GNS3/EVE-NG for the network diagram you'll finalize on Day 7.

### Files/folders to work on
- `~/neurotrap/honeypots/honeyd/honeyd.conf`
- `~/neurotrap/honeypots/honeyd/nmap.prints`

### Step-by-step

> **Reality check on Honeyd.** Honeyd is legacy software and is simplest to run **directly on the host** (or on a dedicated lab VM) bound to spare IPs on the honeypot subnet, rather than in Docker. We run it on the host here. GNS3/EVE-NG is used to *visualize and document* the topology (Day 7 diagram) and, optionally, to host an attacker VM.

**1. Install Honeyd and its fingerprint database.**
```bash
$ sudo apt -y install honeyd
# fingerprint files are usually shipped; locate them:
$ dpkg -L honeyd | grep -i prints
# copy nmap fingerprints into the project for reference:
$ cp /etc/honeypot/nmap.prints ~/neurotrap/honeypots/honeyd/nmap.prints 2>/dev/null \
  || find / -name 'nmap.prints' 2>/dev/null | head
```

**2. Reserve a block of IPs on the honeypot subnet for the virtual hosts.** Pick unused addresses on your lab LAN, e.g. `10.0.0.50–10.0.0.53` (adjust to your lab range). Honeyd will ARP-respond for these.

**3. Write `honeyd.conf`** defining several OS personalities:
```bash
$ vim ~/neurotrap/honeypots/honeyd/honeyd.conf
```
```
### Default template — drop everything unknown
create default
set default default tcp action reset
set default default udp action reset
set default default icmp action open

### Virtual host 1 — Linux web server
create linux-web
set linux-web personality "Linux 5.4"
set linux-web default tcp action reset
add linux-web tcp port 80 "sh scripts/web.sh"
add linux-web tcp port 22 reset
set linux-web ethernet "00:16:3e:1a:2b:01"

### Virtual host 2 — Windows file server
create win-fs
set win-fs personality "Microsoft Windows Server 2016"
set win-fs default tcp action reset
add win-fs tcp port 445 open
add win-fs tcp port 139 open
set win-fs ethernet "00:16:3e:1a:2b:02"

### Virtual host 3 — Cisco router
create cisco-rtr
set cisco-rtr personality "Cisco IOS 15.1"
add cisco-rtr tcp port 23 open
set cisco-rtr ethernet "00:16:3e:1a:2b:03"

### Bind personalities to IPs
bind 10.0.0.50 linux-web
bind 10.0.0.51 win-fs
bind 10.0.0.52 cisco-rtr
```

**4. Launch Honeyd** on the honeypot-facing interface (replace `eth0` and the IP range):
```bash
$ sudo honeyd -d -f ~/neurotrap/honeypots/honeyd/honeyd.conf \
    -p ~/neurotrap/honeypots/honeyd/nmap.prints \
    -i eth0 10.0.0.50-10.0.0.52
```
> `-d` runs in foreground with debug so you can watch ARP/connection events. Once happy, drop `-d` to daemonize.

**5. Verify the virtual hosts answer.** From the attacker VM:
```bash
🔴 ON ATTACKER VM:
$ ping -c2 10.0.0.50
$ nmap -O 10.0.0.50 10.0.0.51 10.0.0.52
```
> **Expected result:** Each IP responds; nmap reports *different* OS guesses per host (Linux / Windows / Cisco), proving the personalities work.

**6. (Optional) GNS3/EVE-NG topology.** Install GNS3 on a workstation, create a topology with: a cloud node (your lab LAN) → a switch → the honeypot host (Cowrie+Dionaea) and the Honeyd virtual subnet → an attacker VM (Kali). Export the topology image — you'll embed it in the Day 7 diagram. If GNS3 is impractical on the server, draw the same topology in diagrams.net and save to `docs/network-diagram.png`.

### Expected results (end of Day 6)
- Honeyd answers for 3+ virtual IPs with distinct OS fingerprints.
- A documented topology (GNS3 export or diagram) ready for Day 7.

### Validation checklist — Day 6
- [ ] `nmap -O` shows different OS per Honeyd IP.
- [ ] Honeyd debug output shows connection attempts from your nmap.
- [ ] `honeyd.conf` committed.
- [ ] Topology drafted in `docs/`.

### Troubleshooting — Day 6
- **`honeyd` package not in apt.** On 22.04 it may be in `universe`: `sudo add-apt-repository universe && sudo apt update && sudo apt install honeyd`. If unavailable, build from source or run Honeyd in a 20.04 LXC/VM — document the deviation.
- **Virtual IPs don't respond.** Another device owns those IPs, or `farpd`/`arpd` isn't handling ARP. Install `farpd`: `sudo apt install farpd && sudo farpd -i eth0 '10.0.0.50-10.0.0.52'` running alongside Honeyd.
- **nmap reports all hosts identical.** Wrong/old `nmap.prints`. Point `-p` at a current fingerprint file.
- **Conflicts with the real host IP.** Never bind Honeyd to the host's own IP; only to free addresses.

---

## Day 7 — Verification & Network Diagram

**Estimated time:** 3–4 hours

### Objectives
- Run a full `nmap` scan against all honeypot ports and confirm each service answers.
- Simulate an SSH brute-force with **Hydra** and confirm Cowrie logs every attempt.
- Produce the **network architecture diagram** (Week 1 deliverable + needed for Week 6 docs).
- Run the full Week 1 deliverables gate.

### Files/folders to work on
- `~/neurotrap/scripts/simulate_attack.sh`
- `~/neurotrap/docs/network-diagram.png`
- `~/neurotrap/docs/architecture.md`

### Step-by-step

**1. Confirm the whole stack is up.**
```bash
$ cd ~/neurotrap && docker compose ps
```
> **Expected result:** `cadn-cowrie` and `cadn-dionaea` both `Up`. Honeyd running on the host (`pgrep -a honeyd`).

**2. Full nmap sweep from the attacker VM.**
```bash
🔴 ON ATTACKER VM:
$ nmap -sV -p 21,22,23,80,445,3306,5060 <HONEYPOT_VM_IP>
$ nmap -O 10.0.0.50 10.0.0.51 10.0.0.52        # Honeyd virtual hosts
```
> **Expected result:** Ports 22/23 show SSH/Telnet (Cowrie), 21/80/445/3306 show FTP/HTTP/SMB/MySQL (Dionaea). This is the raw scan we'll *detect* in Week 2.

**3. Simulate SSH brute-force with Hydra against Cowrie.** Create a small wordlist and run Hydra:
```bash
🔴 ON ATTACKER VM:
$ sudo apt -y install hydra
$ printf 'root\nadmin\nubuntu\noracle\n' > users.txt
$ printf '123456\npassword\nadmin\nletmein\nroot\n' > pass.txt
$ hydra -L users.txt -P pass.txt ssh://<HONEYPOT_VM_IP> -t 4 -f
```
> **Expected result:** Hydra reports one or more "valid" logins (the weak creds in `userdb.txt`). Every attempt — success and failure — is logged by Cowrie.

**4. Verify Cowrie logged the brute-force.**
```bash
# on HONEYPOT host:
$ jq -c 'select(.eventid|test("cowrie.login")) | {eventid, src_ip, username, password}' \
    ~/neurotrap/honeypots/cowrie/var/log/cowrie/cowrie.json | tail -n 20
$ echo "Total login events:"; grep -c 'cowrie.login' ~/neurotrap/honeypots/cowrie/var/log/cowrie/cowrie.json
```
> **Expected result:** A burst of `cowrie.login.failed` / `cowrie.login.success` events matching every Hydra attempt, all from the attacker IP.

**5. Save the attack simulation as a reusable script** (you'll reuse it in Week 2 Day 14 and Week 6):
```bash
$ vim ~/neurotrap/scripts/simulate_attack.sh
```
```bash
#!/usr/bin/env bash
# Usage: ./simulate_attack.sh <TARGET_IP>
set -euo pipefail
TARGET="${1:?Usage: simulate_attack.sh <TARGET_IP>}"
echo "[*] Port scan..."
nmap -sV -p 21,22,23,80,445,3306,5060 "$TARGET"
echo "[*] SSH brute-force..."
printf 'root\nadmin\nubuntu\noracle\n' > /tmp/u.txt
printf '123456\npassword\nadmin\nletmein\nroot\n' > /tmp/p.txt
hydra -L /tmp/u.txt -P /tmp/p.txt "ssh://$TARGET" -t 4 -f || true
echo "[*] HTTP probe..."
curl -s "http://$TARGET/index.php?id=1' OR '1'='1" -o /dev/null -w "%{http_code}\n"
echo "[*] Done."
```
```bash
$ chmod +x ~/neurotrap/scripts/simulate_attack.sh
```

**6. Build the network diagram.** In diagrams.net (or GNS3 export), draw:
- Internet / lab LAN → Honeypot Host
- Host networks: `honeypot-net` (Cowrie 22/23, Dionaea 21/80/445/3306/5060), `elk-net` (internal, Week 2 DB), `management-net`
- Honeyd virtual subnet (10.0.0.50–52)
- Attacker VM

Save as `docs/network-diagram.png` and write a one-page `docs/architecture.md` describing the five layers from the plan (Capture → Detection → Behavior → Deception → Response), noting that Weeks 1–2 implement Layer 1 (Capture) and Layer 2 (Detection).

### Week 1 Deliverables Gate

Run every check. **All must pass before Week 2.**

| # | Deliverable (from plan) | Command / Check | Pass when |
|---|---|---|---|
| 1 | Running Docker Compose stack | `docker compose ps` | All containers `Up`/healthy |
| 2 | Cowrie capturing SSH sessions | `grep -c cowrie.login cowrie.json` | Count grows on each login |
| 3 | Dionaea capturing malware requests | `jq . dionaea.json \| tail` | SMB + HTTP entries present |
| 4 | Network isolation verified | honeypot→mgmt ping | Fails (unreachable) |
| 5 | Git repo initialized | `git log --oneline` | Commits for Days 2–7, `.env` ignored |

```bash
# one-shot gate script:
$ cd ~/neurotrap
$ docker compose ps
$ grep -c cowrie.login honeypots/cowrie/var/log/cowrie/cowrie.json
$ tail -n 5 honeypots/dionaea/var/log/dionaea.json
$ git status --porcelain | grep -q '.env$' && echo "FAIL: .env tracked" || echo "OK: .env ignored"
```

### Validation checklist — Day 7
- [ ] nmap sees all expected open ports.
- [ ] Hydra run produces login events in `cowrie.json`.
- [ ] `simulate_attack.sh` runs end-to-end.
- [ ] `docs/network-diagram.png` and `docs/architecture.md` exist.
- [ ] **Week 1 Deliverables Gate: all 5 rows PASS.**
- [ ] Snapshot `day7-week1-complete` taken; committed: `git add scripts docs && git commit -m "Day 7: verification, attack simulation, network diagram — Week 1 complete"`.

### Troubleshooting — Day 7
- **Hydra reports 0 valid even with weak creds.** `userdb.txt` mismatch, or Hydra hit the management port. Target the honeypot IP on **22**, and confirm creds match `userdb.txt` exactly.
- **nmap shows ports closed.** Container down or UFW blocking. `docker compose ps` + `sudo ufw status`.
- **Logs empty after attacks.** Wrong path/ownership — re-check Day 4 ownership fix and that you're tailing the host-mounted path.

---

# WEEK 2 — Detection & Traffic Analysis

**Week goal (from the plan):** A real-time detection layer that watches honeypot traffic, flags port scans / brute-force / protocol anomalies in under 5 seconds, normalizes every source into one JSON event schema, stores events in a queryable database indexed by IP and time, ingests Zeek connection logs, and is tuned to a false-positive rate under 5%.

**Setup for the whole week — Python environment.** Do this once on Day 8:
```bash
$ cd ~/neurotrap/detection
$ python3 -m venv ~/neurotrap/.venv
$ source ~/neurotrap/.venv/bin/activate
$ cat > requirements.txt << 'EOF'
scapy==2.5.0
pydantic==2.7.1
pymongo==4.7.2
python-dateutil==2.9.0
EOF
$ pip install -r requirements.txt
```
> Activate the venv (`source ~/neurotrap/.venv/bin/activate`) at the start of every Week 2 session.

---

## Day 8 — Scapy Packet Monitor (Part 1: Capture & Port-Scan Detection)

**Estimated time:** 5–6 hours

### Objectives
- Build `detection/packet_monitor.py` that sniffs packets on the honeypot interface using Scapy.
- Implement the first detector: **port scan** — more than **10 distinct destination ports from one source IP within 5 seconds** (exact threshold from the plan).
- Print structured detections to stdout (DB wiring comes Day 11–12).

### Files/folders to work on
- `~/neurotrap/detection/packet_monitor.py`
- `~/neurotrap/detection/detectors/port_scan.py`

### Step-by-step

**1. Identify the capture interface.**
```bash
$ ip -brief addr     # find the iface facing honeypot traffic, e.g. eth0
```

**2. Write the port-scan detector.** This uses a sliding 5-second window per source IP.
```bash
$ vim ~/neurotrap/detection/detectors/port_scan.py
```
```python
"""Port-scan detector: >10 distinct dst ports from one src IP within 5 seconds."""
import time
from collections import defaultdict, deque

PORT_SCAN_WINDOW = 5         # seconds
PORT_SCAN_THRESHOLD = 10     # distinct ports

class PortScanDetector:
    def __init__(self):
        # src_ip -> deque[(timestamp, dst_port)]
        self._seen = defaultdict(deque)
        self._alerted = {}   # src_ip -> last alert time (debounce)

    def observe(self, src_ip: str, dst_port: int, now: float = None):
        """Return a dict describing a detection, or None."""
        now = now or time.time()
        dq = self._seen[src_ip]
        dq.append((now, dst_port))
        # evict entries older than the window
        while dq and now - dq[0][0] > PORT_SCAN_WINDOW:
            dq.popleft()
        distinct_ports = {p for _, p in dq}
        if len(distinct_ports) > PORT_SCAN_THRESHOLD:
            # debounce: at most one alert per src per window
            if now - self._alerted.get(src_ip, 0) > PORT_SCAN_WINDOW:
                self._alerted[src_ip] = now
                return {
                    "attack_type": "port_scan",
                    "severity": "medium",
                    "src_ip": src_ip,
                    "dst_port": dst_port,
                    "detail": f"{len(distinct_ports)} ports in {PORT_SCAN_WINDOW}s",
                    "ports": sorted(distinct_ports),
                }
        return None
```

**3. Write the packet monitor that drives the detector.**
```bash
$ vim ~/neurotrap/detection/packet_monitor.py
```
```python
#!/usr/bin/env python3
"""CADN Scapy packet monitor. Sniffs the honeypot interface and runs detectors."""
import argparse
import json
import time
from datetime import datetime, timezone

from scapy.all import sniff, TCP, IP, UDP
from detectors.port_scan import PortScanDetector

port_scan = PortScanDetector()

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def emit(detection: dict):
    """For now, print as JSON. Day 11 replaces this with pipeline ingestion."""
    detection["timestamp"] = now_iso()
    print(json.dumps(detection), flush=True)

def handle(pkt):
    if IP not in pkt:
        return
    src = pkt[IP].src
    if TCP in pkt:
        dport = int(pkt[TCP].dport)
    elif UDP in pkt:
        dport = int(pkt[UDP].dport)
    else:
        return
    d = port_scan.observe(src, dport)
    if d:
        emit(d)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--iface", required=True, help="capture interface, e.g. eth0")
    ap.add_argument("-f", "--filter", default="tcp or udp", help="BPF filter")
    args = ap.parse_args()
    print(f"[*] CADN monitor on {args.iface} filter='{args.filter}'", flush=True)
    sniff(iface=args.iface, filter=args.filter, prn=handle, store=False)

if __name__ == "__main__":
    main()
```

**4. Run it (needs root for raw sockets).**
```bash
$ cd ~/neurotrap/detection
$ sudo ~/neurotrap/.venv/bin/python packet_monitor.py -i eth0
```

**5. Trigger a port scan from the attacker VM and watch detections.**
```bash
🔴 ON ATTACKER VM:
$ nmap -p 1-1000 <HONEYPOT_VM_IP>      # scans far more than 10 ports
```
> **Expected result:** Within ~5 seconds the monitor prints a JSON line: `{"attack_type": "port_scan", "src_ip": "<attacker>", "detail": "N ports in 5s", ...}`.

### Validation checklist — Day 8
- [ ] `packet_monitor.py` runs without error and prints the startup banner.
- [ ] An nmap scan of >10 ports triggers exactly one `port_scan` detection per window (debounce works).
- [ ] Detection JSON contains `attack_type`, `src_ip`, `dst_port`, `timestamp`.
- [ ] Detection fires in under 5 seconds (eyeball the clock during nmap).
- [ ] Committed: `git add detection && git commit -m "Day 8: Scapy monitor + port-scan detector"`.

### Troubleshooting — Day 8
- **`Operation not permitted` / no packets.** Scapy needs root. Run with `sudo` (using the venv's python path as shown).
- **`No module named scapy`.** You ran system python, not the venv. Use `~/neurotrap/.venv/bin/python`.
- **Nothing detected during nmap.** Wrong interface. Re-check `ip -brief addr`; in a NAT'd VM the honeypot traffic may arrive on a different iface. Test BPF with `sudo tcpdump -i eth0 tcp` first.
- **Too many alerts.** That's expected for a raw scan; the debounce limits to one per 5s window per IP. Tuning happens Day 14.

---

## Day 9 — Scapy Packet Monitor (Part 2: Brute-Force & Anomalies)

**Estimated time:** 5–6 hours

### Objectives
- Add the **brute-force detector**: more than **5 failed logins per minute** from one source (plan threshold). Because Scapy can't see inside encrypted SSH, brute-force is detected by **connection rate to auth ports** (22/23/21) corroborated by Cowrie's `login.failed` events.
- Add a **protocol-anomaly detector** (e.g., TCP flag combinations like NULL/FIN/Xmas scans, or traffic to closed/odd ports).
- Refactor detectors behind a common interface so Day 10's schema plugs in cleanly.

### Files/folders to work on
- `~/neurotrap/detection/detectors/brute_force.py`
- `~/neurotrap/detection/detectors/anomaly.py`
- `~/neurotrap/detection/packet_monitor.py` (wire in new detectors)

### Step-by-step

**1. Brute-force detector (connection-rate based).**
```bash
$ vim ~/neurotrap/detection/detectors/brute_force.py
```
```python
"""Brute-force detector: >5 auth-port connection attempts per minute from one src."""
import time
from collections import defaultdict, deque

BF_WINDOW = 60          # seconds
BF_THRESHOLD = 5        # attempts per window
AUTH_PORTS = {21, 22, 23, 3306}   # FTP, SSH, Telnet, MySQL

class BruteForceDetector:
    def __init__(self):
        self._hits = defaultdict(deque)   # src_ip -> deque[timestamps]
        self._alerted = {}

    def observe(self, src_ip, dst_port, is_syn, now=None):
        if dst_port not in AUTH_PORTS or not is_syn:
            return None
        now = now or time.time()
        dq = self._hits[src_ip]
        dq.append(now)
        while dq and now - dq[0] > BF_WINDOW:
            dq.popleft()
        if len(dq) > BF_THRESHOLD:
            if now - self._alerted.get(src_ip, 0) > BF_WINDOW:
                self._alerted[src_ip] = now
                return {
                    "attack_type": "brute_force",
                    "severity": "high",
                    "src_ip": src_ip,
                    "dst_port": dst_port,
                    "detail": f"{len(dq)} auth attempts in {BF_WINDOW}s",
                }
        return None
```

**2. Protocol-anomaly detector (suspicious TCP flag combos).**
```bash
$ vim ~/neurotrap/detection/detectors/anomaly.py
```
```python
"""Protocol-anomaly detector: NULL/FIN/Xmas scans and SYN+FIN combos."""
# TCP flag bits: FIN=0x01 SYN=0x02 RST=0x04 PSH=0x08 ACK=0x10 URG=0x20
def detect_flag_anomaly(src_ip, dst_port, flags: int):
    f = int(flags)
    label = None
    if f == 0x00:
        label = "null_scan"
    elif f == 0x01:
        label = "fin_scan"
    elif f & 0x01 and f & 0x02:           # SYN+FIN
        label = "syn_fin"
    elif f & 0x29 == 0x29:                # FIN+PSH+URG = Xmas
        label = "xmas_scan"
    if label:
        return {
            "attack_type": "protocol_anomaly",
            "severity": "medium",
            "src_ip": src_ip,
            "dst_port": dst_port,
            "detail": label,
        }
    return None
```

**3. Wire all three detectors into `packet_monitor.py`.** Update the imports and `handle()`:
```python
from detectors.port_scan import PortScanDetector
from detectors.brute_force import BruteForceDetector
from detectors.anomaly import detect_flag_anomaly

port_scan = PortScanDetector()
brute = BruteForceDetector()

def handle(pkt):
    if IP not in pkt or TCP not in pkt:
        return
    src = pkt[IP].src
    dport = int(pkt[TCP].dport)
    flags = int(pkt[TCP].flags)
    is_syn = bool(flags & 0x02) and not (flags & 0x10)   # SYN, not SYN-ACK

    for d in (
        port_scan.observe(src, dport),
        brute.observe(src, dport, is_syn),
        detect_flag_anomaly(src, dport, flags),
    ):
        if d:
            emit(d)
```

**4. Test each detector.**
```bash
# terminal A on HONEYPOT host:
$ sudo ~/neurotrap/.venv/bin/python ~/neurotrap/detection/packet_monitor.py -i eth0
```
```bash
🔴 ON ATTACKER VM:
$ hydra -L users.txt -P pass.txt ssh://<HONEYPOT_VM_IP> -t 4    # brute force -> 'brute_force'
$ sudo nmap -sN <HONEYPOT_VM_IP>      # NULL scan  -> 'protocol_anomaly: null_scan'
$ sudo nmap -sX <HONEYPOT_VM_IP>      # Xmas scan  -> 'protocol_anomaly: xmas_scan'
$ sudo nmap -sF <HONEYPOT_VM_IP>      # FIN scan   -> 'protocol_anomaly: fin_scan'
```
> **Expected result:** Monitor prints a `brute_force` detection during Hydra, and `protocol_anomaly` lines with the matching label for each nmap scan type.

**5. Cross-check brute force against Cowrie's authoritative failed-login count** (this is the corroboration step):
```bash
$ grep -c cowrie.login.failed ~/neurotrap/honeypots/cowrie/var/log/cowrie/cowrie.json
```

### Validation checklist — Day 9
- [ ] Hydra triggers a `brute_force` detection (>5 attempts/min).
- [ ] `nmap -sN/-sX/-sF` each trigger the correct `protocol_anomaly` label.
- [ ] Port-scan detector still works (regression).
- [ ] No crashes on non-TCP packets.
- [ ] Committed: `git add detection && git commit -m "Day 9: brute-force + protocol-anomaly detectors"`.

### Troubleshooting — Day 9
- **Brute-force never fires.** Hydra `-t` too low or SYN not detected. Lower `BF_THRESHOLD` temporarily to 2 to confirm wiring, then restore to 5.
- **Anomaly scans show nothing.** Some VMs/NAT drop crafted flag packets. Run nmap from a bridged attacker VM on the same L2 segment.
- **`pkt[TCP].flags` is a FlagValue not int.** `int(pkt[TCP].flags)` (already done above) normalizes it.

---

## Day 10 — Unified Alert Event Schema

**Estimated time:** 4–5 hours

### Objectives
- Define the **exact JSON event schema from the plan**: `{timestamp, src_ip, dst_port, attack_type, severity, raw_payload, honeypot_source}`.
- Build an `AlertEvent` class **with validation** (using Pydantic) so every event — whether from Scapy, Cowrie, Dionaea, or Zeek — is forced into the same shape.
- Make the Day 8–9 detectors emit `AlertEvent` objects.

### Files/folders to work on
- `~/neurotrap/detection/alert_event.py`
- `~/neurotrap/tests/test_detectors.py`

### Step-by-step

**1. Build the validating `AlertEvent` class.**
```bash
$ vim ~/neurotrap/detection/alert_event.py
```
```python
"""Unified CADN alert event schema with validation."""
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field, IPvAnyAddress, field_validator

class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class HoneypotSource(str, Enum):
    SCAPY = "scapy_monitor"
    COWRIE = "cowrie"
    DIONAEA = "dionaea"
    ZEEK = "zeek"

class AlertEvent(BaseModel):
    timestamp: str                       # ISO-8601 UTC
    src_ip: IPvAnyAddress
    dst_port: Optional[int] = Field(default=None, ge=0, le=65535)
    attack_type: str                     # port_scan | brute_force | protocol_anomaly | login | malware | connection
    severity: Severity
    raw_payload: Optional[str] = None    # original log line / packet summary
    honeypot_source: HoneypotSource
    detail: Optional[str] = None

    @field_validator("timestamp")
    @classmethod
    def _check_ts(cls, v):
        # raises if not parseable ISO-8601
        datetime.fromisoformat(v.replace("Z", "+00:00"))
        return v

    @classmethod
    def now_ts(cls) -> str:
        return datetime.now(timezone.utc).isoformat()

    def to_json(self) -> str:
        return self.model_dump_json()

    def to_dict(self) -> dict:
        d = self.model_dump()
        d["src_ip"] = str(d["src_ip"])
        d["severity"] = self.severity.value
        d["honeypot_source"] = self.honeypot_source.value
        return d
```

**2. Update the Scapy monitor's `emit()` to produce validated events.** In `packet_monitor.py`:
```python
from alert_event import AlertEvent, HoneypotSource

def emit(detection: dict):
    evt = AlertEvent(
        timestamp=AlertEvent.now_ts(),
        src_ip=detection["src_ip"],
        dst_port=detection.get("dst_port"),
        attack_type=detection["attack_type"],
        severity=detection["severity"],
        honeypot_source=HoneypotSource.SCAPY,
        detail=detection.get("detail"),
        raw_payload=detection.get("ports") and str(detection["ports"]) or None,
    )
    print(evt.to_json(), flush=True)
```

**3. Write unit tests for the schema + detectors.**
```bash
$ vim ~/neurotrap/tests/test_detectors.py
```
```python
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "detection"))
import pytest
from alert_event import AlertEvent, HoneypotSource, Severity
from detectors.port_scan import PortScanDetector
from detectors.brute_force import BruteForceDetector

def test_alert_event_valid():
    e = AlertEvent(timestamp=AlertEvent.now_ts(), src_ip="10.0.0.9", dst_port=22,
                   attack_type="brute_force", severity="high",
                   honeypot_source=HoneypotSource.SCAPY)
    assert str(e.src_ip) == "10.0.0.9"
    assert e.severity == Severity.HIGH

def test_alert_event_rejects_bad_ip():
    with pytest.raises(Exception):
        AlertEvent(timestamp=AlertEvent.now_ts(), src_ip="not-an-ip",
                   attack_type="x", severity="low", honeypot_source=HoneypotSource.SCAPY)

def test_alert_event_rejects_bad_port():
    with pytest.raises(Exception):
        AlertEvent(timestamp=AlertEvent.now_ts(), src_ip="10.0.0.9", dst_port=99999,
                   attack_type="x", severity="low", honeypot_source=HoneypotSource.SCAPY)

def test_port_scan_fires_over_threshold():
    d = PortScanDetector()
    res = None
    for p in range(1, 13):           # 12 distinct ports > 10
        res = d.observe("10.0.0.50", p, now=1000.0)
    assert res and res["attack_type"] == "port_scan"

def test_brute_force_fires():
    d = BruteForceDetector()
    res = None
    for i in range(7):               # 7 > 5 in window
        res = d.observe("10.0.0.51", 22, is_syn=True, now=1000.0 + i)
    assert res and res["attack_type"] == "brute_force"
```
Run them:
```bash
$ source ~/neurotrap/.venv/bin/activate
$ pip install pytest
$ cd ~/neurotrap && python -m pytest tests/ -v
```
> **Expected result:** All 5 tests pass. Bad IPs and out-of-range ports are rejected — proving validation works.

### Validation checklist — Day 10
- [ ] `AlertEvent` rejects invalid IPs and ports (tests prove it).
- [ ] Scapy monitor now emits schema-valid JSON (run nmap, pipe a line through `jq` and confirm all 7 fields present).
- [ ] `python -m pytest tests/ -v` → all green.
- [ ] Schema matches plan exactly: timestamp, src_ip, dst_port, attack_type, severity, raw_payload, honeypot_source.
- [ ] Committed: `git add detection tests && git commit -m "Day 10: validated AlertEvent schema + unit tests"`.

### Troubleshooting — Day 10
- **`pydantic` v1 vs v2 API errors.** This manual targets Pydantic v2 (`field_validator`, `model_dump_json`). Confirm `pip show pydantic` is 2.x; if v1, upgrade.
- **`IPvAnyAddress` import error.** It's in `pydantic` v2 core. Ensure `pip install pydantic==2.7.1`.
- **Tests can't import `detection` modules.** The `sys.path.insert` line handles it; run pytest from the repo root (`~/neurotrap`).

---

## Day 11 — Log Pipeline (Part 1: Collectors & Normalizers)

**Estimated time:** 5–6 hours

### Objectives
- Build collectors that **tail** each source: Cowrie JSON, Dionaea JSON, and the Scapy monitor's output.
- Build a `normalizer.py` that converts every native event into a unified `AlertEvent`.
- (DB write lands tomorrow; today, normalize and print.)

### Files/folders to work on
- `~/neurotrap/pipeline/collectors/cowrie_collector.py`
- `~/neurotrap/pipeline/collectors/dionaea_collector.py`
- `~/neurotrap/pipeline/normalizer.py`
- `~/neurotrap/pipeline/run_pipeline.py`

### Step-by-step

**1. Write the normalizer** — maps each source's native fields to `AlertEvent`.
```bash
$ vim ~/neurotrap/pipeline/normalizer.py
```
```python
"""Normalize native honeypot events into the unified AlertEvent schema."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "detection"))
from alert_event import AlertEvent, HoneypotSource

def _sev_for_cowrie(eventid: str) -> str:
    if eventid == "cowrie.login.success":
        return "high"
    if eventid == "cowrie.command.input":
        return "medium"
    if "file_download" in eventid:
        return "high"
    return "low"

def from_cowrie(line: dict):
    eid = line.get("eventid", "")
    if not line.get("src_ip"):
        return None
    return AlertEvent(
        timestamp=line.get("timestamp", AlertEvent.now_ts()),
        src_ip=line["src_ip"],
        dst_port=line.get("dst_port", 22),
        attack_type=eid.replace("cowrie.", ""),
        severity=_sev_for_cowrie(eid),
        raw_payload=line.get("input") or line.get("message"),
        honeypot_source=HoneypotSource.COWRIE,
        detail=eid,
    )

def from_dionaea(line: dict):
    src = line.get("remote_host") or line.get("src_ip")
    if not src:
        return None
    return AlertEvent(
        timestamp=line.get("timestamp", AlertEvent.now_ts()),
        src_ip=src,
        dst_port=line.get("local_port") or line.get("dst_port"),
        attack_type="connection",
        severity="medium",
        raw_payload=line.get("protocol") or str(line.get("connection")),
        honeypot_source=HoneypotSource.DIONAEA,
        detail=line.get("protocol"),
    )

def from_scapy(line: dict):
    # Scapy monitor already emits AlertEvent JSON — re-validate it.
    return AlertEvent(**line)
```

**2. Write a reusable JSON-tailer collector.**
```bash
$ vim ~/neurotrap/pipeline/collectors/cowrie_collector.py
```
```python
"""Tail a JSON-lines log file and yield parsed dicts (like `tail -f`)."""
import json, time, os

def tail_json(path: str):
    # wait for file to exist
    while not os.path.exists(path):
        time.sleep(1)
    with open(path, "r") as f:
        f.seek(0, os.SEEK_END)        # start at end; only new events
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.3)
                continue
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue
```
> Dionaea uses the same tailer; create `dionaea_collector.py` importing `tail_json` from here, or just reuse this function.

**3. Wire collectors + normalizer in `run_pipeline.py`** (print-only today; threads tail each source).
```bash
$ vim ~/neurotrap/pipeline/run_pipeline.py
```
```python
#!/usr/bin/env python3
import threading
from collectors.cowrie_collector import tail_json
import normalizer as N

COWRIE = "/home/cadn-admin/neurotrap/honeypots/cowrie/var/log/cowrie/cowrie.json"
DIONAEA = "/home/cadn-admin/neurotrap/honeypots/dionaea/var/log/dionaea.json"

def run(path, fn, name):
    print(f"[*] collector started: {name}", flush=True)
    for raw in tail_json(path):
        evt = fn(raw)
        if evt:
            print(evt.to_json(), flush=True)   # Day 12: write to DB instead

if __name__ == "__main__":
    threads = [
        threading.Thread(target=run, args=(COWRIE, N.from_cowrie, "cowrie"), daemon=True),
        threading.Thread(target=run, args=(DIONAEA, N.from_dionaea, "dionaea"), daemon=True),
    ]
    for t in threads: t.start()
    for t in threads: t.join()
```

**4. Run and verify normalization.**
```bash
$ source ~/neurotrap/.venv/bin/activate
$ cd ~/neurotrap/pipeline
$ python run_pipeline.py
```
In another terminal, generate traffic (`ssh root@<honeypot>` and run commands; `smbclient -L //<honeypot>`). Watch unified events stream out.
> **Expected result:** Cowrie logins/commands AND Dionaea connections appear as **identically-shaped** JSON with the 7 schema fields and the correct `honeypot_source`.

### Validation checklist — Day 11
- [ ] A live Cowrie login appears as a normalized event with `honeypot_source: cowrie`.
- [ ] A live Dionaea SMB connection appears with `honeypot_source: dionaea`.
- [ ] Every emitted line validates against `AlertEvent` (no crashes).
- [ ] Adjusted the hardcoded paths to your actual home dir.
- [ ] Committed: `git add pipeline && git commit -m "Day 11: collectors + normalizer (unified events)"`.

### Troubleshooting — Day 11
- **Collector prints nothing.** It starts at end-of-file (only new events). Generate fresh traffic, or temporarily remove the `f.seek(0, os.SEEK_END)` to replay history.
- **`KeyError`/validation error on Dionaea fields.** Field names vary by Dionaea version. `tail dionaea.json | jq` to see the real keys and adjust `from_dionaea`.
- **Path wrong.** Use absolute paths; `echo $HOME` to confirm your home directory.

---

## Day 12 — Log Pipeline (Part 2: Database & Indexing)

**Estimated time:** 5–6 hours

### Objectives
- Build `pipeline/db.py` that writes `AlertEvent`s to the event store.
- Support **both backends the plan names**: SQLite (default, zero-setup) and MongoDB (optional, via Docker on `elk-net`).
- Create **indexes on `src_ip` and `timestamp`** (explicit plan requirement) so events are queryable by IP, time, and attack type.
- Switch `run_pipeline.py` from printing to persisting.

### Files/folders to work on
- `~/neurotrap/pipeline/db.py`
- `~/neurotrap/pipeline/run_pipeline.py`
- `~/neurotrap/docker-compose.yml` (optional Mongo service)

### Step-by-step

**1. Write the DB layer with a SQLite default and a Mongo option.**
```bash
$ vim ~/neurotrap/pipeline/db.py
```
```python
"""Event store for CADN. Backend chosen via DB_BACKEND env (sqlite|mongodb)."""
import os, sqlite3, json
from datetime import datetime

BACKEND = os.environ.get("DB_BACKEND", "sqlite")

class EventStore:
    def __init__(self):
        if BACKEND == "mongodb":
            from pymongo import MongoClient, ASCENDING
            self.client = MongoClient(os.environ["MONGO_URI"])
            self.col = self.client.get_default_database()["events"]
            self.col.create_index([("src_ip", ASCENDING)])
            self.col.create_index([("timestamp", ASCENDING)])
            self.col.create_index([("attack_type", ASCENDING)])
            self._mode = "mongo"
        else:
            path = os.environ.get("SQLITE_PATH", os.path.expanduser("~/neurotrap/cadn.sqlite"))
            self.conn = sqlite3.connect(path, check_same_thread=False)
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_port INTEGER,
                    attack_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    raw_payload TEXT,
                    honeypot_source TEXT NOT NULL,
                    detail TEXT
                )""")
            # REQUIRED indexes (plan): src_ip and timestamp, plus attack_type
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_src_ip ON events(src_ip)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_ts ON events(timestamp)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_type ON events(attack_type)")
            self.conn.commit()
            self._mode = "sqlite"

    def write(self, event_dict: dict):
        if self._mode == "mongo":
            self.col.insert_one(event_dict)
        else:
            self.conn.execute(
                """INSERT INTO events
                   (timestamp,src_ip,dst_port,attack_type,severity,raw_payload,honeypot_source,detail)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (event_dict["timestamp"], event_dict["src_ip"], event_dict.get("dst_port"),
                 event_dict["attack_type"], event_dict["severity"], event_dict.get("raw_payload"),
                 event_dict["honeypot_source"], event_dict.get("detail")))
            self.conn.commit()
```

**2. Update `run_pipeline.py` to persist.** Replace the print line:
```python
from db import EventStore
store = EventStore()

def run(path, fn, name):
    print(f"[*] collector started: {name}", flush=True)
    for raw in tail_json(path):
        evt = fn(raw)
        if evt:
            store.write(evt.to_dict())
            print(f"[{name}] stored {evt.attack_type} from {evt.src_ip}", flush=True)
```

**3. (Optional) Add MongoDB on `elk-net`.** Append to compose:
```yaml
  mongo:
    image: mongo:7
    container_name: cadn-mongo
    restart: unless-stopped
    environment:
      MONGO_INITDB_ROOT_USERNAME: cadn
      MONGO_INITDB_ROOT_PASSWORD: ${MONGO_PASS:-CHANGE_ME}
      MONGO_INITDB_DATABASE: cadn
    volumes:
      - mongo-data:/data/db
    networks: [elk-net, management-net]    # reachable by pipeline, not by honeypots
volumes:
  mongo-data:
```
> Note: `mongo` sits on `elk-net` (internal) + `management-net`, NOT `honeypot-net` — so a compromised honeypot can't reach the database. This preserves the Day 2 isolation guarantee.

**4. Run the pipeline with SQLite (default) and generate events.**
```bash
$ source ~/neurotrap/.venv/bin/activate
$ export DB_BACKEND=sqlite
$ cd ~/neurotrap/pipeline && python run_pipeline.py
```
Generate traffic (SSH login + commands, smbclient). Then query the DB:
```bash
$ sqlite3 ~/neurotrap/cadn.sqlite "SELECT attack_type, src_ip, COUNT(*) FROM events GROUP BY 1,2;"
$ sqlite3 ~/neurotrap/cadn.sqlite "SELECT * FROM events WHERE src_ip='<attacker-ip>' ORDER BY timestamp DESC LIMIT 5;"
$ sqlite3 ~/neurotrap/cadn.sqlite ".indexes events"
```
> **Expected result:** Rows present; query-by-IP returns instantly; `.indexes` lists `idx_src_ip`, `idx_ts`, `idx_type`. This satisfies the plan's "Events queryable by IP, time, and attack type."

### Validation checklist — Day 12
- [ ] Pipeline writes live events to `cadn.sqlite`.
- [ ] `SELECT ... WHERE src_ip=...` returns matching rows.
- [ ] `SELECT ... WHERE attack_type=...` works.
- [ ] Indexes on `src_ip` and `timestamp` exist (`.indexes events`).
- [ ] (If used) Mongo container is on elk-net/management-net only, NOT honeypot-net.
- [ ] **Week 2 deliverable "Event database populated" → PASS.**
- [ ] Committed: `git add pipeline docker-compose.yml && git commit -m "Day 12: event store with indexed SQLite/Mongo backends"`.

### Troubleshooting — Day 12
- **`database is locked`.** SQLite + threads; the `check_same_thread=False` + per-write commit handles light load. For heavy load, switch `DB_BACKEND=mongodb`.
- **Mongo auth fails from pipeline.** `MONGO_URI` user/pass must match the compose env. The pipeline runs on the host, so connect via the mapped port or run the pipeline as a container on `management-net`.
- **No rows appear.** Collector started at end-of-file; generate new traffic after starting the pipeline.

---

## Day 13 — Zeek IDS Integration

**Estimated time:** 5–6 hours

### Objectives
- Deploy **Zeek** with **JSON log output** for `conn.log`, `http.log`, `ssh.log`, `dns.log` (exact logs named in the plan).
- Add a Zeek collector + normalizer so connection-level data enriches the event store.

### Files/folders to work on
- `~/neurotrap/zeek/local.zeek`
- `~/neurotrap/pipeline/collectors/zeek_collector.py`
- `~/neurotrap/pipeline/normalizer.py` (add `from_zeek`)

### Step-by-step

**1. Install Zeek** (official OBS repo for Ubuntu 22.04):
```bash
$ echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' \
    | sudo tee /etc/apt/sources.list.d/security:zeek.list
$ curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key \
    | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
$ sudo apt update && sudo apt -y install zeek
$ echo 'export PATH=/opt/zeek/bin:$PATH' >> ~/.bashrc && source ~/.bashrc
$ zeek --version
```

**2. Enable JSON logging.** Create the site policy:
```bash
$ vim ~/neurotrap/zeek/local.zeek
```
```
@load policy/tuning/json-logs.zeek
# Equivalent explicit toggle if the policy isn't present:
redef LogAscii::use_json = T;
redef LogAscii::json_timestamps = JSON::TS_ISO8601;
```

**3. Run Zeek live on the honeypot interface.**
```bash
$ sudo mkdir -p /opt/zeek/logs/cadn && cd /opt/zeek/logs/cadn
$ sudo /opt/zeek/bin/zeek -i eth0 ~/neurotrap/zeek/local.zeek
```
Generate traffic (nmap, ssh, curl) from the attacker VM, then check the JSON logs:
```bash
$ ls /opt/zeek/logs/cadn/
$ tail -n 3 /opt/zeek/logs/cadn/conn.log | jq '{ts, "id.orig_h", "id.resp_h", "id.resp_p", proto, service}'
$ tail -n 3 /opt/zeek/logs/cadn/ssh.log  | jq . 2>/dev/null
```
> **Expected result:** `conn.log`, `ssh.log`, `http.log`, `dns.log` exist and contain valid JSON lines (one JSON object per line) for the traffic you generated.

**4. Add a Zeek normalizer.** In `pipeline/normalizer.py`:
```python
def from_zeek_conn(line: dict):
    src = line.get("id.orig_h")
    if not src:
        return None
    return AlertEvent(
        timestamp=line.get("ts", AlertEvent.now_ts()),
        src_ip=src,
        dst_port=line.get("id.resp_p"),
        attack_type="connection",
        severity="low",
        raw_payload=f'{line.get("proto")}/{line.get("service")} bytes={line.get("orig_bytes")}',
        honeypot_source=HoneypotSource.ZEEK,
        detail=line.get("service") or line.get("proto"),
    )
```
> Note: Zeek's `ts` is a float epoch unless `json_timestamps = TS_ISO8601` is set (it is, per step 2). If you see floats, convert: `datetime.utcfromtimestamp(float(ts)).isoformat()`.

**5. Add a Zeek collector thread** in `run_pipeline.py`:
```python
ZEEK_CONN = "/opt/zeek/logs/cadn/conn.log"
# add to threads list:
threading.Thread(target=run, args=(ZEEK_CONN, N.from_zeek_conn, "zeek"), daemon=True)
```
Restart the pipeline; confirm Zeek events land in the DB:
```bash
$ sqlite3 ~/neurotrap/cadn.sqlite "SELECT honeypot_source, COUNT(*) FROM events GROUP BY 1;"
```
> **Expected result:** A `zeek` row appears alongside `cowrie` and `dionaea` — connection-level data now enriches every record.

### Validation checklist — Day 13
- [ ] `zeek --version` works; runs live on the interface.
- [ ] `conn.log`/`ssh.log`/`http.log`/`dns.log` are valid JSON.
- [ ] Zeek events flow into the event store (`honeypot_source = zeek` rows exist).
- [ ] **Week 2 deliverable "Zeek logs ingested" → PASS.**
- [ ] Committed: `git add zeek pipeline && git commit -m "Day 13: Zeek JSON logging + pipeline ingestion"`.

### Troubleshooting — Day 13
- **`json-logs.zeek` not found.** Use the explicit `redef LogAscii::use_json = T;` line instead (already in the config above).
- **Logs are TSV not JSON.** The `local.zeek` wasn't loaded. Pass it explicitly on the command line as shown.
- **Permission denied writing logs.** Run Zeek from a directory you own, or `sudo chown -R $USER /opt/zeek/logs/cadn`.
- **`ts` is a float in the DB.** Apply the `utcfromtimestamp` conversion in `from_zeek_conn`.
- **Zeek misses traffic in a VM.** Disable NIC offloading: `sudo ethtool -K eth0 gro off lro off`.

---

## Day 14 — Detection Tuning & Testing

**Estimated time:** 4–6 hours

### Objectives
- Run the full simulated attack suite (nmap scan + Hydra brute-force) and confirm every event flows: honeypot → detector → normalizer → DB.
- **Tune thresholds to keep the false-positive rate under 5%** (the plan's success criterion).
- Confirm detection latency is **under 5 seconds**.
- Run the Week 2 deliverables gate.

### Files/folders to work on
- `~/neurotrap/detection/detectors/*.py` (threshold tuning)
- `~/neurotrap/tests/test_normalizer.py`
- `~/neurotrap/scripts/measure_fp.py` (new)

### Step-by-step

**1. Baseline run — start everything.**
```bash
# Terminal 1: detection monitor
$ sudo ~/neurotrap/.venv/bin/python ~/neurotrap/detection/packet_monitor.py -i eth0
# Terminal 2: pipeline (cowrie + dionaea + zeek -> DB)
$ source ~/neurotrap/.venv/bin/activate && cd ~/neurotrap/pipeline && python run_pipeline.py
# Terminal 3: live Zeek
$ cd /opt/zeek/logs/cadn && sudo /opt/zeek/bin/zeek -i eth0 ~/neurotrap/zeek/local.zeek
```

**2. Fire the full attack simulation** from the attacker VM:
```bash
🔴 ON ATTACKER VM:
$ ~/neurotrap/scripts/simulate_attack.sh <HONEYPOT_VM_IP>
# (or run nmap + hydra + curl manually as on Day 7/9)
```

**3. Verify end-to-end flow in the DB.**
```bash
$ sqlite3 ~/neurotrap/cadn.sqlite \
  "SELECT attack_type, honeypot_source, COUNT(*) FROM events
   WHERE timestamp > datetime('now','-10 minutes') GROUP BY 1,2 ORDER BY 3 DESC;"
```
> **Expected result:** `port_scan` (scapy), `brute_force` (scapy), `login`/`command.input` (cowrie), `connection` (dionaea + zeek) — all from your attacker IP, all within the last few minutes.

**4. Measure detection latency.** Note the wall-clock time you launch nmap, then check the earliest `port_scan` timestamp:
```bash
$ sqlite3 ~/neurotrap/cadn.sqlite \
  "SELECT MIN(timestamp) FROM events WHERE attack_type='port_scan';"
```
> **Pass:** difference between scan start and first detection < 5 seconds.

**5. Measure false positives.** Generate *benign* traffic and confirm it does NOT trigger alerts. Write a tiny helper:
```bash
$ vim ~/neurotrap/scripts/measure_fp.py
```
```python
"""Crude FP estimate: count alerts during a benign-traffic window."""
import sqlite3, sys, os
db = os.path.expanduser("~/neurotrap/cadn.sqlite")
c = sqlite3.connect(db)
total = c.execute("SELECT COUNT(*) FROM events WHERE timestamp > datetime('now','-5 minutes')").fetchone()[0]
alerts = c.execute("""SELECT COUNT(*) FROM events
   WHERE attack_type IN ('port_scan','brute_force','protocol_anomaly')
   AND timestamp > datetime('now','-5 minutes')""").fetchone()[0]
print(f"events={total} alerts={alerts} fp_rate={ (alerts/total*100) if total else 0:.1f}%")
```
Generate benign traffic (normal web browsing to the HTTP port, a single legitimate SSH attempt, light pings) for 5 minutes, then:
```bash
🔴 ON ATTACKER VM (benign):
$ for i in $(seq 1 5); do curl -s http://<HONEYPOT_VM_IP>/ -o /dev/null; sleep 10; done
$ ssh oracle@<HONEYPOT_VM_IP>   # single normal login, then exit
```
```bash
$ python ~/neurotrap/scripts/measure_fp.py
```
> **Pass:** alert events from benign traffic < 5% of total events. If higher, tune (step 6).

**6. Tune thresholds if FP > 5%.**
- Port scan firing on normal multi-port apps → raise `PORT_SCAN_THRESHOLD` (10→15) or shorten window.
- Brute-force firing on legit reconnects → raise `BF_THRESHOLD` (5→8) or add a whitelist of known-good IPs.
- Anomaly noise from middleboxes → restrict `detect_flag_anomaly` to only `null_scan`/`xmas_scan`.
Re-run the test after each change. Document the final thresholds in `docs/architecture.md`.

**7. Add a normalizer regression test.**
```bash
$ vim ~/neurotrap/tests/test_normalizer.py
```
```python
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pipeline"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "detection"))
import normalizer as N

def test_cowrie_login_normalizes():
    raw = {"eventid":"cowrie.login.success","src_ip":"10.0.0.9",
           "timestamp":"2026-01-01T00:00:00+00:00","username":"root","password":"123456"}
    e = N.from_cowrie(raw)
    assert e.honeypot_source.value == "cowrie"
    assert e.severity.value == "high"

def test_dionaea_connection_normalizes():
    raw = {"remote_host":"10.0.0.9","local_port":445,"protocol":"smbd",
           "timestamp":"2026-01-01T00:00:00+00:00"}
    e = N.from_dionaea(raw)
    assert e.honeypot_source.value == "dionaea"
    assert e.dst_port == 445
```
```bash
$ cd ~/neurotrap && python -m pytest tests/ -v
```

### Week 2 Deliverables Gate

| # | Deliverable (from plan) | Check | Pass when |
|---|---|---|---|
| 1 | Packet monitor running | nmap → DB | port_scan/brute_force detected < 5s |
| 2 | Unified event schema | `jq` any event | all 7 fields, valid for every source |
| 3 | Event database populated | SQL query by IP/time/type | returns correct rows fast (indexed) |
| 4 | Zeek logs ingested | `GROUP BY honeypot_source` | `zeek` rows present |
| 5 | Detection accuracy tested | `measure_fp.py` | false-positive rate < 5% |

### Validation checklist — Day 14
- [ ] Full simulated attack produces events from all sources in the DB.
- [ ] Port-scan/brute-force detected in under 5 seconds.
- [ ] Benign traffic yields < 5% false-positive rate.
- [ ] Final thresholds documented in `docs/architecture.md`.
- [ ] `python -m pytest tests/ -v` → all green.
- [ ] **Week 2 Deliverables Gate: all 5 rows PASS.**
- [ ] Snapshot `day14-week2-complete`; committed and tagged: `git add -A && git commit -m "Day 14: detection tuning, E2E test, FP<5% — Week 2 complete" && git tag week2-complete`.

### Troubleshooting — Day 14
- **Events appear in logs but not in DB.** The pipeline collector for that source isn't running or its path is wrong. Confirm all three collector threads print "collector started".
- **Latency > 5s.** Scapy is CPU-bound under heavy scan; narrow the BPF filter (`tcp and not port 2222`) and give the VM more CPU.
- **FP rate stuck high.** Your "benign" traffic actually looks like a scan (e.g., a vuln scanner). Use genuinely normal traffic, and whitelist your own admin IP in the detectors.
- **pytest import errors.** Run from repo root; both `sys.path.insert` lines must be present.

---

# Appendix A — Master Troubleshooting Index

| Symptom | Likely cause | Fix | Day |
|---|---|---|---|
| Locked out of SSH after port change | sshd not restarted / UFW | VM console → fix `sshd_config` → restart ssh | 1 |
| `ssh -p 22` still hits real shell | OpenSSH still on 22 | Set `Port 2222`, restart ssh | 1 |
| `permission denied /var/run/docker.sock` | user not in docker group | `newgrp docker` or re-login | 2 |
| Subnet overlap on `compose up` | network conflict | change subnets to free range | 2 |
| Honeypot can reach management net | container on 2 nets | one network per service | 2 |
| Cowrie login always rejected | `userdb.txt` not mounted/format | check format `user:0:pass` | 3 |
| No `cowrie.json` | JSON output off / perms | enable `[output_jsonlog]`, chown 999:999 | 4 |
| Port 22 "in use" by Cowrie | host sshd on 22 | move mgmt ssh to 2222 | 4 |
| No `dionaea.json` | ihandler off / perms | enable `log_json` ihandler | 5 |
| Port 80/3306 "in use" | host apache/mysql | disable host services | 5 |
| Honeyd IPs silent | ARP not handled | run `farpd` alongside | 6 |
| Hydra finds 0 valid creds | wrong port/creds | target port 22, match userdb | 7 |
| Scapy: no packets | not root / wrong iface | `sudo`, check `ip -brief addr` | 8 |
| `No module named scapy` | wrong python | use `.venv/bin/python` | 8 |
| Brute-force never fires | threshold/SYN detection | lower threshold to confirm wiring | 9 |
| Pydantic API errors | v1 vs v2 | install `pydantic==2.7.1` | 10 |
| Collector prints nothing | starts at EOF | generate new traffic | 11 |
| `database is locked` | SQLite + threads | switch to MongoDB backend | 12 |
| Zeek logs are TSV | `local.zeek` not loaded | pass it on CLI, use `use_json=T` | 13 |
| Zeek `ts` is float | TS format | `utcfromtimestamp` conversion | 13 |
| Detection latency > 5s | Scapy CPU bound | narrow BPF, add CPU | 14 |
| FP rate > 5% | thresholds too tight | raise thresholds, whitelist admin IP | 14 |

# Appendix B — Daily Git Commit Checklist

Commit at the end of every day. Never commit `.env`, logs, `*.pcap`, or `*.sqlite` (all gitignored).

```bash
Day 2  : "project skeleton, three isolated docker networks"
Day 3-4: "Cowrie SSH/Telnet honeypot with JSON logging"
Day 5  : "Dionaea multi-protocol collector with JSON logging"
Day 6  : "Honeyd virtual subnet with OS personalities"
Day 7  : "verification, attack simulation, network diagram — Week 1 complete"
Day 8  : "Scapy monitor + port-scan detector"
Day 9  : "brute-force + protocol-anomaly detectors"
Day 10 : "validated AlertEvent schema + unit tests"
Day 11 : "collectors + normalizer (unified events)"
Day 12 : "event store with indexed SQLite/Mongo backends"
Day 13 : "Zeek JSON logging + pipeline ingestion"
Day 14 : "detection tuning, E2E test, FP<5% — Week 2 complete" (+ tag week2-complete)
```

# Appendix C — Quick Command Reference Card

**Stack control**
```bash
cd ~/neurotrap && docker compose up -d        # start honeypots
docker compose ps                              # health
docker compose logs -f cadn-cowrie             # follow cowrie
docker compose down                            # stop
```

**Live monitoring**
```bash
source ~/neurotrap/.venv/bin/activate
sudo ~/neurotrap/.venv/bin/python ~/neurotrap/detection/packet_monitor.py -i eth0
cd ~/neurotrap/pipeline && python run_pipeline.py
sudo /opt/zeek/bin/zeek -i eth0 ~/neurotrap/zeek/local.zeek
```

**Reading logs**
```bash
tail -f honeypots/cowrie/var/log/cowrie/cowrie.json | jq '{eventid,src_ip,input}'
tail -f honeypots/dionaea/var/log/dionaea.json | jq .
grep -c cowrie.login honeypots/cowrie/var/log/cowrie/cowrie.json
```

**Querying the event DB**
```bash
sqlite3 ~/neurotrap/cadn.sqlite "SELECT attack_type,COUNT(*) FROM events GROUP BY 1;"
sqlite3 ~/neurotrap/cadn.sqlite "SELECT * FROM events WHERE src_ip='X' ORDER BY timestamp DESC LIMIT 10;"
sqlite3 ~/neurotrap/cadn.sqlite ".indexes events"
```

**Attack simulation (from attacker VM)**
```bash
nmap -sV -p 21,22,23,80,445,3306,5060 <TARGET>      # service scan
nmap -p 1-1000 <TARGET>                              # port scan -> triggers detector
hydra -L users.txt -P pass.txt ssh://<TARGET> -t 4   # brute force
nmap -sN <TARGET>; nmap -sX <TARGET>; nmap -sF <TARGET>   # anomaly scans
~/neurotrap/scripts/simulate_attack.sh <TARGET>      # all of the above
```

**Validation gates**
```bash
# Week 1: stack + capture + isolation + git
docker compose ps && grep -c cowrie.login honeypots/cowrie/var/log/cowrie/cowrie.json
# Week 2: full flow + FP rate
python ~/neurotrap/scripts/measure_fp.py
cd ~/neurotrap && python -m pytest tests/ -v
```

---

## What comes after Day 14

You now have Layers 1–2 (Capture + Detection) of the five-layer CADN architecture, producing a clean, validated, indexed event stream. **Week 3** consumes exactly this stream: it engineers features from the Cowrie command sequences you're now capturing and trains the attacker-classification model. Because every event already conforms to the unified `AlertEvent` schema and is queryable by `src_ip` and `timestamp`, the behavior-analysis engine can pull per-attacker session histories with a single indexed query — which is precisely why the schema and indexing work on Days 10–12 mattered.

*— End of Weeks 1–2 Execution Manual —*
