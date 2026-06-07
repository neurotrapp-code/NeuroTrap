"""Day 15-16 — Feature engineering.

Group raw Cowrie JSON events into :class:`Session` objects and turn each session
into a fixed-length numeric feature vector for the intent classifier.

Features = a small set of behavioural aggregates (duration, login activity,
downloads, sensitive-file reads, outbound connections ...) concatenated with a
**bag-of-commands** count vector over a fixed attacker-command vocabulary.

Stdlib + numpy only, so it runs anywhere the rest of the detection layer does.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional

import numpy as np

# ---------------------------------------------------------------------------
# Vocabulary & lexicons
# ---------------------------------------------------------------------------
# Bag-of-commands vocabulary: the base command (argv[0]) of each shell input is
# mapped onto this list. Anything outside the vocabulary is bucketed as "other".
COMMAND_VOCAB: List[str] = [
    "wget", "curl", "tftp", "ftpget", "scp",          # ingress / transfer
    "chmod", "chown", "chattr",                        # execution prep
    "cat", "head", "tail", "less", "more", "grep",     # file reads
    "ls", "cd", "pwd", "find", "locate",               # navigation / discovery
    "uname", "whoami", "id", "hostname", "w", "last",  # host discovery
    "ps", "top", "netstat", "ss", "ifconfig", "ip",    # process / net discovery
    "nproc", "lscpu", "free", "df", "lsblk",           # resource discovery
    "crontab", "systemctl", "service",                 # persistence / services
    "ssh", "telnet", "nc", "ncat", "nmap",             # lateral / pivot
    "useradd", "adduser", "passwd",                    # account manipulation
    "apt", "apt-get", "yum", "dnf", "pip", "pip3",     # package ops
    "python", "python3", "perl", "php", "sh", "bash",  # interpreters
    "echo", "printf", "export", "base64", "xxd",       # encode / write
    "rm", "kill", "pkill", "iptables", "history",      # defense evasion / impact
    "xmrig", "minerd", "cpuminer", "stratum",          # cryptomining
    "busybox", "wget.sh", "tor", "screen", "tmux",     # bot / persistence misc
]
_VOCAB_INDEX = {c: i for i, c in enumerate(COMMAND_VOCAB)}

# Lexicons used by the aggregate features below.
_RECON_CMDS = {
    "uname", "whoami", "id", "hostname", "w", "last", "ps", "top", "netstat",
    "ss", "ifconfig", "ip", "nproc", "lscpu", "free", "df", "lsblk", "ls", "cat",
}
_DANGEROUS_CMDS = {"rm", "kill", "pkill", "iptables", "dd", "mkfs", "shred"}
_PKG_CMDS = {"apt", "apt-get", "yum", "dnf", "pip", "pip3"}
_MINER_TOKENS = ("xmrig", "minerd", "cpuminer", "stratum", "monero", "nanopool")

# Substrings that, when read/touched, indicate credential or secret access.
SENSITIVE_PATHS = (
    "/etc/shadow", "/etc/passwd", "/etc/sudoers", ".ssh", "authorized_keys",
    "id_rsa", "id_dsa", ".aws/credentials", ".aws/config", ".env",
    ".bash_history", ".mysql_history", ".pgpass", "credentials", "secrets",
    ".docker/config.json", ".kube/config", "wp-config.php",
)

# Aggregate (non bag-of-commands) feature names, in vector order.
_AGG_FEATURES: List[str] = [
    "num_commands",
    "num_unique_commands",
    "duration_s",
    "num_login_attempts",
    "login_success",
    "num_downloads",
    "num_download_hosts",
    "num_tcpip_requests",
    "num_sensitive_reads",
    "avg_cmd_len",
    "num_chmod",
    "has_crontab",
    "num_pkg_ops",
    "num_recon_cmds",
    "num_dangerous_cmds",
    "num_miner_tokens",
    "piped_to_shell",
    "cmds_per_second",
]

FEATURE_NAMES: List[str] = _AGG_FEATURES + [f"cmd::{c}" for c in COMMAND_VOCAB] + ["cmd::other"]


# ---------------------------------------------------------------------------
# Session model
# ---------------------------------------------------------------------------
@dataclass
class Session:
    """A single attacker SSH/Telnet session reconstructed from Cowrie events."""

    session_id: str
    src_ip: str = "0.0.0.0"
    start_ts: Optional[str] = None
    end_ts: Optional[str] = None
    duration_s: float = 0.0
    commands: List[str] = field(default_factory=list)
    login_attempts: int = 0
    login_success: bool = False
    usernames: List[str] = field(default_factory=list)
    passwords: List[str] = field(default_factory=list)
    downloads: List[str] = field(default_factory=list)        # URLs / files
    tcpip_requests: List[str] = field(default_factory=list)    # outbound connects

    # -- derived helpers ---------------------------------------------------
    def base_commands(self) -> List[str]:
        """argv[0] of each command, path- and ``sudo``-stripped, lower-cased."""
        out: List[str] = []
        for raw in self.commands:
            out.extend(_base_tokens(raw))
        return out

    def download_hosts(self) -> List[str]:
        hosts = []
        for url in self.downloads:
            m = re.search(r"https?://([^/\s:]+)", url)
            hosts.append(m.group(1) if m else url)
        return hosts

    def sensitive_reads(self) -> int:
        joined = " ".join(self.commands).lower()
        return sum(1 for p in SENSITIVE_PATHS if p in joined)


def _base_tokens(raw: str) -> List[str]:
    """Extract the meaningful base command(s) from one shell input line.

    Handles ``sudo``/``env`` prefixes, absolute paths (``/bin/ls`` -> ``ls``),
    ``./binary`` (-> ``binary``) and pipelines (``a | b``) so each stage counts.
    """
    tokens: List[str] = []
    for stage in re.split(r"[|;&]+|\b&&\b", raw):
        parts = stage.strip().split()
        if not parts:
            continue
        cmd = parts[0]
        # skip common wrappers to reach the real command
        while cmd in ("sudo", "env", "nohup", "time", "exec") and len(parts) > 1:
            parts = parts[1:]
            cmd = parts[0]
        cmd = cmd.split("/")[-1]          # /usr/bin/wget -> wget, ./xmrig -> xmrig
        cmd = cmd.lower()
        if cmd:
            tokens.append(cmd)
    return tokens


# ---------------------------------------------------------------------------
# Parsing raw Cowrie events -> sessions
# ---------------------------------------------------------------------------
def parse_sessions(events: Iterable[dict]) -> Dict[str, Session]:
    """Reconstruct sessions from a stream of Cowrie JSON event dicts.

    Events lacking a ``session`` id are grouped under their ``src_ip`` so that
    ad-hoc / synthetic data still produces one session per source.
    """
    sessions: Dict[str, Session] = {}
    for ev in events:
        eid = ev.get("eventid", "")
        sid = ev.get("session") or ev.get("src_ip") or "unknown"
        s = sessions.get(sid)
        if s is None:
            s = Session(session_id=sid, src_ip=ev.get("src_ip", "0.0.0.0"))
            sessions[sid] = s
        if ev.get("src_ip"):
            s.src_ip = ev["src_ip"]

        if eid == "cowrie.session.connect":
            s.start_ts = ev.get("timestamp", s.start_ts)
        elif eid in ("cowrie.login.success", "cowrie.login.failed"):
            s.login_attempts += 1
            if ev.get("username"):
                s.usernames.append(ev["username"])
            if ev.get("password"):
                s.passwords.append(ev["password"])
            if eid == "cowrie.login.success":
                s.login_success = True
        elif eid == "cowrie.command.input":
            if ev.get("input"):
                s.commands.append(ev["input"])
        elif eid in ("cowrie.session.file_download", "cowrie.session.file_upload"):
            s.downloads.append(ev.get("url") or ev.get("filename") or ev.get("outfile", ""))
        elif eid == "cowrie.direct-tcpip.request":
            dst = f'{ev.get("dst_ip","?")}:{ev.get("dst_port","?")}'
            s.tcpip_requests.append(dst)
        elif eid == "cowrie.session.closed":
            s.end_ts = ev.get("timestamp", s.end_ts)
            if ev.get("duration") is not None:
                try:
                    s.duration_s = float(ev["duration"])
                except (TypeError, ValueError):
                    pass
    return sessions


# ---------------------------------------------------------------------------
# Vectorisation
# ---------------------------------------------------------------------------
def vectorize(session: Session) -> np.ndarray:
    """Return the fixed-length feature vector for ``session`` (see FEATURE_NAMES)."""
    base = session.base_commands()
    n_cmds = len(base)
    uniq = len(set(base))
    chmod = base.count("chmod") + base.count("chown") + base.count("chattr")
    recon = sum(1 for c in base if c in _RECON_CMDS)
    dangerous = sum(1 for c in base if c in _DANGEROUS_CMDS)
    pkg = sum(1 for c in base if c in _PKG_CMDS)
    joined = " ".join(session.commands).lower()
    miner = sum(joined.count(t) for t in _MINER_TOKENS)
    has_cron = 1.0 if "crontab" in base or "/etc/cron" in joined else 0.0
    piped = 1.0 if re.search(r"(wget|curl)[^|]*\|\s*(sh|bash)", joined) else 0.0
    avg_len = float(np.mean([len(c) for c in session.commands])) if session.commands else 0.0
    dur = max(session.duration_s, 0.0)
    cps = (n_cmds / dur) if dur > 0 else float(n_cmds)   # commands per second

    agg = [
        n_cmds,
        uniq,
        dur,
        session.login_attempts,
        1.0 if session.login_success else 0.0,
        len(session.downloads),
        len(set(session.download_hosts())),
        len(session.tcpip_requests),
        session.sensitive_reads(),
        avg_len,
        chmod,
        has_cron,
        pkg,
        recon,
        dangerous,
        miner,
        piped,
        cps,
    ]

    bag = np.zeros(len(COMMAND_VOCAB) + 1, dtype=float)
    for c in base:
        idx = _VOCAB_INDEX.get(c)
        if idx is None:
            bag[-1] += 1          # "other"
        else:
            bag[idx] += 1

    return np.concatenate([np.asarray(agg, dtype=float), bag])


def feature_matrix(sessions: Iterable[Session]) -> np.ndarray:
    """Stack vectors for many sessions into a 2-D matrix (rows = sessions)."""
    rows = [vectorize(s) for s in sessions]
    if not rows:
        return np.empty((0, len(FEATURE_NAMES)), dtype=float)
    return np.vstack(rows)
