"""MITRE ATT&CK (Enterprise) technique map for shell-command TTP extraction.

Each rule maps a regex over a command line to an ATT&CK technique. Keep IDs and
names aligned with attack.mitre.org. ``weight`` (0-1) feeds the threat score —
higher = more severe / later-stage. Used by :mod:`behavior.ttp_extractor`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List


@dataclass(frozen=True)
class TechniqueRule:
    technique_id: str
    name: str
    tactic: str
    pattern: re.Pattern
    weight: float = 0.4


def _r(pat: str) -> re.Pattern:
    return re.compile(pat, re.IGNORECASE)


# Order matters only for readability; extraction dedups by technique_id.
RULES: List[TechniqueRule] = [
    # --- Reconnaissance / Discovery ---
    TechniqueRule("T1082", "System Information Discovery", "Discovery",
                  _r(r"\b(uname|lscpu|cat\s+/proc/cpuinfo|cat\s+/etc/issue|hostnamectl)\b"), 0.2),
    TechniqueRule("T1033", "System Owner/User Discovery", "Discovery",
                  _r(r"\b(whoami|\bid\b|\bw\b|\blast\b|who\b)\b"), 0.2),
    TechniqueRule("T1057", "Process Discovery", "Discovery",
                  _r(r"\b(ps\s|top\b|htop\b)"), 0.2),
    TechniqueRule("T1016", "System Network Configuration Discovery", "Discovery",
                  _r(r"\b(ifconfig|ip\s+a|ip\s+addr|netstat|ss\s|arp\b|route\b)"), 0.2),
    TechniqueRule("T1046", "Network Service Discovery", "Discovery",
                  _r(r"\b(nmap|masscan|for\s+i\s+in\s+\$\(seq)"), 0.45),

    # --- Credential Access ---
    TechniqueRule("T1003.008", "OS Credential Dumping: /etc/passwd and /etc/shadow",
                  "Credential Access",
                  _r(r"(cat|less|head|tail|cp)\s+/etc/(shadow|passwd)"), 0.8),
    TechniqueRule("T1552.001", "Unsecured Credentials: Credentials In Files",
                  "Credential Access",
                  _r(r"(\.aws/credentials|\.env\b|wp-config\.php|id_rsa|\.pgpass|"
                     r"grep\s+-?r?i?\s*password)"), 0.75),
    TechniqueRule("T1552.004", "Unsecured Credentials: Private Keys",
                  "Credential Access",
                  _r(r"(id_rsa|id_dsa|\.ssh/.*key|-----BEGIN .*PRIVATE KEY)"), 0.75),

    # --- Execution / Ingress ---
    TechniqueRule("T1105", "Ingress Tool Transfer", "Command and Control",
                  _r(r"\b(wget|curl|tftp|ftpget|scp)\b"), 0.5),
    TechniqueRule("T1059.004", "Command and Scripting Interpreter: Unix Shell",
                  "Execution",
                  _r(r"(\|\s*(sh|bash)\b|;\s*(sh|bash)\b|\bsh\s+-c\b|bash\s+-c)"), 0.55),
    TechniqueRule("T1140", "Deobfuscate/Decode Files or Information", "Defense Evasion",
                  _r(r"\bbase64\s+(-d|--decode)\b|\bxxd\s+-r"), 0.5),

    # --- Persistence ---
    TechniqueRule("T1053.003", "Scheduled Task/Job: Cron", "Persistence",
                  _r(r"\bcrontab\b|/etc/cron|/etc/rc\.local"), 0.7),
    TechniqueRule("T1098.004", "Account Manipulation: SSH Authorized Keys",
                  "Persistence",
                  _r(r"authorized_keys"), 0.7),
    TechniqueRule("T1136.001", "Create Account: Local Account", "Persistence",
                  _r(r"\b(useradd|adduser)\b|\bpasswd\s+\w"), 0.6),

    # --- Defense Evasion ---
    TechniqueRule("T1222.002", "File and Directory Permissions Modification: Linux",
                  "Defense Evasion",
                  _r(r"\bchmod\s+([0-7]{3,4}|\+x)|\bchattr\b"), 0.45),
    TechniqueRule("T1070.003", "Indicator Removal: Clear Command History",
                  "Defense Evasion",
                  _r(r"history\s+-c|>\s*~?/?\.bash_history|unset\s+HISTFILE|rm\s+.*bash_history"), 0.55),
    TechniqueRule("T1562.004", "Impair Defenses: Disable or Modify System Firewall",
                  "Defense Evasion",
                  _r(r"\biptables\s+-F\b|ufw\s+disable|systemctl\s+stop\s+firewalld"), 0.6),

    # --- Lateral Movement ---
    TechniqueRule("T1021.004", "Remote Services: SSH", "Lateral Movement",
                  _r(r"\bssh\s+\S+@|\bscp\s+\S+@|known_hosts"), 0.7),

    # --- Impact ---
    TechniqueRule("T1496", "Resource Hijacking", "Impact",
                  _r(r"\b(xmrig|minerd|cpuminer)\b|stratum\+tcp|pool\.(minexmr|nanopool)"), 0.85),
    TechniqueRule("T1485", "Data Destruction", "Impact",
                  _r(r"\brm\s+-rf\s+/(?!tmp)|\bdd\s+if=/dev/zero|mkfs\b|shred\b"), 0.7),

    # --- C2 ---
    TechniqueRule("T1095", "Non-Application Layer Protocol", "Command and Control",
                  _r(r"\b(nc|ncat|netcat)\s+.*\b\d{2,5}\b|/dev/tcp/"), 0.6),
]
