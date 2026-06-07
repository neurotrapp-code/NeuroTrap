"""Load environment templates from ``deception/templates/*.yaml``.

Uses PyYAML when present. If PyYAML is missing, falls back to a built-in copy of
the three templates so the engine still runs (and unit tests stay green) with
stdlib only.
"""
from __future__ import annotations

import os
from typing import Dict

_TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")

try:
    import yaml
    _HAVE_YAML = True
except Exception:                       # pragma: no cover
    _HAVE_YAML = False

# Minimal built-in fallback (keeps the engine usable without PyYAML/files).
_BUILTIN: Dict[str, dict] = {
    "beginner": {
        "name": "beginner", "os_banner": "Ubuntu 18.04.6 LTS",
        "ssh_banner": "SSH-2.0-OpenSSH_7.6p1", "ttl_seconds": 1800,
        "services": [{"proto": "ssh", "port": 2222, "version": "OpenSSH_7.6p1"},
                     {"proto": "http", "port": 8080, "version": "Apache/2.4.29"}],
        "credential_profile": {"count": 2, "weak": True},
        "filesystem_profile": "minimal",
        "decoy_data": {"aws_keys": False, "env_secrets": False, "fake_db": False,
                       "private_ssh_keys": False},
    },
    "bot": {
        "name": "bot", "os_banner": "Debian GNU/Linux 11",
        "ssh_banner": "SSH-2.0-OpenSSH_8.4p1", "ttl_seconds": 900,
        "services": [{"proto": "ssh", "port": 2222, "version": "OpenSSH_8.4p1"},
                     {"proto": "telnet", "port": 2323, "version": "BusyBox v1.31.1"},
                     {"proto": "http", "port": 8080, "version": "nginx/1.18.0"}],
        "credential_profile": {"count": 6, "weak": True, "common": True},
        "filesystem_profile": "iot",
        "decoy_data": {"aws_keys": False, "env_secrets": True, "fake_db": False,
                       "private_ssh_keys": False},
    },
    "advanced": {
        "name": "advanced", "os_banner": "Ubuntu 22.04.4 LTS",
        "ssh_banner": "SSH-2.0-OpenSSH_8.9p1", "ttl_seconds": 7200,
        "services": [{"proto": "ssh", "port": 2222, "version": "OpenSSH_8.9p1"},
                     {"proto": "http", "port": 8080, "version": "nginx/1.24.0"},
                     {"proto": "ftp", "port": 2121, "version": "vsftpd 3.0.5"},
                     {"proto": "mysql", "port": 33060, "version": "8.0.36"}],
        "credential_profile": {"count": 8, "weak": False},
        "filesystem_profile": "corporate",
        "decoy_data": {"aws_keys": True, "env_secrets": True, "fake_db": True,
                       "private_ssh_keys": True},
    },
}


def load_template(name: str) -> dict:
    """Return the template dict for ``name`` (beginner|bot|advanced)."""
    path = os.path.join(_TEMPLATE_DIR, f"{name}.yaml")
    if _HAVE_YAML and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    if name in _BUILTIN:
        return dict(_BUILTIN[name])
    raise ValueError(f"unknown template: {name!r} (have: beginner, bot, advanced)")


def available_templates() -> list:
    if _HAVE_YAML and os.path.isdir(_TEMPLATE_DIR):
        return sorted(f[:-5] for f in os.listdir(_TEMPLATE_DIR) if f.endswith(".yaml"))
    return sorted(_BUILTIN)
