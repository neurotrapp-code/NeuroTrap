"""Real response actions against the host network stack (Day 29-30).

`ResponseActuator` builds and runs the actual ``iptables`` / ``tc`` / ``tcpdump``
commands that block, redirect, isolate, slow and forensically capture an attacker.
Commands run for real on Linux. The command layer is injectable:

  * ``CommandRunner``   — default; executes via subprocess (live).
  * ``RecordingRunner`` — records commands without executing (unit tests / non-Linux
                          dev boxes). Selecting it does not fake any *data* — it only
                          stubs the OS side-effect so logic can be verified.

Nothing here invents events: actions are taken in response to live verdicts and
the outcome (success/failure) is reported truthfully.
"""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
import time
from dataclasses import dataclass
from typing import List, Optional

IS_LINUX = platform.system() == "Linux"


class CommandRunner:
    """Executes commands for real."""

    def run(self, cmd: List[str], timeout: int = 10) -> tuple:
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return p.returncode, (p.stdout + p.stderr).strip()
        except FileNotFoundError:
            return 127, f"not found: {cmd[0]}"
        except subprocess.TimeoutExpired:
            return 124, "timeout"

    def spawn(self, cmd: List[str]) -> Optional[int]:
        """Start a long-running command (e.g. tcpdump) detached; return its pid."""
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return p.pid
        except FileNotFoundError:
            return None


class RecordingRunner(CommandRunner):
    """Records commands instead of executing (tests / non-Linux)."""

    def __init__(self):
        self.commands: List[List[str]] = []

    def run(self, cmd, timeout: int = 10):
        self.commands.append(list(cmd))
        return 0, "recorded"

    def spawn(self, cmd):
        self.commands.append(list(cmd))
        return 4242


@dataclass
class ActionOutcome:
    action: str
    success: bool
    detail: str
    command: Optional[str] = None


class ResponseActuator:
    def __init__(self, runner: CommandRunner = None, *, iptables: str = "iptables",
                 redirect_port: int = 2222, pcap_dir: str = None,
                 capture_seconds: int = 300):
        self.runner = runner or CommandRunner()
        self.iptables = iptables
        self.redirect_port = redirect_port
        self.capture_seconds = capture_seconds
        self.pcap_dir = pcap_dir or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "forensics")

    def available(self) -> bool:
        """True only if the real firewall tooling is usable on this host."""
        return IS_LINUX and shutil.which(self.iptables) is not None

    # -- individual actions -----------------------------------------------
    def block(self, ip: str) -> ActionOutcome:
        cmd = [self.iptables, "-I", "INPUT", "-s", ip, "-j", "DROP"]
        return self._run("block", cmd)

    def unblock(self, ip: str) -> ActionOutcome:
        cmd = [self.iptables, "-D", "INPUT", "-s", ip, "-j", "DROP"]
        return self._run("unblock", cmd)

    def isolate(self, ip: str) -> ActionOutcome:
        # stop the attacker pivoting: drop anything they try to forward/route
        cmd = [self.iptables, "-I", "FORWARD", "-s", ip, "-j", "DROP"]
        return self._run("isolate", cmd)

    def slow(self, ip: str) -> ActionOutcome:
        # rate-limit new connections from this source (frustrate automated tools)
        cmd = [self.iptables, "-I", "INPUT", "-s", ip, "-p", "tcp", "--syn",
               "-m", "hashlimit", "--hashlimit-name", "cadn_slow",
               "--hashlimit-above", "10/min", "--hashlimit-mode", "srcip",
               "-j", "DROP"]
        return self._run("slow", cmd)

    def redirect(self, ip: str, to_port: int = None) -> ActionOutcome:
        # transparently redirect the attacker to a deeper honeypot port (DNAT)
        to_port = to_port or self.redirect_port
        cmd = [self.iptables, "-t", "nat", "-I", "PREROUTING", "-s", ip,
               "-p", "tcp", "-j", "REDIRECT", "--to-ports", str(to_port)]
        return self._run("redirect", cmd)

    def forensic_capture(self, ip: str, seconds: int = None) -> ActionOutcome:
        seconds = seconds or self.capture_seconds
        os.makedirs(self.pcap_dir, exist_ok=True)
        out = os.path.join(self.pcap_dir, f"{ip.replace(':','_')}-{int(time.time())}.pcap")
        cmd = ["tcpdump", "-i", "any", "host", ip, "-w", out,
               "-G", str(seconds), "-W", "1"]
        pid = self.runner.spawn(cmd)
        ok = pid is not None
        return ActionOutcome("forensic_capture", ok,
                             f"pcap -> {out} (pid {pid})" if ok else "tcpdump unavailable",
                             command=" ".join(cmd))

    # -- internal ----------------------------------------------------------
    def _run(self, action: str, cmd: List[str]) -> ActionOutcome:
        rc, out = self.runner.run(cmd)
        return ActionOutcome(action, rc == 0, out, command=" ".join(cmd))
