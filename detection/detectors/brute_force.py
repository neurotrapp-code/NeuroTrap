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
