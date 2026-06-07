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
