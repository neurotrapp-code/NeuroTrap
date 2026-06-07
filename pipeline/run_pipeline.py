#!/usr/bin/env python3
"""CADN log pipeline: tail Cowrie + Dionaea + Zeek, normalize, persist.

Paths auto-resolve relative to the repo root and can be overridden via env:
    COWRIE_LOG, DIONAEA_LOG, ZEEK_CONN_LOG, ZEEK_HTTP_LOG, ZEEK_SSH_LOG, ZEEK_DNS_LOG
"""
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from collectors.cowrie_collector import tail_json  # noqa: E402
import normalizer as N  # noqa: E402
from db import EventStore  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
COWRIE = os.environ.get("COWRIE_LOG",
                        os.path.join(ROOT, "honeypots/cowrie/var/log/cowrie/cowrie.json"))
DIONAEA = os.environ.get("DIONAEA_LOG",
                         os.path.join(ROOT, "honeypots/dionaea/var/log/dionaea.json"))
ZEEK_DIR = os.environ.get("ZEEK_LOG_DIR", "/opt/zeek/logs/cadn")
ZEEK_CONN = os.environ.get("ZEEK_CONN_LOG", os.path.join(ZEEK_DIR, "conn.log"))
ZEEK_HTTP = os.environ.get("ZEEK_HTTP_LOG", os.path.join(ZEEK_DIR, "http.log"))
ZEEK_SSH = os.environ.get("ZEEK_SSH_LOG", os.path.join(ZEEK_DIR, "ssh.log"))
ZEEK_DNS = os.environ.get("ZEEK_DNS_LOG", os.path.join(ZEEK_DIR, "dns.log"))

store = EventStore()


def run(path, fn, name):
    print(f"[*] collector started: {name} -> {path}", flush=True)
    for raw in tail_json(path):
        evt = fn(raw)
        if evt:
            store.write(evt.to_dict())
            print(f"[{name}] stored {evt.attack_type} from {evt.src_ip}", flush=True)


if __name__ == "__main__":
    threads = [
        threading.Thread(target=run, args=(COWRIE, N.from_cowrie, "cowrie"), daemon=True),
        threading.Thread(target=run, args=(DIONAEA, N.from_dionaea, "dionaea"), daemon=True),
        threading.Thread(target=run, args=(ZEEK_CONN, N.from_zeek_conn, "zeek-conn"), daemon=True),
        threading.Thread(target=run, args=(ZEEK_HTTP, N.from_zeek_http, "zeek-http"), daemon=True),
        threading.Thread(target=run, args=(ZEEK_SSH, N.from_zeek_ssh, "zeek-ssh"), daemon=True),
        threading.Thread(target=run, args=(ZEEK_DNS, N.from_zeek_dns, "zeek-dns"), daemon=True),
    ]
    for t in threads:
        t.start()
    print("[*] pipeline running — Ctrl+C to stop", flush=True)
    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print("\n[*] stopped.")
