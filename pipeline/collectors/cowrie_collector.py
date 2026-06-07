"""Tail a JSON-lines log file and yield parsed dicts (like `tail -f`)."""
import json
import os
import time


def tail_json(path: str, from_start: bool = False):
    # wait for file to exist
    while not os.path.exists(path):
        time.sleep(1)
    with open(path, "r") as f:
        if not from_start:
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
