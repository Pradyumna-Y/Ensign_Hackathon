"""Run the Flip the lock demo against a running API and print each step.

    python scripts/prove_flip.py [http://127.0.0.1:8000]

Leaves the practice server back in classical mode, ready for the next demo.
"""

import json
import sys
import time
import urllib.request

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:8000"


def call(path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)


def scan():
    r = call("/api/scan?host=practice")
    v, h = r["verdict"], r["handshake"]
    return f"{v['label']:9} score {v['score']:3}  picked {h['serverPicked']}"


print("practice mode:", call("/api/practice")["mode"])
for mode in ("classical", "hybrid", "classical"):
    t = time.monotonic()
    call("/api/practice/mode", {"mode": mode})
    print(f"switched to {mode:9} in {time.monotonic() - t:.1f}s -> {scan()}")
