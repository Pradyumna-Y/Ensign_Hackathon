"""Quick pre-demo check against a running app. Prints PASS or FAIL for each step.

    python scripts/check_demo.py [http://127.0.0.1:8000]

Needs the app running and internet for the first scan. The last step puts the
practice server back on the old lock, ready for the demo. Exit code is 0 only
if every step passed.
"""

import json
import sys
import urllib.error
import urllib.request

if len(sys.argv) > 1 and sys.argv[1] in ("-h", "--help"):
    print(__doc__)
    sys.exit(0)
BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:8000"


def call(path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=40) as resp:
            return resp.status, json.load(resp)
    except urllib.error.HTTPError as e:   # 4xx and 5xx still carry a JSON body
        return e.code, json.load(e)


def scan(host):
    status, body = call(f"/api/scan?host={host}")
    return status, body, (body.get("verdict") or {}).get("label"), \
        (body.get("handshake") or {}).get("serverPicked")


def flip(mode):
    call("/api/practice/mode", {"mode": mode})
    return scan("practice")


results = []


def check(name, passed, detail=""):
    results.append(passed)
    print(f"{'PASS' if passed else 'FAIL'}  {name}  {detail}")


_, health = call("/api/health")
check("backend is up and can offer the hybrid group", health.get("hybridSelfTest") is True,
      health.get("opensslVersion", ""))

_, _, label, picked = scan("cloudflare.com")
check("a real hybrid site scans as Ready", label == "ready" and picked == "X25519MLKEM768",
      f"{label} {picked}")

_, _, label, picked = scan("github.com")
check("a classical site scans as Not ready", label == "not_ready", f"{label} {picked}")

status, body, _, _ = scan("169.254.169.254")
check("an internal address is refused", status == 400 and body["error"]["code"] == "invalid_host",
      f"HTTP {status}")

status, body, _, _ = scan("no-such-site-qzx81.com")
check("a made-up name gives a clean error", body["status"] == "error", body["error"]["code"])

_, _, old_label, old_pick = flip("classical")
_, _, new_label, new_pick = flip("hybrid")
check("flip: old lock is Not ready, new lock is Ready",
      old_label == "not_ready" and new_label == "ready",
      f"{old_pick} -> {new_pick}")

_, _, back_label, _ = flip("classical")
check("practice server is back on the old lock", back_label == "not_ready")

print("\nALL PASSED" if all(results) else "\nSOMETHING FAILED, do not demo yet")
sys.exit(0 if all(results) else 1)
