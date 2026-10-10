"""Saved scan results, so the demo still works if the venue network is slow.

One JSON file per demo site in cache/ (gitignored). A saved result is always
served with source "cached" and its original scannedAt, never as live.
Only demo sites are saved, so strangers' scans never fill the disk.
"""

import json
import os
from datetime import datetime
from pathlib import Path

from server import scoring

ROOT = Path(__file__).resolve().parent.parent
CACHE_DIR = Path(os.environ.get("FLIP_CACHE_DIR", ROOT / "cache"))
DEMO_SITES_FILE = Path(__file__).resolve().parent / "demo_sites.json"


def demo_sites():
    return json.loads(DEMO_SITES_FILE.read_text(encoding="utf-8"))["sites"]


def _path(host):
    # Hosts are already validated (letters, digits, dots, hyphens, no empty
    # labels), so this cannot point outside the cache folder.
    return CACHE_DIR / f"{host}.json"


def save(result):
    """Save a successful live result for a demo site. Returns True if saved."""
    if result.get("status") != "ok" or result["host"] not in demo_sites():
        return False
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        tmp = _path(result["host"]).with_suffix(".tmp")
        tmp.write_text(json.dumps(result, indent=2), encoding="utf-8")
        os.replace(tmp, _path(result["host"]))   # atomic: never a half-written file
    except OSError:
        return False   # a cache problem must never turn a good scan into an error
    return True


HANDSHAKE_KEYS = ("keyExchange", "supportsTls13", "acceptsTls12", "serverPicked", "weOffered")
VERDICT_KEYS = ("label", "score", "headline", "reason")
SHELF_KEYS = ("years", "secretUntilYear", "quantumArrivalYear", "urgency")


def _complete(result):
    """True if a saved file has everything the page needs, so a damaged file is ignored."""
    handshake, verdict, shelf = (result.get(k) for k in ("handshake", "verdict", "shelfLife"))
    try:
        datetime.strptime(result["scannedAt"], "%Y-%m-%dT%H:%M:%SZ")
    except (KeyError, TypeError, ValueError):
        return False
    return (isinstance(handshake, dict) and all(k in handshake for k in HANDSHAKE_KEYS)
            and isinstance(handshake["weOffered"], list)
            and isinstance(verdict, dict) and isinstance(verdict.get("fixes"), list)
            and all(isinstance(f, dict) and "title" in f and "detail" in f
                    for f in verdict["fixes"])
            and all(k in verdict for k in VERDICT_KEYS)
            and isinstance(shelf, dict) and all(k in shelf for k in SHELF_KEYS))


def load(host):
    """The saved result for host, labeled cached, or None."""
    try:
        result = json.loads(_path(host).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if result.get("status") != "ok" or result.get("host") != host or not _complete(result):
        return None
    result["source"] = "cached"
    return result


def load_for_request(host, data_type, years):
    """A saved result re-scored for this request's data type.

    The handshake is what we saved; the verdict and shelf life are pure
    functions of it, so we recompute them for the data type asked for. The
    year used is the year of the original scan.
    """
    result = load(host)
    if result is None:
        return None
    handshake = result["handshake"]
    result["verdict"] = scoring.verdict(handshake)
    result["shelfLife"] = scoring.shelf_life(handshake, data_type, years,
                                             int(result["scannedAt"][:4]))
    return result


def all_cached():
    return [r for r in (load(h) for h in demo_sites()) if r is not None]
