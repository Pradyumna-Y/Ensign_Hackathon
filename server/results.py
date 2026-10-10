"""Assembling full ScanResult objects in the shape CONTRACT.md defines."""

from datetime import datetime, timezone

from server import scoring
from server.errors import MESSAGES


def now_utc():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def ok_result(host, probe, data_type, years, when=None):
    """Combine the probe output with the verdict and shelf life."""
    when = when or now_utc()
    handshake = probe["handshake"]
    return {
        "host": host,
        "scannedAt": iso(when),
        "source": "live",
        "status": "ok",
        "error": None,
        "handshake": handshake,
        "certificate": probe["certificate"],
        "verdict": scoring.verdict(handshake),
        "shelfLife": scoring.shelf_life(handshake, data_type, years, when.year),
    }


def error_result(host, code, message=None):
    return {
        "host": host,
        "scannedAt": iso(now_utc()),
        "source": "live",
        "status": "error",
        "error": {"code": code, "message": message or MESSAGES[code]},
        "handshake": None,
        "certificate": None,
        "verdict": None,
        "shelfLife": None,
    }
