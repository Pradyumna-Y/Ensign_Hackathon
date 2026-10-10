"""API tests with the network parts replaced, so they run offline and fast."""

import asyncio

import pytest
from fastapi.testclient import TestClient

from server import app as app_module
from server import cache
from server.errors import ScanError
from server.limits import RateLimiter
from server.targets import Target

OFFLINE = set()   # hosts whose live scan should time out in a test

HYBRID_PROBE = {
    "handshake": {"tlsVersion": "TLSv1.3", "cipherSuite": "TLS_AES_256_GCM_SHA384",
                  "weOffered": ["X25519MLKEM768", "X25519", "secp256r1", "secp384r1"],
                  "serverPicked": "X25519MLKEM768", "keyExchange": "hybrid_pq",
                  "supportsTls13": True, "acceptsTls12": True},
    "certificate": {"keyType": "ECDSA", "keyBits": 256, "signature": "ecdsa-with-SHA256",
                    "expires": "2027-01-04", "note": "Shown for context. Not scored."},
}


@pytest.fixture
def client(monkeypatch, tmp_path):
    async def self_test(openssl):
        return True

    async def resolve(host):
        from server.targets import normalize_host
        name = normalize_host(host)
        if name == "internal.example":
            raise ScanError("blocked_target")
        return Target(name, "104.16.132.229", 443)

    async def probe(openssl, host, ip, port):
        if host == "notls.example":
            raise ScanError("no_tls")
        if host in OFFLINE:
            raise ScanError("timeout")
        if host == "boom.example":
            raise RuntimeError("C:\\secret\\path traceback")
        return HYBRID_PROBE

    class FakePractice:
        def __init__(self, openssl):
            self.mode = None
            self.alive = False
            self.lock = asyncio.Lock()

        @property
        def running(self):
            return self.alive

        async def set_mode(self, mode):
            self.mode = mode
            self.alive = True
            return mode

        async def close(self):
            pass

    monkeypatch.setattr(cache, "CACHE_DIR", tmp_path)   # never touch the real cache/
    monkeypatch.setattr(app_module, "PracticeServer", FakePractice)
    monkeypatch.setattr(app_module, "hybrid_self_test", self_test)
    monkeypatch.setattr(app_module, "resolve_target", resolve)
    monkeypatch.setattr(app_module, "probe_site", probe)
    monkeypatch.setattr(app_module, "rate_limiter", RateLimiter())
    monkeypatch.setattr(app_module, "practice_limiter", RateLimiter(limit=120))
    with TestClient(app_module.app, raise_server_exceptions=False) as c:
        yield c


def test_health(client):
    body = client.get("/api/health").json()
    assert body["ok"] is True and body["hybridSelfTest"] is True
    assert body["opensslVersion"].startswith("3.")


def test_scan_ok_shape(client):
    r = client.get("/api/scan", params={"host": "cloudflare.com", "data": "health_records"})
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"host", "scannedAt", "source", "status", "error", "handshake",
                         "certificate", "verdict", "shelfLife"}
    assert body["source"] == "live" and body["status"] == "ok" and body["error"] is None
    assert body["verdict"]["label"] == "ready" and body["verdict"]["score"] == 95
    assert body["shelfLife"]["years"] == 30 and body["shelfLife"]["urgency"] == "none"
    assert body["scannedAt"].endswith("Z")


def test_years_override(client):
    body = client.get("/api/scan", params={"host": "cloudflare.com", "data": "custom",
                                           "years": "7"}).json()
    assert body["shelfLife"]["years"] == 7 and body["shelfLife"]["dataType"] == "custom"


def error_of(r):
    body = r.json()
    assert body["status"] == "error"
    assert body["handshake"] is None and body["verdict"] is None and body["shelfLife"] is None
    return r.status_code, body["error"]["code"]


@pytest.mark.parametrize("params,expected", [
    ({"host": "127.0.0.1"}, (400, "invalid_host")),
    ({"host": "localhost"}, (400, "invalid_host")),
    ({"host": "example.com:22"}, (400, "invalid_host")),
    ({}, (400, "invalid_host")),
    ({"host": "internal.example"}, (403, "blocked_target")),
    ({"host": "notls.example"}, (200, "no_tls")),
    ({"host": "cloudflare.com", "data": "pets"}, (400, "invalid_input")),
    ({"host": "cloudflare.com", "data": "custom"}, (400, "invalid_input")),
    ({"host": "cloudflare.com", "years": "abc"}, (400, "invalid_input")),
    ({"host": "cloudflare.com", "years": "101"}, (400, "invalid_input")),
])
def test_scan_errors(client, params, expected):
    assert error_of(client.get("/api/scan", params=params)) == expected


def test_unexpected_error_leaks_nothing(client):
    r = client.get("/api/scan", params={"host": "boom.example"})
    assert r.status_code == 500
    assert r.json()["error"]["code"] == "internal"
    assert "secret" not in r.text and "Traceback" not in r.text


def test_practice_endpoints(client):
    assert client.get("/api/practice").json() == {"mode": "classical", "scanHost": "practice"}
    assert client.post("/api/practice/mode", json={"mode": "hybrid"}).json() == {"mode": "hybrid"}
    assert client.get("/api/practice").json()["mode"] == "hybrid"
    r = client.post("/api/practice/mode", json={"mode": "quantum"})
    assert r.status_code == 400 and r.json()["error"]["code"] == "invalid_input"


def test_rate_limit(client):
    codes = [client.get("/api/scan", params={"host": "cloudflare.com"}).status_code
             for _ in range(31)]
    assert codes[:30] == [200] * 30
    assert codes[30] == 429


def test_demo_sites(client):
    sites = client.get("/api/demo-sites").json()["sites"]
    assert "cloudflare.com" in sites and len(sites) >= 5


def test_live_demo_scan_is_saved_and_listed_as_cached(client):
    assert client.get("/api/cached").json() == []
    client.get("/api/scan", params={"host": "cloudflare.com"})
    client.get("/api/scan", params={"host": "not-a-demo-site.example"})
    saved = client.get("/api/cached").json()
    assert [r["host"] for r in saved] == ["cloudflare.com"]   # strangers' scans are not saved
    assert saved[0]["source"] == "cached"


def test_falls_back_to_saved_result_when_live_scan_fails(client):
    live = client.get("/api/scan", params={"host": "github.com"}).json()
    OFFLINE.add("github.com")
    try:
        r = client.get("/api/scan", params={"host": "github.com", "data": "login_session"})
    finally:
        OFFLINE.discard("github.com")
    body = r.json()
    assert r.status_code == 200 and body["status"] == "ok"
    assert body["source"] == "cached"
    assert body["scannedAt"] == live["scannedAt"]            # original time, not now
    assert body["shelfLife"]["dataType"] == "login_session"  # re-scored for this request


def test_no_saved_result_means_error(client):
    OFFLINE.add("wikipedia.org")
    try:
        r = client.get("/api/scan", params={"host": "wikipedia.org"})
    finally:
        OFFLINE.discard("wikipedia.org")
    assert error_of(r) == (200, "timeout")


def test_practice_has_its_own_rate_limit(client):
    for _ in range(31):
        client.get("/api/scan", params={"host": "cloudflare.com"})
    # outside scans are now limited, but flipping and scanning practice still work
    assert client.get("/api/scan", params={"host": "cloudflare.com"}).status_code == 429
    assert client.post("/api/practice/mode", json={"mode": "hybrid"}).status_code == 200
    r = client.get("/api/scan", params={"host": "practice"})
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_failed_practice_restart_is_a_clean_error(client, monkeypatch):
    async def broken(mode):
        raise RuntimeError("port 8443 is already in use")
    monkeypatch.setattr(client.app.state.practice, "set_mode", broken)
    r = client.post("/api/practice/mode", json={"mode": "hybrid"})
    assert r.status_code == 500 and r.json()["error"]["code"] == "internal"
    assert "8443" not in r.text


def test_practice_scan_refuses_when_our_server_is_not_running(client):
    client.app.state.practice.alive = False   # e.g. its port was taken at startup
    for host in ("practice", "Practice."):
        r = client.get("/api/scan", params={"host": host})
        assert error_of(r) == (200, "no_tls")


def test_practice_name_variants_use_the_practice_limit(client):
    for _ in range(40):
        assert client.get("/api/scan", params={"host": "Practice."}).status_code == 200


def test_security_headers_and_cache_rules(client):
    api = client.get("/api/health")
    assert api.headers["Cache-Control"] == "no-store"
    page = client.get("/")
    assert page.headers["Cache-Control"] == "no-cache"
    for r in (api, page):
        assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]
        assert r.headers["X-Content-Type-Options"] == "nosniff"
        assert r.headers["Referrer-Policy"] == "no-referrer"
    assert "script-src 'self'" in page.headers["Content-Security-Policy"]


def test_unexpected_error_still_carries_the_safe_headers(client):
    r = client.get("/api/scan", params={"host": "boom.example"})
    assert r.status_code == 500
    assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]
    assert r.headers["Cache-Control"] == "no-store"


def test_practice_status_is_null_when_the_server_is_not_running(client):
    practice = client.app.state.practice
    practice.mode, practice.alive = "classical", False   # the process died; mode is stale
    assert client.get("/api/practice").json()["mode"] is None
