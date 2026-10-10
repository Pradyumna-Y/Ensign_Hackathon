"""API tests with the network parts replaced, so they run offline and fast."""

import pytest
from fastapi.testclient import TestClient

from server import app as app_module
from server.errors import ScanError
from server.limits import RateLimiter
from server.targets import Target

HYBRID_PROBE = {
    "handshake": {"tlsVersion": "TLSv1.3", "cipherSuite": "TLS_AES_256_GCM_SHA384",
                  "weOffered": ["X25519MLKEM768", "X25519", "secp256r1", "secp384r1"],
                  "serverPicked": "X25519MLKEM768", "keyExchange": "hybrid_pq",
                  "supportsTls13": True, "acceptsTls12": True},
    "certificate": {"keyType": "ECDSA", "keyBits": 256, "signature": "ecdsa-with-SHA256",
                    "expires": "2027-01-04", "note": "Shown for context. Not scored."},
}


@pytest.fixture
def client(monkeypatch):
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
        if host == "boom.example":
            raise RuntimeError("C:\\secret\\path traceback")
        return HYBRID_PROBE

    monkeypatch.setattr(app_module, "hybrid_self_test", self_test)
    monkeypatch.setattr(app_module, "resolve_target", resolve)
    monkeypatch.setattr(app_module, "probe_site", probe)
    monkeypatch.setattr(app_module, "rate_limiter", RateLimiter())
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


def test_rate_limit(client):
    codes = [client.get("/api/scan", params={"host": "cloudflare.com"}).status_code
             for _ in range(31)]
    assert codes[:30] == [200] * 30
    assert codes[30] == 429
