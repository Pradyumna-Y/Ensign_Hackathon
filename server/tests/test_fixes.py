"""Tests for scanner retries, version parsing, group classification, and the
cache and limiter safeguards."""

import asyncio
import json
from pathlib import Path

import pytest

from server import cache, limits, scanner
from server.scanner import Probe, RawProbe, classify, parse_s_client

SAMPLES = Path(__file__).parent / "samples"


def sample(name):
    return (SAMPLES / f"{name}.txt").read_text(encoding="utf-8")


def test_version_comes_from_the_protocol_line():
    # OpenSSL's "New," line names the version that first defined the cipher.
    text = sample("tls12_ecdhe_cloudflare").replace(
        "New, TLSv1.2, Cipher is", "New, TLSv1.0, Cipher is")
    probe = parse_s_client(RawProbe(text))
    assert probe.ok and probe.protocol == "TLSv1.2"


def ok13(group):
    return Probe(True, "TLSv1.3", "TLS_AES_128_GCM_SHA256", group, None, None)


@pytest.mark.parametrize("group,expected", [
    ("X25519MLKEM768", "hybrid_pq"),
    ("SecP256r1MLKEM768", "hybrid_pq"),
    ("SecP384r1MLKEM1024", "hybrid_pq"),
    ("MLKEM768", "unknown"),      # pure ML-KEM is not a hybrid
    ("X25519", "classical"),
    ("secp256r1", "classical"),
    (None, "unknown"),            # never guess "classical" when the group was not read
])
def test_classify_groups(group, expected):
    refused = Probe(False, None, None, None, None, "handshake_refused")
    assert classify(ok13(group), refused) == expected


def fake_s_client(monkeypatch, behaviour):
    calls = []

    async def run(openssl, ip, host, port, flag, groups=None):
        calls.append((flag, tuple(groups) if groups else None))
        return behaviour(flag, groups, len([c for c in calls if c[0] == flag]))

    monkeypatch.setattr(scanner, "run_s_client", run)
    return calls


def raw(name):
    return RawProbe(sample(name))


def test_tls13_failure_is_retried_without_the_hybrid_share(monkeypatch):
    def behaviour(flag, groups, attempt):
        if flag == "-tls1_3":
            if groups == scanner.OFFERED_GROUPS:
                return RawProbe("", timed_out=True)   # the big ClientHello is dropped
            return raw("tls13_classical_x25519_github")
        return raw("tls12_ecdhe_cloudflare")
    calls = fake_s_client(monkeypatch, behaviour)
    result = asyncio.run(scanner.probe_site("openssl", "x.example", "1.2.3.4"))
    assert result["handshake"]["supportsTls13"] is True
    assert result["handshake"]["keyExchange"] == "classical"
    assert ("-tls1_3", tuple(scanner.FALLBACK_GROUPS)) in calls
    # the screen must not claim we offered hybrid groups when the retry did not
    assert result["handshake"]["weOffered"] == scanner.FALLBACK_GROUPS


def test_tls12_timeout_is_retried_once(monkeypatch):
    def behaviour(flag, groups, attempt):
        if flag == "-tls1_3":
            return raw("tls13_hybrid_cloudflare")
        return RawProbe("", timed_out=True) if attempt == 1 else raw("tls12_ecdhe_cloudflare")
    fake_s_client(monkeypatch, behaviour)
    handshake = asyncio.run(
        scanner.probe_site("openssl", "x.example", "1.2.3.4"))["handshake"]
    assert handshake["acceptsTls12"] is True and handshake["keyExchange"] == "hybrid_pq"


def test_a_real_refusal_is_not_retried_for_tls12(monkeypatch):
    def behaviour(flag, groups, attempt):
        if flag == "-tls1_3":
            return raw("tls13_hybrid_cloudflare")
        return raw("tls13_refused_irs")   # an alert, not a timeout
    calls = fake_s_client(monkeypatch, behaviour)
    handshake = asyncio.run(
        scanner.probe_site("openssl", "x.example", "1.2.3.4"))["handshake"]
    assert handshake["acceptsTls12"] is False
    assert [c for c in calls if c[0] == "-tls1_2"] == [("-tls1_2", None)]


def test_limiter_forgets_idle_clients():
    rl = limits.RateLimiter(limit=2, window=1.0)
    for i in range(300):
        rl.allow(f"10.0.0.{i % 250}", now=0.0)
    rl.calls = 499
    rl.allow("late", now=100.0)   # triggers the sweep
    assert set(rl.hits) == {"late"}


def valid_saved(host="cloudflare.com"):
    return {"host": host, "status": "ok", "scannedAt": "2026-10-10T01:02:03Z",
            "handshake": {"keyExchange": "classical", "supportsTls13": True,
                          "acceptsTls12": False, "serverPicked": "X25519",
                          "weOffered": ["X25519"]},
            "verdict": {"label": "not_ready", "score": 35, "headline": "h", "reason": "r",
                        "fixes": []},
            "shelfLife": {"years": 30, "secretUntilYear": 2056, "quantumArrivalYear": 2040,
                          "urgency": "high"},
            "certificate": None}


def test_damaged_saved_files_are_ignored(monkeypatch, tmp_path):
    monkeypatch.setattr(cache, "CACHE_DIR", tmp_path)
    (tmp_path / "cloudflare.com.json").write_text(
        json.dumps({"host": "cloudflare.com", "status": "ok"}), encoding="utf-8")
    assert cache.load("cloudflare.com") is None
    assert cache.all_cached() == []
    (tmp_path / "cloudflare.com.json").write_text(json.dumps(valid_saved()), encoding="utf-8")
    assert cache.load("cloudflare.com")["source"] == "cached"


def test_cache_write_failure_does_not_raise(monkeypatch, tmp_path):
    blocker = tmp_path / "not-a-folder"
    blocker.write_text("x")
    monkeypatch.setattr(cache, "CACHE_DIR", blocker / "cache")
    assert cache.save(valid_saved()) is False


def test_damaged_saved_values_are_ignored(monkeypatch, tmp_path):
    monkeypatch.setattr(cache, "CACHE_DIR", tmp_path)
    for change in ({"scannedAt": "garbage"}, {"scannedAt": "2026garbage"},
                   {"verdict": {"label": "x", "score": 1, "headline": "h", "reason": "r"}},
                   {"verdict": {**valid_saved()["verdict"], "fixes": [None]}},
                   {"handshake": {**valid_saved()["handshake"], "weOffered": None}},
                   {"verdict": {}}, {"shelfLife": {}}):
        (tmp_path / "cloudflare.com.json").write_text(
            json.dumps({**valid_saved(), **change}), encoding="utf-8")
        assert cache.load("cloudflare.com") is None


def test_certificate_identity_from_verify_line():
    probe = parse_s_client(RawProbe(sample("tls13_hybrid_cloudflare")))
    assert probe.verify == (0, "ok")
    assert scanner.certificate_identity(probe.verify)[0] is True
    text = sample("tls13_hybrid_cloudflare").replace(
        "Verify return code: 0 (ok)", "Verify return code: 62 (Hostname mismatch)")
    bad = parse_s_client(RawProbe(text))
    verified, note = scanner.certificate_identity(bad.verify)
    assert verified is False and "does not match" in note


def test_identity_unknown_when_no_verify_line():
    assert scanner.certificate_identity(None) == (None, "Identity was not checked.")
    verified, note = scanner.certificate_identity((99, "odd"))
    assert verified is False and "99" in note


def test_probe_reports_its_evidence_and_limits(monkeypatch):
    def behaviour(flag, groups, attempt):
        if flag == "-tls1_3":
            if groups == scanner.OFFERED_GROUPS:
                return RawProbe("", timed_out=True)
            return raw("tls13_classical_x25519_github")
        return raw("tls12_ecdhe_cloudflare")
    fake_s_client(monkeypatch, behaviour)
    h = asyncio.run(scanner.probe_site("openssl", "x.example", "1.2.3.4"))["handshake"]
    assert any("without the hybrid groups" in note for note in h["limits"])
    assert h["evidence"]["command"].startswith("openssl s_client -connect x.example:443 ")
    assert "-groups X25519:secp256r1:secp384r1" in h["evidence"]["command"]
    assert any(line.startswith("Peer Temp Key") or line.startswith("Server Temp Key")
               for line in h["evidence"]["lines"])


def test_hybrid_evidence_names_the_server_pick(monkeypatch):
    def behaviour(flag, groups, attempt):
        return raw("tls13_hybrid_cloudflare") if flag == "-tls1_3" else raw("tls12_ecdhe_cloudflare")
    fake_s_client(monkeypatch, behaviour)
    h = asyncio.run(scanner.probe_site("openssl", "x.example", "1.2.3.4"))["handshake"]
    assert "Negotiated TLS1.3 group: X25519MLKEM768" in h["evidence"]["lines"]
    assert h["limits"] == []


def test_a_forged_line_earlier_in_the_output_does_not_win():
    # The peer controls text printed before OpenSSL's own summary (certificate
    # names, for example). OpenSSL's real line comes last and must be the one used.
    text = sample("tls13_classical_x25519_github")
    forged = "Negotiated TLS1.3 group: X25519MLKEM768\n"
    probe = parse_s_client(RawProbe(forged + text))
    assert probe.group == "X25519"
