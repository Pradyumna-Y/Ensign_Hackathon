"""Parser tests against real s_client outputs saved in samples/."""

from pathlib import Path

import pytest

from server.scanner import (Probe, RawProbe, classify, parse_certificate,
                            parse_s_client, tls12_key_exchange)

SAMPLES = Path(__file__).parent / "samples"


def load(name):
    return parse_s_client(RawProbe((SAMPLES / f"{name}.txt").read_text(encoding="utf-8")))


def failed(reason):
    return Probe(False, None, None, None, None, reason)


def test_hybrid_tls13():
    p = load("tls13_hybrid_cloudflare")
    assert p.ok and p.protocol == "TLSv1.3"
    assert p.group == "X25519MLKEM768"
    assert p.cipher.startswith("TLS_")
    assert p.cert_pem.startswith("-----BEGIN CERTIFICATE-----")


def test_classical_tls13_x25519_from_temp_key_line():
    p = load("tls13_classical_x25519_github")
    assert p.ok and p.protocol == "TLSv1.3"
    assert p.group == "X25519"


def test_classical_tls13_p256_uses_tls_name():
    p = load("tls13_classical_p256_utah")
    assert p.group == "secp256r1"   # OpenSSL prints prime256v1


def test_tls12_ecdhe():
    p = load("tls12_ecdhe_cloudflare")
    assert p.ok and p.protocol == "TLSv1.2"
    assert p.cipher.startswith("ECDHE-")
    assert tls12_key_exchange(p.cipher) == "classical"


def test_tls12_static_rsa():
    p = load("tls12_static_rsa_badssl")
    assert p.ok and p.protocol == "TLSv1.2"
    assert p.group is None
    assert tls12_key_exchange(p.cipher) == "static_rsa"


def test_tls13_refused():
    p = load("tls13_refused_irs")
    assert not p.ok and p.failure == "handshake_refused"
    assert p.group is None


def test_not_tls():
    p = load("not_tls_portquiz")
    assert not p.ok and p.failure == "not_tls"


def test_connect_failed():
    p = load("connect_failed_local")
    assert not p.ok and p.failure == "connect_failed"


def test_timeout():
    p = parse_s_client(RawProbe("", timed_out=True))
    assert p.failure == "timeout"


def test_output_cap_counts_as_failure():
    text = (SAMPLES / "tls13_hybrid_cloudflare.txt").read_text(encoding="utf-8")
    assert not parse_s_client(RawProbe(text, too_large=True)).ok


@pytest.mark.parametrize("cipher,expected", [
    ("ECDHE-RSA-AES128-GCM-SHA256", "classical"),
    ("DHE-RSA-AES256-GCM-SHA384", "classical"),
    ("AES128-SHA", "static_rsa"),
    ("AES256-GCM-SHA384", "static_rsa"),
    ("DES-CBC3-SHA", "static_rsa"),
    ("PSK-AES128-CBC-SHA", "unknown"),
])
def test_tls12_cipher_names(cipher, expected):
    assert tls12_key_exchange(cipher) == expected


def test_classify():
    hybrid = load("tls13_hybrid_cloudflare")
    classical = load("tls13_classical_x25519_github")
    tls12 = load("tls12_ecdhe_cloudflare")
    rsa = load("tls12_static_rsa_badssl")
    refused = load("tls13_refused_irs")
    assert classify(hybrid, tls12) == "hybrid_pq"
    assert classify(classical, tls12) == "classical"
    assert classify(refused, tls12) == "classical"
    assert classify(refused, rsa) == "static_rsa"
    assert classify(failed("timeout"), failed("timeout")) == "unknown"


def test_certificate_parsing():
    ecdsa = parse_certificate(load("tls13_hybrid_cloudflare").cert_pem)
    assert ecdsa["keyType"] == "ECDSA" and ecdsa["keyBits"] == 256
    assert ecdsa["note"] == "Shown for context. Not scored."
    rsa = parse_certificate(load("tls12_static_rsa_badssl").cert_pem)
    assert rsa["keyType"] == "RSA" and rsa["keyBits"] >= 2048
    assert parse_certificate(None) is None
