"""Tests for the blocking rules: what /api/scan refuses to connect to."""

import asyncio
import socket

import pytest

from server import targets
from server.errors import ScanError
from server.targets import is_blocked, normalize_host, resolve_target


@pytest.mark.parametrize("raw,expected", [
    ("cloudflare.com", "cloudflare.com"),
    ("  Sub.Example.co.uk ", "sub.example.co.uk"),
    ("example.com.", "example.com"),
    ("example.com\n", "example.com"),   # pasted with a newline
    ("xn--bcher-kva.example", "xn--bcher-kva.example"),
    ("bücher.example", "xn--bcher-kva.example"),   # international names become ASCII
    ("practice", "practice"),
])
def test_valid_hostnames(raw, expected):
    assert normalize_host(raw) == expected


@pytest.mark.parametrize("raw", [
    "", "   ", "com", "localhost", "LOCALHOST", "foo.localhost",
    "127.0.0.1", "10.1", "0x7f.0.0.0x1", "1.2.3.4.5", "::1", "[::1]", "[2606:4700::1]",
    "example.com:8443", "example.com:443", "example.com/path", "https://example.com",
    "exa mple.com", "exa\tmple.com", "example.com\nevil.com", "-bad.com", "bad-.com", "example..com",
    "ex_ample.com", "ex\u202eample.com", "a" * 64 + ".com", ("a" * 60 + ".") * 5 + "com",
    "user@example.com", "example.com;ls", "$(whoami).com",
])
def test_invalid_hostnames(raw):
    with pytest.raises(ScanError) as e:
        normalize_host(raw)
    assert e.value.code == "invalid_host"


@pytest.mark.parametrize("ip", [
    "10.0.0.1", "172.16.5.4", "192.168.1.1", "127.0.0.1", "127.8.8.8",
    "169.254.169.254", "169.254.1.1", "100.64.0.1", "100.100.100.200",
    "0.0.0.0", "224.0.0.1", "239.255.255.250", "255.255.255.255", "240.0.0.1",
    "192.0.2.1", "198.18.0.1",
    "::1", "::", "fe80::1", "fc00::1", "fd00:ec2::254", "ff02::1", "2001:db8::1",
    "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254",
    "2002:7f00:1::1",    # 6to4 wrapping 127.0.0.1
])
def test_blocked_addresses(ip):
    assert is_blocked(ip)


@pytest.mark.parametrize("ip", ["1.1.1.1", "8.8.8.8", "104.16.132.229",
                                "2606:4700::6810:84e5", "2001:4860:4860::8888"])
def test_public_addresses_allowed(ip):
    assert not is_blocked(ip)


def fake_dns(monkeypatch, addresses):
    async def getaddrinfo(self, host, port, **kw):
        if addresses is None:
            raise socket.gaierror("not found")
        return [(socket.AF_INET6 if ":" in a else socket.AF_INET, socket.SOCK_STREAM,
                 6, "", (a, port)) for a in addresses]
    monkeypatch.setattr(asyncio.BaseEventLoop, "getaddrinfo", getaddrinfo)


def run(coro):
    return asyncio.run(coro)


def test_resolves_public_name_prefers_ipv4(monkeypatch):
    fake_dns(monkeypatch, ["2606:4700::6810:84e5", "104.16.132.229"])
    t = run(resolve_target("cloudflare.com"))
    assert (t.host, t.ip, t.port) == ("cloudflare.com", "104.16.132.229", 443)


@pytest.mark.parametrize("addresses", [
    ["169.254.169.254"],                 # name pointing at cloud metadata
    ["127.0.0.1"],                       # name pointing at this machine
    ["104.16.132.229", "10.0.0.5"],      # one public, one private: refuse
    ["::ffff:192.168.0.1"],
])
def test_names_resolving_to_internal_addresses_are_blocked(monkeypatch, addresses):
    fake_dns(monkeypatch, addresses)
    with pytest.raises(ScanError) as e:
        run(resolve_target("evil.example"))
    assert e.value.code == "blocked_target"


def test_dns_failure(monkeypatch):
    fake_dns(monkeypatch, None)
    with pytest.raises(ScanError) as e:
        run(resolve_target("no-such-host.example"))
    assert e.value.code == "dns_failed"


def test_practice_is_the_only_local_target(monkeypatch):
    fake_dns(monkeypatch, None)   # no DNS lookup happens for "practice"
    t = run(resolve_target("practice"))
    assert (t.ip, t.port) == ("127.0.0.1", targets.PRACTICE_PORT)


@pytest.mark.parametrize("ip", ["64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe", "64:ff9b::808:808"])
def test_nat64_addresses_are_refused(ip):
    assert is_blocked(ip)   # even a public IPv4 inside is refused: we play it safe
