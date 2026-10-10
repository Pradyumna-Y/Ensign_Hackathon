"""Deciding what we are allowed to connect to.

/api/scan connects to whatever hostname a stranger types, so this is the
security boundary. The rules:

1. The name must be a plain public DNS name: no IP literals, no "localhost",
   no port, path or whitespace.
2. We resolve it ourselves and refuse if ANY address is private, loopback,
   link-local (this includes the 169.254.169.254 cloud metadata service),
   multicast, reserved or otherwise not on the public internet.
3. We then connect to the exact IP we checked and send the name only as SNI,
   so the name cannot be re-resolved to an internal address in between
   (DNS rebinding).
4. Port 443 only. The reserved name "practice" maps to our own practice
   server on this machine, and that is the only way to reach a local port.
"""

import asyncio
import ipaddress
import os
import re
import socket
from dataclasses import dataclass

from server.errors import ScanError

PRACTICE_HOST = "practice"
PRACTICE_PORT = int(os.environ.get("PRACTICE_PORT", "8443"))
DNS_TIMEOUT = 5
MAX_DNS_LOOKUPS = 8   # lookups still running count, even after we stopped waiting
_dns_gate = asyncio.Semaphore(MAX_DNS_LOOKUPS)

# One DNS label: letters, digits and hyphens, 1 to 63 chars, no hyphen at either end.
LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
HOSTNAME = re.compile(rf"{LABEL}(\.{LABEL})+")   # used with fullmatch

# Well-known cloud metadata addresses. They are already blocked as
# link-local or private; listing them makes the intent obvious and testable.
METADATA_IPS = {
    ipaddress.ip_address("169.254.169.254"),   # AWS, GCP, Azure, ...
    ipaddress.ip_address("fd00:ec2::254"),     # AWS over IPv6
    ipaddress.ip_address("100.100.100.200"),   # Alibaba Cloud
}


@dataclass
class Target:
    host: str   # what we send as SNI and show to the user
    ip: str     # the address we checked and will connect to
    port: int


def normalize_host(raw):
    """Return the cleaned hostname or raise ScanError("invalid_host")."""
    if not isinstance(raw, str):
        raise ScanError("invalid_host")
    host = raw.strip().lower()
    if host and not host.isascii():   # an international name: use its ASCII form
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            raise ScanError("invalid_host")
    if host.endswith("."):
        host = host[:-1]   # "example.com." is the same name as "example.com"
    if host == PRACTICE_HOST:
        return host
    if len(host) > 253 or not HOSTNAME.fullmatch(host):
        raise ScanError("invalid_host")
    if host == "localhost" or host.endswith(".localhost"):
        raise ScanError("invalid_host")
    # Every real top-level domain starts with a letter. This rejects IP
    # literals like 127.0.0.1, 10.1 and the hex form 0x7f.0.0.0x1.
    if not host.rsplit(".", 1)[1][0].isalpha():
        raise ScanError("invalid_host")
    return host


def is_blocked(ip):
    """True if this address is not a normal public internet address."""
    ip = ipaddress.ip_address(ip)
    if ip.version == 6:
        # IPv6 forms that carry an IPv4 address inside are judged by that address.
        embedded = ip.ipv4_mapped or ip.sixtofour or (ip.teredo and ip.teredo[1])
        if embedded and is_blocked(embedded):
            return True
    return (ip in METADATA_IPS or ip.is_private or ip.is_loopback
            or ip.is_link_local or ip.is_multicast or ip.is_reserved
            or ip.is_unspecified or not ip.is_global)


async def resolve_target(raw_host):
    """Validate, resolve and check a hostname. Returns a Target or raises ScanError."""
    host = normalize_host(raw_host)
    if host == PRACTICE_HOST:
        return Target(host, "127.0.0.1", PRACTICE_PORT)

    loop = asyncio.get_running_loop()
    try:
        await asyncio.wait_for(_dns_gate.acquire(), DNS_TIMEOUT)
    except asyncio.TimeoutError:
        raise ScanError("rate_limited")
    try:
        lookup = asyncio.ensure_future(loop.getaddrinfo(host, 443, type=socket.SOCK_STREAM))
    except BaseException:
        _dns_gate.release()
        raise

    def lookup_finished(done):
        # A lookup keeps its thread until the resolver answers, even after we
        # stop waiting, so the slot is only freed here.
        _dns_gate.release()
        if not done.cancelled():
            done.exception()   # mark any error as seen

    lookup.add_done_callback(lookup_finished)
    try:
        infos = await asyncio.wait_for(asyncio.shield(lookup), DNS_TIMEOUT)
    except (socket.gaierror, asyncio.TimeoutError, UnicodeError):
        raise ScanError("dns_failed")
    addresses = list(dict.fromkeys(info[4][0] for info in infos))
    if not addresses:
        raise ScanError("dns_failed")
    if any(is_blocked(a) for a in addresses):
        raise ScanError("blocked_target")

    # Prefer IPv4: many laptops and venue networks have no IPv6 route.
    addresses.sort(key=lambda a: ":" in a)
    return Target(host, addresses[0], 443)
