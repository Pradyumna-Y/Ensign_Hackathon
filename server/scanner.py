"""Scanner core: two OpenSSL handshakes against one site, then read the result.

We drive the openssl command line (3.5 or later) because it is the first
release that can offer the hybrid post-quantum group X25519MLKEM768.
Probe 1 asks for TLS 1.3 and offers the new group first. Probe 2 asks for
TLS 1.2 only, to see whether old clients are still accepted and which key
exchange they get.
"""

import asyncio
import os
import re
import shutil
import socket
import subprocess
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa

from server.errors import ScanError

# What our TLS 1.3 probe offers, in order of preference. The extra hybrid
# groups and secp384r1 are there so a server that only supports one of them is
# not wrongly reported as "no TLS 1.3" or "classical".
OFFERED_GROUPS = ["X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024",
                  "X25519", "secp256r1", "secp384r1"]
# Used for one retry if the first TLS 1.3 attempt failed: a short ClientHello
# with no large ML-KEM key share, in case something in the path dislikes it.
FALLBACK_GROUPS = ["X25519", "secp256r1", "secp384r1"]
# Groups that combine ML-KEM with a classical exchange. Pure ML-KEM groups are
# deliberately not listed.
HYBRID_GROUPS = {"x25519mlkem768", "secp256r1mlkem768", "secp384r1mlkem1024"}

PROBE_TIMEOUT = 8          # seconds per openssl run
MAX_OUTPUT = 256 * 1024    # bytes; a normal handshake prints about 15 KB

# Places Git for Windows puts its OpenSSL, used when "openssl" on PATH is too old.
WINDOWS_CANDIDATES = [
    r"C:\Program Files\Git\mingw64\bin\openssl.exe",
    r"C:\Program Files\Git\usr\bin\openssl.exe",
]


# ---------------------------------------------------------------------------
# Finding OpenSSL
# ---------------------------------------------------------------------------

def openssl_version(binary):
    """Return (major, minor, patch, text) for an openssl binary, or None."""
    try:
        out = subprocess.run([binary, "version"], capture_output=True,
                             text=True, timeout=5).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = re.match(r"OpenSSL (\d+)\.(\d+)\.(\d+)", out)
    if not m:
        return None
    return int(m[1]), int(m[2]), int(m[3]), out.split()[1]


def find_openssl():
    """Pick the first OpenSSL that is 3.5 or later. OPENSSL_BIN overrides."""
    candidates = [os.environ.get("OPENSSL_BIN"), shutil.which("openssl"),
                  *WINDOWS_CANDIDATES]
    for binary in candidates:
        if not binary:
            continue
        version = openssl_version(binary)
        if version and version[:2] >= (3, 5):
            return binary, version[3]
    raise SystemExit(
        "No OpenSSL 3.5 or later found. It is needed to offer X25519MLKEM768. "
        "Install Git for Windows, use the Docker image, or set OPENSSL_BIN."
    )


# ---------------------------------------------------------------------------
# Running s_client
# ---------------------------------------------------------------------------

@dataclass
class RawProbe:
    text: str
    timed_out: bool = False
    too_large: bool = False


async def _read_capped(stream, limit):
    chunks, total = [], 0
    while True:
        chunk = await stream.read(65536)
        if not chunk:
            return b"".join(chunks), False
        total += len(chunk)
        if total > limit:
            return b"".join(chunks), True
        chunks.append(chunk)


async def run_s_client(openssl, ip, host, port, version_flag, groups=None):
    """Run one `openssl s_client` handshake and return its text output.

    We connect to the IP we resolved ourselves and pass the hostname only as
    SNI (-servername). Arguments are a list, never a shell string, so a
    hostname can never be interpreted as a command.
    """
    target = f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"
    # -verify_hostname only records whether the certificate fits the name (it
    # does not stop the handshake), so the result can show an identity check.
    args = [openssl, "s_client", "-connect", target, "-servername", host,
            "-verify_hostname", host, version_flag, "-showcerts"]
    if groups:
        args += ["-groups", ":".join(groups)]

    proc = await asyncio.create_subprocess_exec(
        *args,
        stdin=asyncio.subprocess.DEVNULL,   # closed stdin: s_client quits after the handshake
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    try:
        try:
            data, too_large = await asyncio.wait_for(
                _read_capped(proc.stdout, MAX_OUTPUT), PROBE_TIMEOUT)
            timed_out = False
        except asyncio.TimeoutError:
            data, too_large, timed_out = b"", False, True
    finally:
        # Also runs when the scan is cancelled, so no openssl process is left behind.
        if proc.returncode is None:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
        await proc.wait()
    return RawProbe(data.decode("utf-8", "replace"), timed_out, too_large)


# ---------------------------------------------------------------------------
# Parsing s_client output
# ---------------------------------------------------------------------------

@dataclass
class Probe:
    ok: bool                  # handshake completed
    protocol: str | None      # "TLSv1.3", "TLSv1.2"
    cipher: str | None        # e.g. "TLS_AES_128_GCM_SHA256" or "ECDHE-RSA-AES128-GCM-SHA256"
    group: str | None         # key exchange group the server picked, e.g. "X25519MLKEM768"
    cert_pem: str | None      # the server's own (leaf) certificate
    failure: str | None       # why it failed: timeout, connect_failed, not_tls, handshake_refused
    verify: tuple | None = None   # (OpenSSL verify code, text) for the certificate, if printed
    evidence: tuple = ()          # the s_client lines the verdict was read from


NEW_LINE = re.compile(r"^New, (\S+), Cipher is (\S+)", re.M)
# The "New," line shows the first protocol version that defined the cipher, not
# the version that was negotiated (a TLS 1.2 handshake with a CBC suite says
# TLSv1.0 there), so the negotiated version comes from this line.
PROTOCOL = re.compile(r"^Protocol\s*:\s*(\S+)", re.M)
NEGOTIATED = re.compile(r"^Negotiated TLS1\.3 group: (\S+)", re.M)
TEMP_KEY = re.compile(r"^(?:Peer|Server) Temp Key: (.+)$", re.M)
VERIFY = re.compile(r"^\s*Verify return code: (-?\d+) \((.*)\)\s*$", re.M)
PEM_BLOCK = re.compile(
    r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.S)

# OpenSSL calls P-256 "prime256v1"; the TLS name is secp256r1.
CURVE_NAMES = {"prime256v1": "secp256r1", "x25519": "X25519", "x448": "X448"}


def _group_from_temp_key(value):
    """'X25519, 253 bits' -> X25519, 'ECDH, prime256v1, 256 bits' -> secp256r1."""
    parts = [p.strip() for p in value.split(",")]
    if parts[0] == "ECDH" and len(parts) > 1:
        name = parts[1]
    elif parts[0] == "DH":
        name = "DH"   # finite-field Diffie-Hellman, still classical
    else:
        name = parts[0]
    return CURVE_NAMES.get(name, name)


def _summary(text):
    """The part of the output OpenSSL writes itself, after the certificate chain.
    The chain is where text the peer controls (names and so on) is printed."""
    marker = "-----END CERTIFICATE-----"
    start = text.rfind(marker)
    return text[start + len(marker):] if start != -1 else text


def _last(pattern, text):
    """The last match in the text."""
    found = None
    for found in pattern.finditer(text):
        pass
    return found


def _evidence_lines(text):
    """The few s_client lines the verdict comes from, so the page can show them."""
    lines = []
    for pattern in (PROTOCOL, NEGOTIATED, TEMP_KEY, NEW_LINE):
        found = _last(pattern, _summary(text))
        if found and found[0].strip() not in lines:
            lines.append(found[0].strip()[:90])
    return tuple(lines)


def parse_s_client(raw):
    """Turn s_client text into a Probe. Works on saved samples too (see tests)."""
    if raw.timed_out:
        return Probe(False, None, None, None, None, "timeout")
    text = raw.text.replace("\r\n", "\n")

    protocol = cipher = group = None
    summary = _summary(text)
    m = _last(NEW_LINE, summary)
    if m and m[1] != "(NONE)" and m[2] != "(NONE)":
        protocol, cipher = m[1], m[2]
        negotiated = _last(PROTOCOL, summary)
        if negotiated:
            protocol = negotiated[1]

    # OpenSSL 3.5 prints "Negotiated TLS1.3 group" for hybrid groups and
    # "Peer Temp Key" for classical ones, so we read both.
    m = _last(NEGOTIATED, summary)
    if m and m[1] != "<NULL>":
        group = m[1]
    else:
        m = _last(TEMP_KEY, summary)
        if m:
            group = _group_from_temp_key(m[1])

    pem = PEM_BLOCK.search(text)
    ok = protocol is not None and not raw.too_large

    failure = None
    if not ok:
        if raw.too_large:
            failure = "not_tls"
        elif "CONNECTED(" not in text or "connect:errno" in text:
            failure = "connect_failed"
        elif "packet length too long" in text or "wrong version number" in text:
            failure = "not_tls"   # something answered, but it does not speak TLS
        else:
            failure = "handshake_refused"
    verify = VERIFY.search(text) if ok else None
    return Probe(ok, protocol, cipher, group if ok else None,
                 pem[0] if (ok and pem) else None, failure,
                 (int(verify[1]), verify[2]) if verify else None,
                 _evidence_lines(text) if ok else ())


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

def tls12_key_exchange(cipher):
    """Read the key exchange from an OpenSSL TLS 1.2 cipher suite name.

    ECDHE-/DHE- suites make a fresh key per connection (ephemeral). Suites that
    start straight with the bulk cipher (AES128-SHA, AES256-GCM-SHA384, ...)
    use RSA key exchange: the browser encrypts the secret to the server's
    long-term RSA key.
    """
    if cipher.startswith(("ECDHE-", "DHE-", "EDH-")):
        return "classical"
    if cipher.startswith(("AES", "CAMELLIA", "DES-", "RC4", "SEED", "IDEA", "ARIA")):
        return "static_rsa"
    return "unknown"


def classify(tls13, tls12):
    if tls13.ok:
        # TLS 1.3 always uses an ephemeral key exchange; the question is which group.
        if not tls13.group:
            return "unknown"   # never guess "classical" when the group was not read
        name = tls13.group.lower()
        if name in HYBRID_GROUPS:
            return "hybrid_pq"
        if "mlkem" in name:
            return "unknown"   # a pure ML-KEM group is neither hybrid nor classical
        return "classical"
    if tls12.ok:
        return tls12_key_exchange(tls12.cipher)
    return "unknown"


# ---------------------------------------------------------------------------
# Certificate (shown for context, never scored)
# ---------------------------------------------------------------------------

# Plain-English notes for the most common OpenSSL verify results.
VERIFY_NOTES = {
    0: "The certificate matches this name and chains to a trusted authority.",
    10: "The certificate has expired.",
    18: "The certificate is self-signed.",
    19: "The certificate chain ends in an untrusted root.",
    20: "We could not build a chain to a trusted authority.",
    21: "We could not build a chain to a trusted authority.",
    62: "The certificate does not match this name.",
}


def certificate_identity(verify):
    """(verified, note) from a probe's verify result. verified is None if unknown."""
    if verify is None:
        return None, "Identity was not checked."
    code, _text = verify
    return code == 0, VERIFY_NOTES.get(
        code, f"The certificate could not be confirmed (OpenSSL code {code}).")


def parse_certificate(pem):
    if not pem:
        return None
    try:
        cert = x509.load_pem_x509_certificate(pem.encode())
        key = cert.public_key()
    except Exception:   # unreadable or unsupported certificate: show no details
        return None
    if isinstance(key, rsa.RSAPublicKey):
        key_type, bits = "RSA", key.key_size
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key_type, bits = "ECDSA", key.curve.key_size
    elif isinstance(key, ed25519.Ed25519PublicKey):
        key_type, bits = "Ed25519", 256
    elif isinstance(key, ed448.Ed448PublicKey):
        key_type, bits = "Ed448", 456
    else:
        key_type, bits = type(key).__name__, None
    oid = cert.signature_algorithm_oid
    return {
        "keyType": key_type,
        "keyBits": bits,
        "signature": getattr(oid, "_name", oid.dotted_string),
        "expires": cert.not_valid_after_utc.date().isoformat(),
        "note": "Shown for context. Not scored.",
    }


# ---------------------------------------------------------------------------
# One full site probe
# ---------------------------------------------------------------------------

RETRY_FAILURES = ("timeout", "connect_failed", "handshake_refused")


async def _nothing():
    return None


def _with_identity(cert, verify):
    if cert is not None:
        cert["verified"], cert["verifyNote"] = certificate_identity(verify)
    return cert


async def probe_site(openssl, host, ip, port=443):
    """Run both probes (2 connections total) and build the handshake section.

    Returns {"handshake": {...}, "certificate": {...}} or raises ScanError.
    """
    offered = OFFERED_GROUPS   # what the successful TLS 1.3 attempt really offered
    raw13, raw12 = await asyncio.gather(
        run_s_client(openssl, ip, host, port, "-tls1_3", OFFERED_GROUPS),
        run_s_client(openssl, ip, host, port, "-tls1_2"),
    )
    tls13, tls12 = parse_s_client(raw13), parse_s_client(raw12)

    # A failed attempt is not proof that the site lacks that protocol: a dropped
    # packet or a middlebox that dislikes our large ClientHello looks the same.
    # Try once more before drawing a conclusion.
    retry13 = not tls13.ok and tls13.failure in RETRY_FAILURES
    retry12 = not tls12.ok and tls12.failure in ("timeout", "connect_failed")
    if retry13 or retry12:
        again13, again12 = await asyncio.gather(
            run_s_client(openssl, ip, host, port, "-tls1_3", FALLBACK_GROUPS)
            if retry13 else _nothing(),
            run_s_client(openssl, ip, host, port, "-tls1_2")
            if retry12 else _nothing(),
        )
        if retry13 and parse_s_client(again13).ok:
            tls13 = parse_s_client(again13)
            offered = FALLBACK_GROUPS   # the retry did not offer a hybrid group
        if retry12 and parse_s_client(again12).ok:
            tls12 = parse_s_client(again12)

    if not tls13.ok and not tls12.ok:
        if tls13.failure == "timeout" and tls12.failure == "timeout":
            raise ScanError("timeout")
        raise ScanError("no_tls")

    main = tls13 if tls13.ok else tls12
    # Say plainly when the evidence is thinner than it looks.
    limits = []
    if tls13.ok and offered is FALLBACK_GROUPS:
        limits.append("TLS 1.3 worked only after a retry without the hybrid groups, "
                      "so hybrid support was not tested on this connection.")
    if not tls13.ok and tls13.failure in ("timeout", "connect_failed"):
        limits.append("The TLS 1.3 attempt timed out, so we cannot say TLS 1.3 is unsupported.")
    if tls13.ok and not tls12.ok and tls12.failure in ("timeout", "connect_failed"):
        limits.append("The TLS 1.2 attempt timed out, so we cannot say TLS 1.2 is refused.")
    flag = "-tls1_3" if main is tls13 else "-tls1_2"
    groups = f" -groups {':'.join(offered)}" if main is tls13 else ""
    return {
        "handshake": {
            "tlsVersion": main.protocol,
            "cipherSuite": main.cipher,
            "weOffered": list(offered),
            "serverPicked": main.group,
            "keyExchange": classify(tls13, tls12),
            "supportsTls13": tls13.ok,
            "acceptsTls12": tls12.ok,
            "limits": limits,
            "evidence": {
                "command": f"openssl s_client -connect {host}:{port} -servername {host} "
                           f"{flag}{groups}",
                "lines": list(main.evidence),
            },
        },
        "certificate": _with_identity(parse_certificate(main.cert_pem), main.verify),
    }


# ---------------------------------------------------------------------------
# Startup self-test
# ---------------------------------------------------------------------------

SELF_TEST_HOST = "cloudflare.com"


def local_supports_hybrid(openssl):
    """True if this OpenSSL lists X25519MLKEM768 as a TLS 1.3 group."""
    out = subprocess.run([openssl, "list", "-tls-groups", "-tls1_3"],
                         capture_output=True, text=True, timeout=5).stdout
    return "X25519MLKEM768" in out.split(":")


async def hybrid_self_test(openssl):
    """Make sure we can really offer the hybrid group, so we never report
    "classical" because of our own tooling.

    Exits if the local OpenSSL cannot offer it. Returns True if a known
    hybrid site actually agreed to it, False if we could not reach it
    (for example no internet), in which case scans still run.
    """
    if not local_supports_hybrid(openssl):
        raise SystemExit(
            f"{openssl} cannot offer X25519MLKEM768. Use OpenSSL 3.5 or later.")
    try:
        infos = await asyncio.wait_for(
            asyncio.get_running_loop().getaddrinfo(
                SELF_TEST_HOST, 443, type=socket.SOCK_STREAM), 5)
        ip = infos[0][4][0]
        raw = await run_s_client(openssl, ip, SELF_TEST_HOST, 443,
                                 "-tls1_3", ["X25519MLKEM768"])
    except (OSError, asyncio.TimeoutError, IndexError):
        return False   # no internet or filtered DNS: start anyway
    probe = parse_s_client(raw)
    return probe.ok and probe.group == "X25519MLKEM768"
