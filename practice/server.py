"""The practice server: a real TLS server we control, for the "Flip the lock" demo.

It is `openssl s_server` listening on 127.0.0.1:8443 with TLS 1.3 only.
Switching modes really stops the process and starts it again with a
different list of key exchange groups it is willing to use:

    classical: X25519                    (the old method)
    hybrid:    X25519MLKEM768:X25519     (the new method first)

A fresh self-signed certificate and key are made at startup in a temporary
folder outside the repo, so no private key is ever committed.
"""

import asyncio
import os
import socket
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

MODES = {
    "classical": "X25519",
    "hybrid": "X25519MLKEM768:X25519",
}
HOST = "127.0.0.1"
PORT = int(os.environ.get("PRACTICE_PORT", "8443"))
READY_TIMEOUT = 10   # seconds to wait for the restarted server to accept connections


def make_self_signed_cert(folder):
    """Write cert.pem and key.pem for the name "practice" and return their paths."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "practice")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=7))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("practice")]),
                           critical=False)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = Path(folder) / "cert.pem", Path(folder) / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    return str(cert_path), str(key_path)


async def wait_for_port(host, port, timeout=READY_TIMEOUT):
    """Poll until something accepts TCP connections on host:port.

    Each attempt is a plain socket connect with a 0.3 s timeout, run in a
    thread. On Windows a connection to a closed local port takes about 2 s to
    be refused, and cancelling an asyncio connect waits for that, which would
    slow every flip down.
    """
    def try_connect():
        try:
            socket.create_connection((host, port), timeout=0.3).close()
            return True
        except OSError:
            return False

    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        if await asyncio.to_thread(try_connect):
            return True
        if loop.time() >= deadline:
            return False
        await asyncio.sleep(0.05)


class PracticeServer:
    def __init__(self, openssl, host=HOST, port=PORT):
        self.openssl, self.host, self.port = openssl, host, port
        self.mode = None
        self.proc = None
        self.lock = asyncio.Lock()   # one restart at a time
        self.tmpdir = tempfile.TemporaryDirectory(prefix="flip-practice-")
        self.cert, self.key = make_self_signed_cert(self.tmpdir.name)

    async def _start(self, mode):
        # If something else already holds the port (say a leftover s_server
        # from a crashed run), we would be checking the wrong server.
        if await wait_for_port(self.host, self.port, timeout=0):
            raise RuntimeError(f"port {self.port} is already in use; stop the old "
                               "process or set PRACTICE_PORT to another port")
        self.proc = await asyncio.create_subprocess_exec(
            self.openssl, "s_server",
            "-accept", f"{self.host}:{self.port}",
            "-cert", self.cert, "-key", self.key,
            "-tls1_3", "-groups", MODES[mode],
            "-www",      # answer each connection with a small status page, keep running
            "-quiet",
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        if not await wait_for_port(self.host, self.port) or self.proc.returncode is not None:
            await self._stop()
            raise RuntimeError("practice server did not start")
        self.mode = mode

    async def _stop(self):
        if self.proc and self.proc.returncode is None:
            self.proc.kill()
            await self.proc.wait()
        self.proc = None
        self.mode = None   # nothing is running, so do not report an old mode

    @property
    def running(self):
        """True while our own s_server process is alive."""
        return self.proc is not None and self.proc.returncode is None

    async def set_mode(self, mode):
        """Really restart s_server with the group list for `mode`."""
        if mode not in MODES:
            raise ValueError(mode)
        async with self.lock:
            if mode == self.mode and self.proc and self.proc.returncode is None:
                return self.mode   # already in this mode: no pointless restart
            await self._stop()
            await self._start(mode)
        return self.mode

    async def close(self):
        async with self.lock:
            await self._stop()
        self.tmpdir.cleanup()
