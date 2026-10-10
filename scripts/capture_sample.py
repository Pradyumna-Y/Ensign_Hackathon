"""Save a real s_client output as a parser test sample.

    python scripts/capture_sample.py <host> <tls1_3|tls1_2> <name> [port]

Writes server/tests/samples/<name>.txt using exactly the command the scanner
runs. Session secrets (master key, session ID, ticket bytes) are removed
before saving, since they are not needed for parsing.
"""

import asyncio
import re
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from server.scanner import OFFERED_GROUPS, find_openssl, run_s_client  # noqa: E402

SAMPLES = Path(__file__).resolve().parent.parent / "server" / "tests" / "samples"
SECRET_LINE = re.compile(
    r"^\s*(Master-Key|Session-ID|Resumption PSK|PSK identity|"
    r"[0-9a-f]{4} - [0-9a-f]{2}[ -]).*$", re.M)


async def main(host, version, name, port=443):
    openssl, _ = find_openssl()
    ip = socket.gethostbyname(host)
    groups = OFFERED_GROUPS if version == "tls1_3" else None
    raw = await run_s_client(openssl, ip, host, int(port), f"-{version}", groups)
    text = SECRET_LINE.sub("", raw.text.replace("\r\n", "\n"))
    SAMPLES.mkdir(parents=True, exist_ok=True)
    (SAMPLES / f"{name}.txt").write_text(text, encoding="utf-8")
    print(f"saved {name}.txt ({len(text)} chars, timed_out={raw.timed_out})")


if __name__ == "__main__":
    asyncio.run(main(*sys.argv[1:]))
