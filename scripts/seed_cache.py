"""Scan every demo site once and save the results to cache/.

    python scripts/seed_cache.py

Runs one site at a time with a 1 second gap, to stay polite. Uses the same
checks and scanner as the API, so it works without the server running.
Run it on the demo laptop on the morning of the demo.
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from server import cache, scoring  # noqa: E402
from server.errors import ScanError  # noqa: E402
from server.results import ok_result  # noqa: E402
from server.scanner import find_openssl, hybrid_self_test, probe_site  # noqa: E402
from server.targets import resolve_target  # noqa: E402

DATA_TYPE = "health_records"


async def main():
    openssl, version = find_openssl()
    if not await hybrid_self_test(openssl):
        sys.exit("Hybrid self-test failed (no internet?). Not seeding.")
    print(f"OpenSSL {version}. Saving to {cache.CACHE_DIR}")

    sites = cache.demo_sites()
    for i, host in enumerate(sites):
        if i:
            await asyncio.sleep(1)
        try:
            target = await resolve_target(host)
            probe = await probe_site(openssl, target.host, target.ip, target.port)
        except ScanError as e:
            print(f"  {host:24} skipped: {e.code}")
            continue
        result = ok_result(host, probe, DATA_TYPE, scoring.years_for(DATA_TYPE))
        cache.save(result)
        v = result["verdict"]
        print(f"  {host:24} {v['label']:9} {v['score']:3}  {probe['handshake']['serverPicked']}")


if __name__ == "__main__":
    asyncio.run(main())
