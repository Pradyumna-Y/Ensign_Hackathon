"""Command line scanner: python -m server.scan cloudflare.com [more hosts...]

Prints the handshake and certificate sections of a ScanResult as JSON.
With several hosts it prints a summary table instead.
"""

import asyncio
import json
import socket
import sys

from server.scanner import ScanError, find_openssl, hybrid_self_test, probe_site


async def resolve(host):
    """Plain DNS lookup, IPv4 first. (The API uses the guarded resolver instead.)"""
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(
            host, 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise ScanError("dns_failed")
    infos.sort(key=lambda i: i[0] != socket.AF_INET)
    return infos[0][4][0]


async def scan_one(openssl, host):
    try:
        ip = await resolve(host)
        return await probe_site(openssl, host, ip)
    except ScanError as e:
        return {"error": {"code": e.code, "message": e.message}}


async def main(hosts):
    openssl, version = find_openssl()
    ok = await hybrid_self_test(openssl)
    print(f"OpenSSL {version} at {openssl}, hybrid self-test: {ok}", file=sys.stderr)

    if len(hosts) == 1:
        print(json.dumps(await scan_one(openssl, hosts[0]), indent=2))
        return

    print(f"{'host':26} {'keyExchange':12} {'picked':16} {'tls':8} {'1.3':5} {'1.2':5} cipher")
    for host in hosts:   # one site at a time, to stay polite
        r = await scan_one(openssl, host)
        if "error" in r:
            print(f"{host:26} error: {r['error']['code']}")
            continue
        h = r["handshake"]
        print(f"{host:26} {h['keyExchange']:12} {str(h['serverPicked']):16} "
              f"{h['tlsVersion']:8} {str(h['supportsTls13']):5} "
              f"{str(h['acceptsTls12']):5} {h['cipherSuite']}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: python -m server.scan <host> [host...]")
    asyncio.run(main(sys.argv[1:]))
