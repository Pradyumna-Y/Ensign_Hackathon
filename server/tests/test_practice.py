"""Proves the flip with a real s_server on this machine (no internet needed)."""

import asyncio

from practice.server import PracticeServer
from server import scoring
from server.scanner import find_openssl, probe_site

TEST_PORT = 18443   # not 8443, so a running dev server does not get in the way


def test_flip_changes_the_real_handshake():
    async def run():
        openssl, _ = find_openssl()
        ps = PracticeServer(openssl, port=TEST_PORT)
        results = {}
        try:
            for mode in ("classical", "hybrid", "classical"):
                await ps.set_mode(mode)
                probe = await probe_site(openssl, "practice", "127.0.0.1", TEST_PORT)
                results.setdefault(mode, []).append(probe["handshake"])
        finally:
            await ps.close()
        return results

    results = asyncio.run(run())
    for handshake in results["classical"]:
        assert handshake["serverPicked"] == "X25519"
        assert handshake["keyExchange"] == "classical"
        v = scoring.verdict(handshake)
        assert v["label"] == "not_ready" and v["score"] == 40
    hybrid = results["hybrid"][0]
    assert hybrid["serverPicked"] == "X25519MLKEM768"
    assert hybrid["supportsTls13"] and not hybrid["acceptsTls12"]
    v = scoring.verdict(hybrid)
    assert v["label"] == "ready" and v["score"] == 100
