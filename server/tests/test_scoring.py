import pytest

from server import scoring


def hs(kx, tls13=True, tls12=True, picked="X25519"):
    return {"keyExchange": kx, "supportsTls13": tls13, "acceptsTls12": tls12,
            "serverPicked": picked}


@pytest.mark.parametrize("handshake,points,label", [
    (hs("hybrid_pq", True, True, "X25519MLKEM768"), 95, "ready"),
    (hs("hybrid_pq", True, False, "X25519MLKEM768"), 100, "ready"),
    (hs("classical", True, True), 35, "not_ready"),
    (hs("classical", True, False), 40, "not_ready"),
    (hs("classical", False, True, "secp256r1"), 25, "not_ready"),
    (hs("static_rsa", False, True, None), 5, "not_ready"),
    (hs("unknown", False, False, None), 0, "not_ready"),
])
def test_score_and_label(handshake, points, label):
    v = scoring.verdict(handshake)
    assert v["score"] == points and v["label"] == label


def test_harvest_window_only_closed_by_hybrid():
    assert scoring.verdict(hs("hybrid_pq", picked="X25519MLKEM768"))["harvestWindowOpen"] is False
    for kx in ("classical", "static_rsa", "unknown"):
        assert scoring.verdict(hs(kx))["harvestWindowOpen"] is True


def titles(handshake):
    return [f["title"] for f in scoring.verdict(handshake)["fixes"]]


def test_fixes():
    assert titles(hs("hybrid_pq", True, False)) == []
    assert titles(hs("hybrid_pq", True, True)) == ["Retire TLS 1.2 when old clients are gone."]
    assert titles(hs("classical", True, True)) == [scoring.FIX_HYBRID["title"]]
    assert titles(hs("classical", False, True)) == [scoring.FIX_TLS13["title"],
                                                    scoring.FIX_HYBRID["title"]]
    assert titles(hs("static_rsa", False, True, None)) == [scoring.FIX_STATIC_RSA["title"],
                                                          scoring.FIX_TLS13["title"],
                                                          scoring.FIX_HYBRID["title"]]


LONGEST_GROUP = "brainpoolP512r1tls13"


@pytest.mark.parametrize("handshake", [
    hs("hybrid_pq"), hs("classical", True, True, LONGEST_GROUP),
    hs("classical", False, True, LONGEST_GROUP), hs("classical", True, True, None),
    hs("static_rsa", False, True, None), hs("unknown", False, False, None),
])
def test_text_limits_and_banned_words(handshake):
    v = scoring.verdict(handshake)
    assert len(v["headline"]) <= 80
    assert len(v["reason"]) <= 160
    assert len(v["fixes"]) <= 3
    text = " ".join([v["headline"], v["reason"]] +
                    [f["title"] + " " + f["detail"] for f in v["fixes"]]).lower()
    for word in ("secure", "insecure", "safe", "unsafe", "hacked", "—"):
        assert word not in text


def test_years_for():
    assert scoring.years_for("health_records") == 30
    assert scoring.years_for("login_session") == 0
    assert scoring.years_for("bank_records", 10) == 10
    assert scoring.years_for("custom", 7) == 7
    for bad in [("custom", None), ("pets", None), ("health_records", 101),
                ("health_records", -1), ("pets", 5)]:
        with pytest.raises(ValueError):
            scoring.years_for(*bad)


@pytest.mark.parametrize("kx,years,urgency", [
    ("hybrid_pq", 30, "none"),
    ("classical", 30, "high"),      # 2026 + 30 = 2056 > 2040
    ("classical", 14, "medium"),    # 2040 is not after 2040, but is after 2030
    ("classical", 5, "medium"),     # 2031 > 2030
    ("classical", 4, "low"),        # 2030 is not after 2030
    ("static_rsa", 0, "low"),
])
def test_shelf_life_urgency(kx, years, urgency):
    s = scoring.shelf_life(hs(kx), "custom", years, 2026)
    assert s["urgency"] == urgency
    assert s["secretUntilYear"] == 2026 + years
    assert s["quantumArrivalYear"] == 2040 and s["quantumArrivalIsAssumption"] is True


def test_urgency_never_changes_score():
    h = hs("classical")
    assert scoring.score(h) == 35
    scoring.shelf_life(h, "government_docs", 50, 2026)
    assert scoring.score(h) == 35
