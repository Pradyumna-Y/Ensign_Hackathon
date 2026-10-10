"""Scoring: turn a handshake section into a verdict and a shelf-life estimate.

Pure functions only, no network, so every rule is easy to test and explain.
Certificates are never scored: they matter for impersonation in the future,
not for traffic that was recorded today.
"""

KEY_EXCHANGE_POINTS = {"hybrid_pq": 80, "classical": 20, "static_rsa": 0, "unknown": 0}
READY_AT = 80

QUANTUM_ARRIVAL_YEAR = 2040   # an assumption, and labeled as one everywhere

# How long each kind of data usually has to stay secret, in years.
DATA_TYPE_YEARS = {
    "health_records": 30,
    "bank_records": 25,
    "government_docs": 50,
    "login_session": 0,
}


def version_points(handshake):
    tls13, tls12 = handshake["supportsTls13"], handshake["acceptsTls12"]
    if tls13 and not tls12:
        return 20
    if tls13 and tls12:
        return 15
    if tls12:
        return 5
    return 0


def score(handshake):
    return KEY_EXCHANGE_POINTS[handshake["keyExchange"]] + version_points(handshake)


def _headline_and_reason(handshake):
    kx = handshake["keyExchange"]
    group = handshake["serverPicked"]
    if kx == "hybrid_pq":
        method = group or "a hybrid method"
        return ("Our scanner connected to this site using hybrid post-quantum key exchange.",
                f"The site picked {method}, a hybrid post-quantum method. "
                "Other clients and older TLS versions may differ.")
    if kx == "classical":
        method = group or "a classical method"
        if handshake["supportsTls13"]:
            reason = (f"The site agreed on its key with {method}. Today's computers cannot "
                      "break that, but a future quantum computer could.")
        else:
            reason = (f"We only completed a TLS 1.2 connection, where the site agreed on "
                      f"its key with {method}, which a future quantum computer could break.")
        return ("Recorded traffic to this site could be read once quantum computers arrive.",
                reason)
    if kx == "static_rsa":
        return ("Recorded traffic could be read later, by quantum computers or a stolen key.",
                "The site uses RSA key exchange, so the server's long-term key unlocks "
                "recorded traffic, and a future quantum computer could recover that key.")
    return ("We could not tell how this site agrees on its key.",
            "The handshake finished, but we could not identify the key exchange method.")


FIX_TLS13 = {"title": "Turn on TLS 1.3.",
             "detail": "Post-quantum key exchange only works on TLS 1.3."}
FIX_HYBRID = {"title": "Turn on hybrid post-quantum key exchange (X25519MLKEM768).",
              "detail": "This is usually a library upgrade (OpenSSL 3.5 or later) or a "
                        "setting in your hosting provider or CDN."}
FIX_STATIC_RSA = {"title": "Stop using RSA key exchange.",
                  "detail": "It also fails to protect recorded traffic against theft of "
                            "the server key."}
FIX_RETIRE_TLS12 = {"title": "Retire TLS 1.2 when old clients are gone.",
                    "detail": "Optional. Clients that only speak TLS 1.2 still get a "
                              "classical key exchange."}


def fixes(handshake):
    kx = handshake["keyExchange"]
    out = []
    if kx == "static_rsa":
        out.append(FIX_STATIC_RSA)
    if not handshake["supportsTls13"]:
        out.append(FIX_TLS13)
    if kx != "hybrid_pq":
        out.append(FIX_HYBRID)
    elif handshake["acceptsTls12"]:
        out.append(FIX_RETIRE_TLS12)
    return [dict(f) for f in out[:3]]


def verdict(handshake):
    points = score(handshake)
    headline, reason = _headline_and_reason(handshake)
    return {
        "label": "ready" if points >= READY_AT else "not_ready",
        "score": points,
        "headline": headline,
        "reason": reason,
        "harvestWindowOpen": handshake["keyExchange"] != "hybrid_pq",
        "fixes": fixes(handshake),
    }


def years_for(data_type, years=None):
    """Years the data must stay secret. Raises ValueError on bad input."""
    if years is not None:
        if not 0 <= years <= 100:
            raise ValueError("years must be between 0 and 100")
        if data_type not in DATA_TYPE_YEARS and data_type != "custom":
            raise ValueError("unknown data type")
        return years
    if data_type == "custom":
        raise ValueError("custom needs years")
    if data_type not in DATA_TYPE_YEARS:
        raise ValueError("unknown data type")
    return DATA_TYPE_YEARS[data_type]


def shelf_life(handshake, data_type, years, current_year):
    """How long the data must stay secret versus when quantum computers may arrive.

    Urgency is shown to the user but never changes the score.
    """
    secret_until = current_year + years
    if handshake["keyExchange"] == "hybrid_pq":
        urgency = "none"
    elif secret_until > QUANTUM_ARRIVAL_YEAR:
        urgency = "high"
    elif secret_until > 2030:
        urgency = "medium"
    else:
        urgency = "low"
    return {
        "dataType": data_type,
        "years": years,
        "secretUntilYear": secret_until,
        "quantumArrivalYear": QUANTUM_ARRIVAL_YEAR,
        "quantumArrivalIsAssumption": True,
        "urgency": urgency,
    }
