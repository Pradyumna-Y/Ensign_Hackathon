# Flip the Lock: shared contract

Both builders read this first. It is the source of truth for the API, the wording, and the schedule. If it must change, tell the other person and edit this file in the same commit as the code that depends on it.

## What we are building

A website where a judge types a site address and sees whether that site's HTTPS connection is ready for the quantum era.

The problem: when a browser and a site start a secure connection, they agree on a secret key using math that a future quantum computer could break. Someone can record the scrambled traffic today and read it later ("harvest now, decrypt later"). A newer hybrid key exchange (X25519MLKEM768, built on the NIST ML-KEM standard) fixes this, and big sites are switching it on now.

The headline demo, "Flip the Lock": a practice server we control. The judge switches it from the old method to the new one, rescans, and watches the verdict flip from "Not ready yet" to "Ready".

## Honest scope (use this wording everywhere)

- We check one thing: how the connection agrees on its secret key, plus the TLS version.
- Labels are "Ready" and "Not ready yet". We never say "secure", "insecure", "safe", "unsafe" or "hacked".
- Not ready today is normal and not a sign of carelessness. Ordinary computers cannot break these connections today.
- We cannot see databases, passwords, or anything behind the connection.
- Certificates are shown for context but not scored. They matter for impersonation later, not for recorded traffic.
- The year quantum computers arrive is an assumption. We use 2040 and say so on screen. Estimates vary.
- Live results are labeled "Live scan". Saved results are labeled "Saved result from <time>". Never present a saved result as live.

## Who owns what

| Person | Owns |
|---|---|
| A | /server, /practice, /scripts, Dockerfile, README |
| B | /web |

Shared files: CONTRACT.md, LEARNED.md. Do not edit the other person's folder. Ask instead.

## Event rules that affect us

- All work happens during the event. Libraries and open-source code are allowed. Confirm with the organizers that working off-site overnight is allowed; if anyone says otherwise, stop and ask.
- Before submitting, list development tools honestly in the README and the submission, and answer questions about them.
- The repo is public and stays public. Never commit secrets, .env files, or private keys.
- Everyone must be able to explain every part of their code to judges (the Learning criterion). Keep LEARNED.md: each person adds what they learned, with the time.
- Submission category: Technical Solution.

## Git

One repo, branch main, small commits. Run `git pull --rebase` before every push. Separate folders mean no merge conflicts.

## Running it

- The backend serves the files in /web at "/" (same origin, no CORS needed).
- Frontend without the backend: open /web/index.html?mock=1 (or run `python -m http.server` inside /web). Mock mode reads /web/fixtures/*.json.
- Full app: see the README (Docker is the supported way, because the scanner needs OpenSSL 3.5 or later).

## API

All responses are JSON. Errors never leak stack traces.

### GET /api/scan?host=<hostname>&data=<dataType>&years=<int>

- `host`: a public hostname, or the reserved name `practice`, which scans our local practice server. Send only the name: the API rejects `https://`, paths, ports and IP addresses with `invalid_host`, so the frontend should strip a scheme or path the user pasted before sending.
- `data`: one of `health_records` (default years 30), `bank_records` (25), `government_docs` (50), `login_session` (0), `custom` (needs `years`).
- `years`: optional override, 0 to 100.

Returns a ScanResult:

```json
{
  "host": "cloudflare.com",
  "scannedAt": "2026-10-10T07:12:03Z",
  "source": "live",
  "status": "ok",
  "error": null,
  "handshake": {
    "tlsVersion": "TLSv1.3",
    "cipherSuite": "TLS_AES_256_GCM_SHA384",
    "weOffered": ["X25519MLKEM768", "X25519", "secp256r1", "secp384r1"],
    "serverPicked": "X25519MLKEM768",
    "keyExchange": "hybrid_pq",
    "supportsTls13": true,
    "acceptsTls12": true
  },
  "certificate": {
    "keyType": "ECDSA",
    "keyBits": 256,
    "signature": "ecdsa-with-SHA256",
    "expires": "2027-01-04",
    "note": "Shown for context. Not scored."
  },
  "verdict": {
    "label": "ready",
    "score": 95,
    "headline": "Recorded traffic to this site is protected against future quantum attacks.",
    "reason": "The site agreed on its key using a hybrid post-quantum method.",
    "harvestWindowOpen": false,
    "fixes": [
      {
        "title": "Retire TLS 1.2 when old clients are gone.",
        "detail": "Optional. Clients that only speak TLS 1.2 still get a classical key exchange."
      }
    ]
  },
  "shelfLife": {
    "dataType": "health_records",
    "years": 30,
    "secretUntilYear": 2056,
    "quantumArrivalYear": 2040,
    "quantumArrivalIsAssumption": true,
    "urgency": "none"
  }
}
```

Field rules:

- `source`: `live` or `cached`.
- `status`: `ok` or `error`. When `error`, `handshake`, `certificate`, `verdict` and `shelfLife` are null and `error` is `{ "code": "...", "message": "plain English, safe to show" }`.
- `error.code`: `invalid_host`, `invalid_input` (bad `data` or `years`), `blocked_target`, `dns_failed`, `timeout`, `no_tls`, `rate_limited`, `internal`.
- HTTP status: errors in the request get 4xx (`invalid_host` and `invalid_input` 400, `blocked_target` 403, `rate_limited` 429) and `internal` gets 500. A scan that ran but could not reach a TLS server (`dns_failed`, `timeout`, `no_tls`) is HTTP 200 with `status: "error"`. Always read the JSON body, whatever the status.
- `handshake.keyExchange`: `hybrid_pq`, `classical`, `static_rsa`, or `unknown`.
- `handshake.serverPicked` can be null (for example TLS 1.2 with no named group).
- `verdict.label`: `ready` (score 80 to 100) or `not_ready` (score 0 to 79).
- `verdict.headline` is at most 80 characters, `reason` at most 160, `fixes` is at most 3 items of `{ "title": "...", "detail": "..." }`. The frontend renders these as given and never hardcodes verdict text.
- `shelfLife.urgency`: `none`, `low`, `medium`, `high`. Only meaningful when the key exchange is not hybrid.

### GET /api/practice

Returns `{ "mode": "classical" | "hybrid", "scanHost": "practice" }`.

### POST /api/practice/mode

Body: `{ "mode": "classical" | "hybrid" }`. Really reconfigures and restarts the practice server, waits until it is accepting connections (about 1 to 3 seconds), then returns `{ "mode": "<new mode>" }`.

### GET /api/cached

Returns an array of ScanResult (each with `source: "cached"`), the latest saved result per demo site.

### GET /api/demo-sites

Returns `{ "sites": ["cloudflare.com", "..."] }`.

### GET /api/health

Returns `{ "ok": true, "opensslVersion": "3.5.x", "hybridSelfTest": true }`.

### Limits the frontend must respect

- At most 4 scans in flight at once.
- HTTP 429 means wait a few seconds and retry; show a friendly message.

## Demo script (both of us build toward this)

1. A judge types any site. Within about 5 seconds they see a plain-English verdict, which key method the site picked, and the timeline.
2. Open "Flip the lock". The practice server is on the old method and shows "Not ready yet". The judge flips the switch, the practice server really restarts with the new method, the page rescans, and the verdict changes to "Ready".
3. 10 seconds of explanation: "Attackers can record traffic today and decrypt it later. This checks whether a site is using the new method that stops that."

## Schedule (overnight work allowed)

- By about 1 AM: A has real scans coming back from /api/scan with scoring. B has the scan and verdict screens finished on mock fixtures.
- By about 3 AM: practice server and toggle work. B's Flip the lock panel works against the real API. Then sleep. A tired team ships bugs.
- Sat 7:30 AM: seed the cache, full integration pass, polish.
- Sat 10:00 AM: feature freeze. Only bug fixes after this.
- Sat 10:00 to 11:30 AM: rehearse the demo, record a 45 to 60 second backup screen recording, final checks.
- Sat 11:30 AM: final push and submit. Build ends at 12:00 PM.

## Cut order if time runs short

1. Scoreboard.
2. Shelf-life input (keep a fixed default).
3. Timeline polish.

Protect: the verdict screen, Flip the lock, and cached results.

## Final checklist

- Repo is public, README has how to run and the final development tools list, LEARNED.md is filled in.
- Cache is seeded and the practice server was tested on the demo laptop.
- Demo laptop: notifications off, sleep off, charger plugged in, browser zoomed for the projector or table.
- Backup recording saved and uploaded where the rules ask (ask organizers about the video requirement).
