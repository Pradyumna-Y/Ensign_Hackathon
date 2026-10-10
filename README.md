# Flip the Lock

Type a website address and see whether its HTTPS connection is ready for the
quantum era.

When a browser and a website start a secure connection, they agree on a
secret key using math that a future quantum computer could break. Someone can
record the scrambled traffic today and read it later ("harvest now, decrypt
later"). A newer hybrid key exchange, X25519MLKEM768 (built on the NIST
ML-KEM standard), stops that, and large sites are switching it on now.

Flip the Lock connects to a site, sees which key exchange the site picks, and
says "Ready" or "Not ready yet" in plain English, with a timeline of how long
your kind of data needs to stay secret. The "Flip the lock" demo switches a
practice server we control from the old method to the new one, rescans, and
shows the verdict change.

Built for Ensign BUILD, Technical Solution category.

## What we check (honest scope)

- We check one thing: how the connection agrees on its secret key, plus the
  TLS version.
- Labels are "Ready" and "Not ready yet". Not ready today is normal and not a
  sign of carelessness. Ordinary computers cannot break these connections
  today.
- We cannot see databases, passwords, or anything behind the connection.
- Certificates are shown for context but not scored. With an ephemeral key
  exchange, a stolen certificate key alone cannot decrypt traffic recorded
  today. Static RSA key exchange is the exception. We do not verify the
  certificate's identity, so a result describes the server our scanner reached.
- "Ready" means our scanner negotiated a hybrid group on this one connection.
  Other clients, older TLS versions, and other servers behind the same name
  may behave differently. A bare domain and its `www` name can differ.
- The year quantum computers arrive is an assumption. We use 2040 and say so
  on screen. Estimates vary.
- Live results are labeled "Live scan". Saved results are labeled with the
  time they were saved and are never shown as live.

## How it works

For each site we make two real TLS connections with the OpenSSL 3.5 command
line:

1. TLS 1.3, offering the hybrid groups `X25519MLKEM768`, `SecP256r1MLKEM768`
   and `SecP384r1MLKEM1024` first, then `X25519`, `secp256r1`, `secp384r1`.
   We read which group the server picked.
2. TLS 1.2 only, to see whether old clients are still accepted and whether
   the key exchange is ephemeral (ECDHE/DHE) or static RSA.

| Key exchange | Meaning |
|---|---|
| `hybrid_pq` | Picked a group containing ML-KEM. Recorded traffic stays protected. |
| `classical` | Ephemeral X25519 or elliptic curve. Fine today, breakable by a future quantum computer. |
| `static_rsa` | TLS 1.2 RSA key exchange. The server's long-term key unlocks recorded traffic. |
| `unknown` | Handshake finished but the method could not be identified. |

At startup we check that our own OpenSSL can offer the hybrid group, and we
try a test handshake with a known hybrid site (skipped without internet). A
failed handshake is retried once before we conclude a site lacks a protocol,
because a dropped packet looks the same as a refusal.

## Scoring

| Part | Points |
|---|---|
| Key exchange: hybrid_pq | 80 |
| Key exchange: classical (ephemeral) | 20 |
| Key exchange: static_rsa or unknown | 0 |
| TLS version: TLS 1.3, and TLS 1.2 not accepted | 20 |
| TLS version: TLS 1.3, and TLS 1.2 also accepted | 15 |
| TLS version: TLS 1.2 only | 5 |
| TLS version: no TLS 1.2 or 1.3 handshake | 0 |

"Ready" at 80 or above, so only hybrid key exchange can be ready. The
headline, reason and up to 3 fixes come from fixed rules.

Shelf life compares how long the chosen data must stay secret (health records
30 years, bank records 25, government documents 50, login session 0) with the
assumed 2040 quantum arrival. Urgency is shown but never changes the score.

## Running it

### Docker (recommended)

```
docker build -t flip-the-lock .
docker run --rm -p 8000:8000 -v "$PWD/cache:/app/cache" flip-the-lock
```

The `-v` option shares the `cache/` folder (see "Saved results" below) so
saved results survive restarts. Create it first (`mkdir cache`); on Linux add
`--user "$(id -u):$(id -g)"` to `docker run` so the container can write to it. Open http://localhost:8000.

If the app sits behind a proxy, start uvicorn with
`--forwarded-allow-ips=<proxy address>`, or every visitor shares one rate
limit.

### Saved results

Run `python scripts/seed_cache.py` on the demo machine, on the demo network,
before the demo. Saved results are used only when a live scan of a demo site
times out, finds no TLS, or cannot resolve the name.

### Without Docker

Needs Python 3.12 or later and OpenSSL 3.5 or later. On Windows, Git for
Windows ships a new enough OpenSSL and the scanner finds it automatically.
Set `OPENSSL_BIN` to use a different one.

```
python -m venv venv
venv\Scripts\pip install -r requirements-dev.txt
venv\Scripts\python -m uvicorn server.app:app --port 8000
```

On macOS or Linux use `venv/bin/` instead of `venv\Scripts\`. The OpenSSL
that ships with macOS (LibreSSL) is too old: run `brew install openssl@3` and
set `OPENSSL_BIN=/opt/homebrew/opt/openssl@3/bin/openssl`. Linux releases
older than Debian 13 or Ubuntu 25.04 also need a newer OpenSSL. The practice
server uses port 8443; if something else holds it, set `PRACTICE_PORT` to
another port, and the app still starts without the practice server. On Windows,
do not add `--reload`: reload mode switches to an event loop that cannot
start the OpenSSL processes.

### Useful commands

| Command | What it does |
|---|---|
| `python -m server.scan cloudflare.com` | Scan one site from the command line |
| `python -m server.scan a.com b.com` | Scan several sites and print a table |
| `python scripts/seed_cache.py` | Save fresh results for the demo sites (run on demo morning) |
| `python scripts/prove_flip.py` | Flip the practice server both ways against a running API |
| `python scripts/check_demo.py` | Seven pass/fail checks against a running app; run it before a demo |
| `python -m pytest` | Run the tests |

The frontend alone, without the backend: open `web/index.html?mock=1`
through `python -m http.server` inside `web/`.

## API

Full details are in [CONTRACT.md](CONTRACT.md).

| Endpoint | Purpose |
|---|---|
| `GET /api/scan?host=&data=&years=` | Scan a site, returns a ScanResult |
| `GET /api/practice` | Current practice server mode |
| `POST /api/practice/mode` | Really restart the practice server in `classical` or `hybrid` mode |
| `GET /api/cached` | Saved results for the demo sites |
| `GET /api/demo-sites` | The demo site list |
| `GET /api/health` | OpenSSL version and hybrid self-test result |

## Security notes

`/api/scan` connects to hosts that strangers type, so we treat it as a
security-sensitive surface:

- Strict hostname check: no IP addresses, no `localhost`, no port, path,
  whitespace or leading hyphen.
- We resolve DNS ourselves and refuse the scan if any address is private,
  loopback, link-local (including the 169.254.169.254 cloud metadata
  service), multicast, reserved or otherwise not public, for IPv4 and IPv6,
  including IPv6 forms that wrap an IPv4 address.
- We connect to the exact IP we checked and send the name only as SNI, so
  the name cannot be re-resolved to an internal address in between (DNS
  rebinding).
- Port 443 only. The reserved name `practice` maps to our own practice
  server and is the only way to reach a local port.
- 8 second timeout per handshake, 20 seconds for the scan itself, output size capped.
- At most 6 scans at once (3 per client), and about 30 scans per minute per
  client IP (HTTP 429 after that). The practice server has its own, larger
  limit so flipping it cannot be locked out by outside scans.
- At most 8 DNS lookups at once.
- OpenSSL runs with an argument list, never through a shell. Responses never
  include raw OpenSSL output or stack traces.
- The practice server's certificate and key are made fresh at startup in a
  temporary folder and never committed.

If the scanner is deployed somewhere, the practice server must run on a
machine we control, not behind a platform that terminates TLS for us.
Otherwise the key exchange would be the platform's, not ours.

## Project layout

| Path | Owner | Contents |
|---|---|---|
| `server/` | Person A | Scanner, scoring, API, saved results |
| `practice/` | Person A | Practice TLS server and mode switch |
| `scripts/` | Person A | Seeding, sample capture, flip proof |
| `web/` | Person B | Frontend (plain HTML, CSS, JavaScript) |
| `CONTRACT.md` | Shared | API and wording both sides follow |
| `LEARNED.md` | Shared | What each of us learned, with times |

