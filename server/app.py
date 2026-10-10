"""FastAPI app: the API from CONTRACT.md, plus /web served at "/".

Run (Windows, no --reload: reload mode switches to an event loop that cannot
start the openssl subprocesses):
    venv\\Scripts\\python -m uvicorn server.app:app --port 8000
"""

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.exceptions import HTTPException as StarletteHTTPException
from typing import Literal

from practice.server import PracticeServer
from server import cache, scoring
from server.errors import HTTP_STATUS, MESSAGES, ScanError
from server.limits import (MAX_SCANS_PER_IP, PRACTICE_PER_MINUTE, RateLimiter,
                           ScanSlots)
from server.results import error_result, ok_result
from server.scanner import find_openssl, hybrid_self_test, probe_site
from server.targets import normalize_host, resolve_target

TOTAL_SCAN_TIMEOUT = 20   # seconds for the whole scan, both probes included
# Network failures where a saved result is better than an error.
FALL_BACK_ON = {"timeout", "no_tls", "dns_failed"}
WEB_DIR = Path(__file__).resolve().parent.parent / "web"

log = logging.getLogger("flip")


@asynccontextmanager
async def lifespan(app):
    # Exits here if this OpenSSL cannot offer the hybrid group.
    app.state.openssl, app.state.openssl_version = find_openssl()
    app.state.hybrid_ok = await hybrid_self_test(app.state.openssl)
    log.warning("OpenSSL %s, hybrid self-test: %s",
                app.state.openssl_version, app.state.hybrid_ok)

    # The practice server always starts on the old method.
    app.state.practice = PracticeServer(app.state.openssl)
    try:
        try:
            await app.state.practice.set_mode("classical")
        except RuntimeError as e:
            # Real scans still work without it, so say what is wrong and carry on.
            log.error("practice server unavailable: %s", e)
        yield
    finally:
        await app.state.practice.close()


app = FastAPI(title="Flip the Lock", lifespan=lifespan, docs_url=None, redoc_url=None)
rate_limiter = RateLimiter()
practice_limiter = RateLimiter(limit=PRACTICE_PER_MINUTE)   # flips and practice scans
scan_slots = ScanSlots()
scans_in_flight = {}   # client IP -> scans running now


def scan_error_response(host, code, message=None):
    return JSONResponse(error_result(host, code, message),
                        status_code=HTTP_STATUS.get(code, 200))


# Never leak stack traces or framework error formats: every failure is JSON
# with a plain-English message.
@app.exception_handler(Exception)
async def on_unexpected(request, exc):
    log.exception("unhandled error")
    return JSONResponse({"error": {"code": "internal", "message": "Something went wrong "
                                   "on our side. Try again."}}, status_code=500)


@app.exception_handler(RequestValidationError)
async def on_bad_request(request, exc):
    return JSONResponse({"error": {"code": "invalid_input",
                                   "message": "That request is not valid."}}, status_code=400)


@app.exception_handler(StarletteHTTPException)
async def on_http_error(request, exc):
    return JSONResponse({"error": {"code": "not_found" if exc.status_code == 404 else "internal",
                                   "message": "Not found." if exc.status_code == 404
                                   else "That request is not valid."}},
                        status_code=exc.status_code)


@app.get("/api/health")
async def health(request: Request):
    return {"ok": True, "opensslVersion": request.app.state.openssl_version,
            "hybridSelfTest": request.app.state.hybrid_ok}


@app.get("/api/scan")
async def scan(request: Request, host: str = "", data: str = "health_records",
               years: str | None = None):
    shown_host = host.strip()[:253]

    # Cheap checks first, before using any network.
    try:
        years_int = int(years) if years not in (None, "") else None
        years_int = scoring.years_for(data, years_int)
    except ValueError:
        return scan_error_response(shown_host, "invalid_input")

    client_ip = request.client.host if request.client else "unknown"
    is_practice = shown_host.lower() == "practice"
    if not (practice_limiter if is_practice else rate_limiter).allow(client_ip):
        return scan_error_response(shown_host, "rate_limited")

    def failed(name, code):
        # If the network let us down and we have a saved result, show that,
        # clearly labeled "cached" with its original time. Otherwise the error.
        if code in FALL_BACK_ON:
            saved = cache.load_for_request(name, data, years_int)
            if saved:
                return saved
        return scan_error_response(name, code)

    try:
        target = await resolve_target(host)
    except ScanError as e:
        if e.code == "dns_failed":
            return failed(normalize_host(host), e.code)
        return scan_error_response(shown_host, e.code)

    async def run_probe():
        return await asyncio.wait_for(
            probe_site(request.app.state.openssl, target.host, target.ip, target.port),
            TOTAL_SCAN_TIMEOUT)

    if is_practice:
        # The local practice server skips the shared scan slots, so a busy
        # outside scanner cannot block the demo. It does wait for any restart
        # in progress, so a scan never lands on a half-restarted server.
        try:
            async with request.app.state.practice.lock:
                probe = await run_probe()
        except asyncio.TimeoutError:
            return failed(target.host, "timeout")
        except ScanError as e:
            return failed(target.host, e.code)
    else:
        if scans_in_flight.get(client_ip, 0) >= MAX_SCANS_PER_IP:
            return scan_error_response(target.host, "rate_limited")
        if not await scan_slots.acquire():
            return scan_error_response(target.host, "rate_limited")
        scans_in_flight[client_ip] = scans_in_flight.get(client_ip, 0) + 1
        try:
            probe = await run_probe()
        except asyncio.TimeoutError:
            return failed(target.host, "timeout")
        except ScanError as e:
            return failed(target.host, e.code)
        finally:
            scan_slots.release()
            scans_in_flight[client_ip] -= 1
            if not scans_in_flight[client_ip]:
                del scans_in_flight[client_ip]

    result = ok_result(target.host, probe, data, years_int)
    cache.save(result)   # keeps demo sites' saved results fresh; ignores other hosts
    return result


@app.get("/api/cached")
async def cached():
    return cache.all_cached()


@app.get("/api/demo-sites")
async def demo_sites():
    return {"sites": cache.demo_sites()}


@app.get("/api/practice")
async def practice_status(request: Request):
    # "mode" is null while the practice server is not running.
    return {"mode": request.app.state.practice.mode, "scanHost": "practice"}


class ModeRequest(BaseModel):
    mode: Literal["classical", "hybrid"]


@app.post("/api/practice/mode")
async def practice_mode(body: ModeRequest, request: Request):
    """Really stop and restart the practice server with the other group list."""
    client_ip = request.client.host if request.client else "unknown"
    if not practice_limiter.allow(client_ip):
        return JSONResponse({"error": {"code": "rate_limited",
                                       "message": MESSAGES["rate_limited"]}}, status_code=429)
    try:
        mode = await request.app.state.practice.set_mode(body.mode)
    except RuntimeError as e:
        log.error("practice restart failed: %s", e)
        return JSONResponse({"error": {"code": "internal", "message":
                                       "The practice server could not restart. Try again."}},
                            status_code=503)
    return {"mode": mode}


# Static frontend last, so /api/* routes win.
if WEB_DIR.is_dir():
    app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")
