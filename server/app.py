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
from server import scoring
from server.errors import HTTP_STATUS, MESSAGES, ScanError
from server.limits import RateLimiter, ScanSlots
from server.results import error_result, ok_result
from server.scanner import find_openssl, hybrid_self_test, probe_site
from server.targets import resolve_target

TOTAL_SCAN_TIMEOUT = 20   # seconds for the whole scan, both probes included
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
    await app.state.practice.set_mode("classical")
    try:
        yield
    finally:
        await app.state.practice.close()


app = FastAPI(title="Flip the Lock", lifespan=lifespan, docs_url=None, redoc_url=None)
rate_limiter = RateLimiter()
scan_slots = ScanSlots()


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
    if not rate_limiter.allow(client_ip):
        return scan_error_response(shown_host, "rate_limited")

    try:
        target = await resolve_target(host)
    except ScanError as e:
        return scan_error_response(shown_host, e.code)

    if not await scan_slots.acquire():
        return scan_error_response(target.host, "rate_limited")
    try:
        probe = await asyncio.wait_for(
            probe_site(request.app.state.openssl, target.host, target.ip, target.port),
            TOTAL_SCAN_TIMEOUT)
    except asyncio.TimeoutError:
        return scan_error_response(target.host, "timeout")
    except ScanError as e:
        return scan_error_response(target.host, e.code)
    finally:
        scan_slots.release()

    return ok_result(target.host, probe, data, years_int)


@app.get("/api/practice")
async def practice_status(request: Request):
    return {"mode": request.app.state.practice.mode, "scanHost": "practice"}


class ModeRequest(BaseModel):
    mode: Literal["classical", "hybrid"]


@app.post("/api/practice/mode")
async def practice_mode(body: ModeRequest, request: Request):
    """Really stop and restart the practice server with the other group list."""
    client_ip = request.client.host if request.client else "unknown"
    if not rate_limiter.allow(client_ip):
        return JSONResponse({"error": {"code": "rate_limited",
                                       "message": MESSAGES["rate_limited"]}}, status_code=429)
    mode = await request.app.state.practice.set_mode(body.mode)
    return {"mode": mode}


# Static frontend last, so /api/* routes win.
if WEB_DIR.is_dir():
    app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")
