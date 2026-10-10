#!/usr/bin/env bash
# One command to start Flip the Lock on macOS or Linux.
#
#     ./scripts/run.sh
#
# It finds an OpenSSL 3.5 or later, makes a virtual environment the first time,
# picks free ports, starts the app and opens your browser. Ctrl+C stops it.
# Set PORT or OPENSSL_BIN to override. On Windows, follow the README instead.

set -euo pipefail
cd "$(dirname "$0")/.."

python_ok() {   # true if "$1" is Python 3.12 or later
    command -v "$1" >/dev/null 2>&1 &&
        "$1" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)' 2>/dev/null
}
PYTHON=""
for candidate in "${PYTHON_BIN:-}" python3.14 python3.13 python3.12 python3; do
    if [[ -n "$candidate" ]] && python_ok "$candidate"; then PYTHON="$candidate"; break; fi
done
if [[ -z "$PYTHON" ]]; then
    echo "Python 3.12 or later is needed, and none was found."
    echo "  macOS:  brew install python@3.13"
    echo "  Linux:  install python3.12 or later, or use the Docker image."
    echo "  Then run this again (or set PYTHON_BIN to the python you want)."
    exit 1
fi

openssl_ok() {   # true if "$1" is OpenSSL 3.5 or later
    local v major minor
    v=$("$1" version 2>/dev/null | awk '{print $2}') || return 1
    IFS=. read -r major minor _ <<<"$v"
    [[ "$major" =~ ^[0-9]+$ && "$minor" =~ ^[0-9]+$ ]] || return 1
    (( major > 3 || (major == 3 && minor >= 5) ))
}

OPENSSL_FOUND=""
for candidate in "${OPENSSL_BIN:-}" "$(command -v openssl || true)" \
        /opt/homebrew/opt/openssl@3/bin/openssl /usr/local/opt/openssl@3/bin/openssl; do
    if [[ -n "$candidate" ]] && openssl_ok "$candidate"; then OPENSSL_FOUND="$candidate"; break; fi
done
if [[ -z "$OPENSSL_FOUND" ]]; then
    echo "No OpenSSL 3.5 or later found (it is needed to offer X25519MLKEM768)."
    echo "  macOS:  brew install openssl@3"
    echo "  Linux:  use Debian 13 or Ubuntu 25.04 or later, or the Docker image."
    echo "  Then run this again, or set OPENSSL_BIN to the openssl you want."
    exit 1
fi
export OPENSSL_BIN="$OPENSSL_FOUND"

if [[ -x venv/bin/python ]] && ! python_ok venv/bin/python; then
    rm -rf venv   # left over from an older Python
fi
if [[ -d venv ]] && ! venv/bin/python -c 'import sys' 2>/dev/null; then
    rm -rf venv   # broken, for example its Python was uninstalled
fi
if [[ ! -x venv/bin/python ]]; then
    echo "First run: creating a virtual environment (about a minute)..."
    rm -rf venv
    "$PYTHON" -m venv venv
fi
if [[ ! -f venv/.installed || requirements.txt -nt venv/.installed ]]; then
    venv/bin/pip install --quiet -r requirements.txt
    touch venv/.installed
fi

free_port() {   # first TCP port at or above $1 that we can bind, skipping $2
    venv/bin/python - "$1" "${2:-0}" <<'PY'
import socket, sys
port, skip = int(sys.argv[1]), int(sys.argv[2])
while True:
    if port != skip:
        with socket.socket() as s:
            try:
                s.bind(("127.0.0.1", port))
                print(port)
                break
            except OSError:
                pass
    port += 1
PY
}
PORT="$(free_port "${PORT:-8000}")"
export PRACTICE_PORT="$(free_port "${PRACTICE_PORT:-8443}" "$PORT")"

# First run: save results for the demo sites in the background, so the offline
# fallback works even if the network is slow later.
if [[ "$(ls cache/*.json 2>/dev/null | wc -l)" -lt 10 ]]; then
    ( venv/bin/python scripts/seed_cache.py > venv/seed.log 2>&1 & ) || true
fi

URL="http://127.0.0.1:$PORT"
echo "OpenSSL: $OPENSSL_BIN ($("$OPENSSL_BIN" version | awk '{print $2}'))"
echo "Open $URL   (practice server on port $PRACTICE_PORT; Ctrl+C to stop)"
( sleep 4
  if command -v open >/dev/null; then open "$URL"; elif command -v xdg-open >/dev/null; then xdg-open "$URL"; fi
) >/dev/null 2>&1 &
exec venv/bin/python -m uvicorn server.app:app --host 127.0.0.1 --port "$PORT"
