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

PYTHON="${PYTHON:-python3}"
command -v "$PYTHON" >/dev/null || { echo "Python 3.12 or later is needed (python3 not found)."; exit 1; }

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

if [[ ! -x venv/bin/python ]]; then
    echo "First run: creating a virtual environment (about a minute)..."
    "$PYTHON" -m venv venv
fi
if [[ ! -f venv/.installed || requirements.txt -nt venv/.installed ]]; then
    venv/bin/pip install --quiet -r requirements.txt
    touch venv/.installed
fi

free_port() {   # first free TCP port at or above $1
    venv/bin/python - "$1" <<'PY'
import socket, sys
port = int(sys.argv[1])
while True:
    with socket.socket() as s:
        if s.connect_ex(("127.0.0.1", port)) != 0:
            print(port)
            break
    port += 1
PY
}
PORT="$(free_port "${PORT:-8000}")"
export PRACTICE_PORT="$(free_port "${PRACTICE_PORT:-8443}")"

URL="http://127.0.0.1:$PORT"
echo "OpenSSL: $OPENSSL_BIN ($("$OPENSSL_BIN" version | awk '{print $2}'))"
echo "Open $URL   (practice server on port $PRACTICE_PORT; Ctrl+C to stop)"
( sleep 4
  if command -v open >/dev/null; then open "$URL"; elif command -v xdg-open >/dev/null; then xdg-open "$URL"; fi
) >/dev/null 2>&1 &
exec venv/bin/python -m uvicorn server.app:app --host 127.0.0.1 --port "$PORT"
