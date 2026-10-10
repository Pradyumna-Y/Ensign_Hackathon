# Flip the Lock: API + frontend + practice server in one container.
#
# Debian 13 (trixie) ships OpenSSL 3.5, the first version that can offer the
# hybrid post-quantum group X25519MLKEM768.
FROM python:3.12-slim-trixie

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Fail the build early if this OpenSSL cannot offer the hybrid group.
RUN openssl version \
 && openssl list -tls-groups -tls1_3 | tr ':' '\n' | grep -qx X25519MLKEM768

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server server
COPY practice practice
COPY scripts scripts
COPY web web

# Run as an ordinary user, not root. cache/ is where saved results live.
RUN useradd --create-home app && mkdir -p /app/cache && chown -R app /app
USER app

# Only the API is published. The practice server listens on 127.0.0.1:8443
# inside the container, where only our scanner can reach it.
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s \
  CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8000/api/health', timeout=4)"
CMD ["uvicorn", "server.app:app", "--host", "0.0.0.0", "--port", "8000"]
