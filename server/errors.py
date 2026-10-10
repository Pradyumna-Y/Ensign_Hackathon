"""Error codes from CONTRACT.md and the plain-English message for each.

Messages are safe to show on screen: they never contain raw OpenSSL output,
file paths or stack traces.
"""

MESSAGES = {
    "invalid_host": "That does not look like a website name. Type something like "
                    "example.com, without https:// or a path.",
    "invalid_input": "The data type or number of years is not valid.",
    "blocked_target": "That name points to a private or internal network address, "
                      "so we do not scan it.",
    "dns_failed": "We could not find that site. Check the spelling.",
    "timeout": "The site did not answer in time. Try again in a moment.",
    "no_tls": "This site did not complete a TLS 1.2 or 1.3 handshake on port 443.",
    "rate_limited": "Too many scans right now. Wait a few seconds and try again.",
    "internal": "Something went wrong on our side. Try again.",
}

# HTTP status per code. Problems with the request get 4xx; a scan that ran but
# could not reach a TLS server still answers 200 with status "error".
HTTP_STATUS = {
    "invalid_host": 400,
    "invalid_input": 400,
    "blocked_target": 403,
    "rate_limited": 429,
    "internal": 500,
}


class ScanError(Exception):
    def __init__(self, code, message=None):
        self.code = code
        self.message = message or MESSAGES[code]
        super().__init__(self.message)
