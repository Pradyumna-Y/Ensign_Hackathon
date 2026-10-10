"""Limits that keep the scanner from being used to flood other sites.

- At most 6 scans run at once across all users (each scan is 2 connections).
- Each client IP gets about 30 scans per minute.
"""

import asyncio
import time
from collections import defaultdict, deque

MAX_CONCURRENT_SCANS = 6
PER_IP_PER_MINUTE = 30
SLOT_WAIT = 5   # seconds to wait for a free scan slot before answering 429


class RateLimiter:
    """Sliding one-minute window per client IP, kept in memory."""

    def __init__(self, limit=PER_IP_PER_MINUTE, window=60.0):
        self.limit, self.window = limit, window
        self.hits = defaultdict(deque)

    def allow(self, client_ip, now=None):
        now = time.monotonic() if now is None else now
        hits = self.hits[client_ip]
        while hits and now - hits[0] > self.window:
            hits.popleft()
        if len(hits) >= self.limit:
            return False
        hits.append(now)
        return True


class ScanSlots:
    """A semaphore with a short wait, so a burst gets 429 instead of piling up."""

    def __init__(self, size=MAX_CONCURRENT_SCANS):
        self.sem = asyncio.Semaphore(size)

    async def acquire(self, wait=SLOT_WAIT):
        try:
            await asyncio.wait_for(self.sem.acquire(), wait)
            return True
        except asyncio.TimeoutError:
            return False

    def release(self):
        self.sem.release()
