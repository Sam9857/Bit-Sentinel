"""
Rate Limiter — Phase 2
In-memory per-IP request rate limiting.
Uses a sliding window counter stored in a dict.
No external Redis/cache dependency required.
"""

import time
import threading
from collections import defaultdict, deque


class RateLimiter:
    """
    Sliding window rate limiter.
    Tracks request timestamps per IP in a deque.
    Thread-safe via a lock.
    """

    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests     = max_requests
        self.window_seconds   = window_seconds
        self._requests: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def is_allowed(self, ip: str) -> tuple[bool, dict]:
        """
        Returns (allowed: bool, info: dict)
        info contains: remaining, reset_in, total
        """
        now    = time.time()
        cutoff = now - self.window_seconds

        with self._lock:
            dq = self._requests[ip]
            # Remove old timestamps outside window
            while dq and dq[0] < cutoff:
                dq.popleft()

            count = len(dq)
            if count >= self.max_requests:
                reset_in = round(dq[0] + self.window_seconds - now, 1) if dq else 0
                return False, {
                    "allowed":    False,
                    "ip":         ip,
                    "total":      count,
                    "remaining":  0,
                    "reset_in":   reset_in,
                    "window":     self.window_seconds,
                    "max":        self.max_requests,
                }

            dq.append(now)
            return True, {
                "allowed":   True,
                "ip":        ip,
                "total":     count + 1,
                "remaining": self.max_requests - count - 1,
                "reset_in":  self.window_seconds,
                "window":    self.window_seconds,
                "max":       self.max_requests,
            }

    def get_stats(self, ip: str) -> dict:
        """Return current stats for an IP without consuming a slot."""
        now    = time.time()
        cutoff = now - self.window_seconds
        with self._lock:
            dq = self._requests.get(ip, deque())
            count = sum(1 for t in dq if t >= cutoff)
        return {
            "ip":        ip,
            "total":     count,
            "remaining": max(0, self.max_requests - count),
            "max":       self.max_requests,
            "window":    self.window_seconds,
        }

    def get_all_stats(self) -> list[dict]:
        """Return stats for all tracked IPs (non-zero requests only)."""
        now    = time.time()
        cutoff = now - self.window_seconds
        stats  = []
        with self._lock:
            for ip, dq in list(self._requests.items()):
                count = sum(1 for t in dq if t >= cutoff)
                if count > 0:
                    stats.append({
                        "ip":        ip,
                        "total":     count,
                        "remaining": max(0, self.max_requests - count),
                        "max":       self.max_requests,
                        "window":    self.window_seconds,
                        "at_limit":  count >= self.max_requests,
                    })
        return sorted(stats, key=lambda x: x["total"], reverse=True)

    def reset(self, ip: str):
        """Reset rate limit counter for a specific IP."""
        with self._lock:
            self._requests.pop(ip, None)

    def reset_all(self):
        with self._lock:
            self._requests.clear()

    def update_config(self, max_requests: int = None, window_seconds: int = None):
        if max_requests is not None:
            self.max_requests = int(max_requests)
        if window_seconds is not None:
            self.window_seconds = int(window_seconds)


# Singleton used across the app
limiter = RateLimiter(max_requests=100, window_seconds=60)