"""
traffic_tap.py — Real Request Interceptor
==========================================
Hooks into Flask's before_request / after_request lifecycle.

Every real HTTP request that hits this server is captured,
aggregated per IP, and fed into the detection pipeline.

This means when a judge browses the dashboard:
  - Their real IP is captured
  - Their real request patterns are analysed
  - ML scores their actual behaviour
  - Auto-block fires if they hit the threshold

ZERO simulation — this is genuine traffic analysis.
"""

import threading
from collections import defaultdict
from datetime import datetime
from flask import request as flask_request

_lock        = threading.Lock()
_enabled     = False
_registered  = False

# Per-IP rolling stats (reset-able)
_buckets = defaultdict(lambda: {
    "request_count":    0,
    "failed_attempts":  0,
    "unique_paths":     set(),
    "error_count":      0,
    "total_payload_sz": 0,
    "last_seen":        None,
})

# Flat log of recent requests (for the /tap-feed UI)
_recent = []
MAX_RECENT = 300

# Skip these paths to avoid feedback loop with SSE + status polling
_SKIP_PREFIXES = (
    "/stream/",
    "/api/live-monitoring",
    "/static/",
)


def _before():
    """Capture request metadata before it is handled."""
    if not _enabled:
        return
    flask_request._tap_ip      = (
        flask_request.headers.get("X-Forwarded-For", flask_request.remote_addr) or "unknown"
    ).split(",")[0].strip()
    flask_request._tap_path    = flask_request.path
    flask_request._tap_method  = flask_request.method
    flask_request._tap_payload = flask_request.get_data(as_text=True)[:512]


def _after(response):
    """Record response status and update per-IP buckets."""
    if not _enabled:
        return response

    ip      = getattr(flask_request, "_tap_ip",     "unknown")
    path    = getattr(flask_request, "_tap_path",   "/")
    method  = getattr(flask_request, "_tap_method", "GET")
    payload = getattr(flask_request, "_tap_payload", "")
    status  = response.status_code

    # Skip SSE streams and monitoring endpoints
    if any(path.startswith(p) for p in _SKIP_PREFIXES):
        return response

    with _lock:
        b = _buckets[ip]
        b["request_count"]    += 1
        b["unique_paths"].add(path)
        b["total_payload_sz"] += len(payload)
        b["last_seen"]         = datetime.utcnow().isoformat()

        if status in (401, 403):
            b["failed_attempts"] += 1
        if status >= 400:
            b["error_count"] += 1

        _recent.append({
            "ip":          ip,
            "method":      method,
            "path":        path,
            "status_code": status,
            "payload":     payload[:80],
            "timestamp":   datetime.utcnow().isoformat(),
        })
        if len(_recent) > MAX_RECENT:
            _recent.pop(0)

    return response


def register(app):
    """Call once in app.py to attach hooks."""
    global _registered
    if not _registered:
        app.before_request(_before)
        app.after_request(_after)
        _registered = True


def enable():
    global _enabled
    _enabled = True


def disable():
    global _enabled
    _enabled = False


def is_enabled():
    return _enabled


def get_ip_stats():
    """
    Return list of ip_stats dicts compatible with analyze_ip_behaviour().
    """
    out = []
    with _lock:
        for ip, b in _buckets.items():
            req = b["request_count"]
            if req == 0:
                continue
            out.append({
                "ip":              ip,
                "request_count":   req,
                "failed_attempts": b["failed_attempts"],
                "unique_paths":    len(b["unique_paths"]),
                "error_rate":      round(b["error_count"] / req, 4) if req else 0,
                "avg_payload_size": round(b["total_payload_sz"] / req, 2) if req else 0,
            })
    return out


def get_recent_requests(limit=50):
    with _lock:
        return list(reversed(_recent[-limit:]))


def reset():
    with _lock:
        _buckets.clear()
        _recent.clear()