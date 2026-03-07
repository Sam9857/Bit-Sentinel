"""
Stream Routes — Phase 3
Server-Sent Events (SSE) for real-time dashboard updates.

Endpoints:
  GET /stream/threats    — live threat feed (SSE)
  GET /stream/stats      — live stats snapshot (SSE)
  GET /api/ip/<ip>       — full IP status card (REST)
  GET /api/activity      — recent activity timeline (REST)
"""

import json
import time
import threading
from datetime import datetime
from flask import Blueprint, Response, jsonify, request

from models.prevention_engine import (
    get_blacklist, is_blocked, is_whitelisted,
    get_threat_stats,
)
from utils.rate_limiter import limiter

stream = Blueprint("stream", __name__)

# ── In-memory activity log ────────────────────────────────────────────────────
_activity_lock = threading.Lock()
_activity_log: list[dict] = []   # newest appended last, max 200 entries
MAX_ACTIVITY = 200


def log_activity(event_type: str, message: str, ip: str = "", level: str = "info"):
    """
    Add an entry to the in-memory activity timeline.
    level: info | warning | danger | success
    """
    entry = {
        "id":         int(time.time() * 1000),
        "timestamp":  datetime.utcnow().isoformat(),
        "event_type": event_type,
        "message":    message,
        "ip":         ip,
        "level":      level,
    }
    with _activity_lock:
        _activity_log.append(entry)
        if len(_activity_log) > MAX_ACTIVITY:
            _activity_log.pop(0)
    return entry


def get_activity(limit: int = 50) -> list[dict]:
    with _activity_lock:
        return list(reversed(_activity_log[-limit:]))


# ── SSE Helper ────────────────────────────────────────────────────────────────

def _sse(data: dict, event: str = "message") -> str:
    """Format a dict as an SSE message string."""
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


def _heartbeat() -> str:
    return f"event: heartbeat\ndata: {json.dumps({'ts': datetime.utcnow().isoformat()})}\n\n"


# ── SSE: Live Threat Feed ─────────────────────────────────────────────────────

@stream.route("/stream/threats")
def stream_threats():
    """
    SSE stream that pushes a snapshot of the latest threats + stats
    every 3 seconds. The client (realtime.js) merges these into the UI.
    """
    from data_watcher import get_latest_threats, get_stats_snapshot   # lazy import

    def generate():
        sent_ids: set = set()
        try:
            while True:
                try:
                    threats = get_latest_threats(limit=20)
                    new_threats = [t for t in threats if t.get("scan_id") not in sent_ids]

                    for t in new_threats:
                        sid = t.get("scan_id")
                        if sid:
                            sent_ids.add(sid)
                        yield _sse(t, event="threat")

                    # Always send a stats tick
                    stats = get_stats_snapshot()
                    yield _sse(stats, event="stats")

                    # Heartbeat
                    yield _heartbeat()

                except Exception:
                    yield _heartbeat()

                time.sleep(3)
        except GeneratorExit:
            pass

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":     "no-cache",
            "X-Accel-Buffering": "no",
            "Connection":        "keep-alive",
        },
    )


# ── SSE: Live Stats Only ──────────────────────────────────────────────────────

@stream.route("/stream/stats")
def stream_stats():
    """Lighter SSE stream — sends only stats snapshots every 5 seconds."""
    from data_watcher import get_stats_snapshot

    def generate():
        try:
            while True:
                try:
                    stats = get_stats_snapshot()
                    yield _sse(stats, event="stats")
                    yield _heartbeat()
                except Exception:
                    yield _heartbeat()
                time.sleep(5)
        except GeneratorExit:
            pass

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":     "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ── REST: IP Detail Card ──────────────────────────────────────────────────────

@stream.route("/api/ip/<ip_addr>")
def ip_detail(ip_addr: str):
    """Return a full status card for a single IP address."""
    import re
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip_addr):
        return jsonify({"error": "Invalid IP"}), 400

    bl_data    = get_blacklist()
    block_entry = next(
        (e for e in bl_data.get("blocked_ips", []) if e.get("ip") == ip_addr),
        None,
    )
    rl_stats   = limiter.get_stats(ip_addr)

    # Pull threat history for this IP
    from data_watcher import get_threats_for_ip
    ip_threats = get_threats_for_ip(ip_addr, limit=10)

    return jsonify({
        "ip":           ip_addr,
        "is_blocked":   bool(block_entry),
        "is_whitelisted": is_whitelisted(ip_addr),
        "block_entry":  block_entry,
        "rate_limit":   rl_stats,
        "threat_history": ip_threats,
        "fetched_at":   datetime.utcnow().isoformat(),
    })


# ── REST: Activity Timeline ───────────────────────────────────────────────────

@stream.route("/api/activity")
def activity_timeline():
    limit = min(int(request.args.get("limit", 50)), 200)
    return jsonify({
        "activity": get_activity(limit),
        "total":    len(_activity_log),
    })


@stream.route("/api/activity/clear", methods=["POST"])
def clear_activity():
    with _activity_lock:
        _activity_log.clear()
    return jsonify({"message": "Activity log cleared"})