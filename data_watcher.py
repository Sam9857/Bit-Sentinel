"""
data_watcher.py — Phase 3
Thin read-only helpers consumed by stream_routes.py.
Kept separate to avoid circular imports with other route modules.
"""

import json
import os
from datetime import datetime

BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
DATA_DIR     = os.path.join(BASE_DIR, "data")
THREATS_FILE = os.path.join(DATA_DIR, "threats.json")


def _load_threats_raw() -> dict:
    try:
        with open(THREATS_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"threats": [], "total_scanned": 0, "last_scan": ""}


def get_latest_threats(limit: int = 20) -> list[dict]:
    """Return the most recent threats (newest first)."""
    data    = _load_threats_raw()
    threats = data.get("threats", [])
    return list(reversed(threats[-limit:]))


def get_threats_for_ip(ip: str, limit: int = 10) -> list[dict]:
    """Return threat history for a specific IP."""
    data    = _load_threats_raw()
    threats = data.get("threats", [])
    matched = [t for t in threats if t.get("ip") == ip]
    return list(reversed(matched[-limit:]))


def get_stats_snapshot() -> dict:
    """Return a lightweight stats dict suitable for SSE."""
    from models.prevention_engine import get_blacklist, get_threat_stats
    from utils.rate_limiter import limiter

    data    = _load_threats_raw()
    threats = data.get("threats", [])

    danger_count     = sum(1 for t in threats if t.get("risk_level") == "danger")
    suspicious_count = sum(1 for t in threats if t.get("risk_level") == "suspicious")
    safe_count       = sum(1 for t in threats if t.get("risk_level") == "safe")

    scores = [t.get("risk_score", 0) for t in threats if t.get("risk_score") is not None]
    avg_score = round(sum(scores) / len(scores), 1) if scores else 0

    bl_data    = get_blacklist()
    rl_tracked = limiter.get_all_stats()

    # Trend: last 10 risk scores for the chart
    trend_scores = [t.get("risk_score", 0) for t in threats[-10:]]

    return {
        "timestamp":      datetime.utcnow().isoformat(),
        "total_threats":  len(threats),
        "danger":         danger_count,
        "suspicious":     suspicious_count,
        "safe":           safe_count,
        "avg_score":      avg_score,
        "blocked_ips":    bl_data.get("total", 0),
        "total_scanned":  data.get("total_scanned", 0),
        "last_scan":      data.get("last_scan", "Never"),
        "rl_at_limit":    sum(1 for r in rl_tracked if r.get("at_limit")),
        "trend_scores":   trend_scores,
    }