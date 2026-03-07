"""
Prevention Routes — Phase 2
All endpoints for the Prevention System:
  /api/prevention/config        GET/POST
  /api/prevention/whitelist     GET
  /api/prevention/whitelist/add POST
  /api/prevention/whitelist/remove POST
  /api/prevention/stats         GET
  /api/prevention/ratelimit     GET (all IPs)
  /api/prevention/ratelimit/<ip> GET
  /api/prevention/ratelimit/reset POST
  /api/prevention/check/<ip>    GET  (full status check)
  /api/prevention/simulate      POST (simulate auto-block on a result)
"""

import re
from flask import Blueprint, request, jsonify

from models.prevention_engine import (
    get_config, save_config,
    get_whitelist, add_to_whitelist, remove_from_whitelist,
    get_blacklist, add_to_blacklist, remove_from_blacklist,
    is_blocked, is_whitelisted,
    evaluate_auto_block,
    get_threat_stats, trim_threat_history,
)
from utils.rate_limiter import limiter

prevention = Blueprint("prevention", __name__, url_prefix="/api/prevention")

IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _valid_ip(ip: str) -> bool:
    return bool(ip and IP_RE.match(ip))


# ─── Config ───────────────────────────────────────────────────────────────────

@prevention.route("/config", methods=["GET"])
def get_prevention_config():
    """Return current prevention configuration."""
    return jsonify(get_config())


@prevention.route("/config", methods=["POST"])
def update_prevention_config():
    """
    Update prevention configuration.
    Accepts partial updates — only known keys are changed.
    """
    body = request.get_json(silent=True) or {}

    # Validate numeric fields
    numeric_fields = {
        "auto_block_threshold":      (0, 100),
        "rate_limit_max_requests":   (1, 10000),
        "rate_limit_window_seconds": (5, 3600),
        "brute_force_threshold":     (1, 1000),
        "high_freq_threshold":       (1, 100000),
        "max_threat_history":        (10, 100000),
    }
    for field, (lo, hi) in numeric_fields.items():
        if field in body:
            try:
                v = int(body[field])
                if not (lo <= v <= hi):
                    return jsonify({"error": f"{field} must be between {lo} and {hi}"}), 400
                body[field] = v
            except (ValueError, TypeError):
                return jsonify({"error": f"{field} must be an integer"}), 400

    # Boolean fields
    for bool_field in ("auto_block_enabled", "rate_limit_enabled", "alert_on_danger"):
        if bool_field in body:
            body[bool_field] = bool(body[bool_field])

    config = save_config(body)

    # Sync rate limiter
    limiter.update_config(
        max_requests=config.get("rate_limit_max_requests"),
        window_seconds=config.get("rate_limit_window_seconds"),
    )

    return jsonify({"message": "Config updated", "config": config})


# ─── Whitelist ────────────────────────────────────────────────────────────────

@prevention.route("/whitelist", methods=["GET"])
def get_whitelist_route():
    return jsonify(get_whitelist())


@prevention.route("/whitelist/add", methods=["POST"])
def whitelist_add():
    body = request.get_json(silent=True) or {}
    ip   = body.get("ip", "").strip()
    if not _valid_ip(ip):
        return jsonify({"error": "Invalid IP address"}), 400
    result = add_to_whitelist(ip)
    if "error" in result:
        return jsonify(result), 400
    return jsonify(result)


@prevention.route("/whitelist/remove", methods=["POST"])
def whitelist_remove():
    body = request.get_json(silent=True) or {}
    ip   = body.get("ip", "").strip()
    if not _valid_ip(ip):
        return jsonify({"error": "Invalid IP address"}), 400
    result = remove_from_whitelist(ip)
    if "error" in result:
        return jsonify(result), 404
    return jsonify(result)


# ─── Enhanced Blacklist ───────────────────────────────────────────────────────

@prevention.route("/blacklist", methods=["GET"])
def enhanced_blacklist():
    """Return blacklist with full metadata."""
    return jsonify(get_blacklist())


@prevention.route("/blacklist/add", methods=["POST"])
def blacklist_add():
    body   = request.get_json(silent=True) or {}
    ip     = body.get("ip", "").strip()
    reason = body.get("reason", "Manual block").strip()
    score  = int(body.get("risk_score", 0))
    if not _valid_ip(ip):
        return jsonify({"error": "Invalid IP address"}), 400
    result = add_to_blacklist(ip, reason=reason, score=score, auto=False)
    if result.get("whitelisted"):
        return jsonify(result), 403
    return jsonify(result)


@prevention.route("/blacklist/remove", methods=["POST"])
def blacklist_remove():
    body = request.get_json(silent=True) or {}
    ip   = body.get("ip", "").strip()
    if not _valid_ip(ip):
        return jsonify({"error": "Invalid IP address"}), 400
    result = remove_from_blacklist(ip)
    if "error" in result:
        return jsonify(result), 404
    return jsonify(result)


# ─── Rate Limiter ─────────────────────────────────────────────────────────────

@prevention.route("/ratelimit", methods=["GET"])
def rate_limit_all():
    """Return rate limit stats for all tracked IPs."""
    config  = get_config()
    enabled = config.get("rate_limit_enabled", True)
    return jsonify({
        "enabled":  enabled,
        "settings": {
            "max_requests": limiter.max_requests,
            "window_seconds": limiter.window_seconds,
        },
        "tracked_ips": limiter.get_all_stats(),
    })


@prevention.route("/ratelimit/<ip>", methods=["GET"])
def rate_limit_single(ip):
    if not _valid_ip(ip):
        return jsonify({"error": "Invalid IP"}), 400
    return jsonify(limiter.get_stats(ip))


@prevention.route("/ratelimit/reset", methods=["POST"])
def rate_limit_reset():
    body = request.get_json(silent=True) or {}
    ip   = body.get("ip", "").strip()
    if ip:
        if not _valid_ip(ip):
            return jsonify({"error": "Invalid IP"}), 400
        limiter.reset(ip)
        return jsonify({"message": f"Rate limit reset for {ip}"})
    limiter.reset_all()
    return jsonify({"message": "All rate limits reset"})


# ─── Full IP Status Check ─────────────────────────────────────────────────────

@prevention.route("/check/<ip>", methods=["GET"])
def check_ip_status(ip):
    """
    Full prevention status for a single IP:
    blocked, whitelisted, rate_limit_stats.
    """
    if not _valid_ip(ip):
        return jsonify({"error": "Invalid IP"}), 400

    blocked_data = get_blacklist()
    block_entry  = next((e for e in blocked_data["blocked_ips"] if e["ip"] == ip), None)

    return jsonify({
        "ip":          ip,
        "is_blocked":  bool(block_entry),
        "is_whitelisted": is_whitelisted(ip),
        "block_entry": block_entry,
        "rate_limit":  limiter.get_stats(ip),
    })


# ─── Auto-Block Simulation ────────────────────────────────────────────────────

@prevention.route("/simulate", methods=["POST"])
def simulate_auto_block():
    """
    Simulate the auto-block engine against a manually supplied threat result.
    Useful for testing the threshold without running a real scan.
    Body: { ip, risk_score, risk_level, threat_types }
    """
    body = request.get_json(silent=True) or {}
    ip   = body.get("ip", "").strip()
    if not _valid_ip(ip):
        return jsonify({"error": "Invalid IP"}), 400

    threat_result = {
        "ip":          ip,
        "risk_score":  int(body.get("risk_score", 0)),
        "risk_level":  body.get("risk_level", "safe"),
        "threat_types": body.get("threat_types", []),
    }

    action = evaluate_auto_block(threat_result)
    return jsonify(action)


# ─── Threat Stats ─────────────────────────────────────────────────────────────

@prevention.route("/stats", methods=["GET"])
def threat_stats():
    """Enhanced threat statistics for the prevention dashboard."""
    trim_threat_history()
    stats = get_threat_stats()
    config = get_config()
    return jsonify({
        **stats,
        "config": {
            "auto_block_threshold": config.get("auto_block_threshold"),
            "auto_block_enabled":   config.get("auto_block_enabled"),
        },
    })