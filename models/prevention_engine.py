"""
Prevention Engine — Phase 2
Handles:
  - Auto-blocking IPs that exceed configurable risk threshold
  - Whitelist checks (trusted IPs are never blocked)
  - Enhanced blacklist entries with metadata
  - Threat history management (trim to max size)
  - Block audit log
"""

import json
import os
from datetime import datetime

BASE_DIR        = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR        = os.path.join(BASE_DIR, "data")
BLACKLIST_FILE  = os.path.join(DATA_DIR, "blacklist.json")
WHITELIST_FILE  = os.path.join(DATA_DIR, "whitelist.json")
THREATS_FILE    = os.path.join(DATA_DIR, "threats.json")
CONFIG_FILE     = os.path.join(DATA_DIR, "config.json")


# ── JSON helpers ──────────────────────────────────────────────────────────────

def _load(path: str) -> dict:
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save(path: str, data: dict):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


# ── Config ────────────────────────────────────────────────────────────────────

def get_config() -> dict:
    defaults = {
        "auto_block_enabled":       True,
        "auto_block_threshold":     65,
        "rate_limit_enabled":       True,
        "rate_limit_max_requests":  100,
        "rate_limit_window_seconds": 60,
        "brute_force_threshold":    5,
        "high_freq_threshold":      100,
        "alert_on_danger":          True,
        "max_threat_history":       500,
    }
    stored = _load(CONFIG_FILE)
    defaults.update(stored)
    return defaults


def save_config(updates: dict) -> dict:
    config = get_config()
    # Only allow known keys
    allowed = {
        "auto_block_enabled", "auto_block_threshold",
        "rate_limit_enabled", "rate_limit_max_requests",
        "rate_limit_window_seconds", "brute_force_threshold",
        "high_freq_threshold", "alert_on_danger", "max_threat_history",
    }
    for k, v in updates.items():
        if k in allowed:
            config[k] = v
    config["last_updated"] = datetime.utcnow().isoformat()
    _save(CONFIG_FILE, config)
    return config


# ── Whitelist ─────────────────────────────────────────────────────────────────

def is_whitelisted(ip: str) -> bool:
    data = _load(WHITELIST_FILE)
    return ip in data.get("trusted_ips", [])


def add_to_whitelist(ip: str) -> dict:
    data = _load(WHITELIST_FILE)
    trusted = data.get("trusted_ips", [])
    if ip in trusted:
        return {"message": f"{ip} already whitelisted", "ip": ip}
    trusted.append(ip)
    data["trusted_ips"]  = trusted
    data["last_updated"] = datetime.utcnow().isoformat()
    _save(WHITELIST_FILE, data)

    # If it was blocked, auto-unblock it
    _remove_from_blacklist(ip, reason="Moved to whitelist")
    return {"message": f"{ip} added to whitelist", "ip": ip}


def remove_from_whitelist(ip: str) -> dict:
    data = _load(WHITELIST_FILE)
    trusted = data.get("trusted_ips", [])
    if ip not in trusted:
        return {"error": "IP not in whitelist"}
    trusted.remove(ip)
    data["trusted_ips"]  = trusted
    data["last_updated"] = datetime.utcnow().isoformat()
    _save(WHITELIST_FILE, data)
    return {"message": f"{ip} removed from whitelist", "ip": ip}


def get_whitelist() -> dict:
    return _load(WHITELIST_FILE)


# ── Blacklist (enhanced) ───────────────────────────────────────────────────────

def _build_block_entry(ip: str, reason: str, score: int, auto: bool) -> dict:
    return {
        "ip":         ip,
        "reason":     reason,
        "risk_score": score,
        "auto":       auto,
        "blocked_at": datetime.utcnow().isoformat(),
    }


def add_to_blacklist(ip: str, reason: str = "Manual block",
                     score: int = 0, auto: bool = False) -> dict:
    """Add IP to blacklist with metadata. Skips if whitelisted."""
    if is_whitelisted(ip):
        return {"error": f"{ip} is whitelisted and cannot be blocked", "whitelisted": True}

    data    = _load(BLACKLIST_FILE)
    blocked = data.get("blocked_ips", [])

    # Support both old list-of-strings and new list-of-dicts format
    existing_ips = [e if isinstance(e, str) else e["ip"] for e in blocked]
    if ip in existing_ips:
        return {"message": f"{ip} already blocked", "ip": ip, "already_blocked": True}

    entry = _build_block_entry(ip, reason, score, auto)
    blocked.append(entry)
    data["blocked_ips"]  = blocked
    data["last_updated"] = datetime.utcnow().isoformat()
    _save(BLACKLIST_FILE, data)
    return {"message": f"{ip} blocked", "ip": ip, "entry": entry}


def _remove_from_blacklist(ip: str, reason: str = "") -> bool:
    data    = _load(BLACKLIST_FILE)
    blocked = data.get("blocked_ips", [])
    new_blocked = [e for e in blocked if (e if isinstance(e, str) else e["ip"]) != ip]
    if len(new_blocked) == len(blocked):
        return False
    data["blocked_ips"]  = new_blocked
    data["last_updated"] = datetime.utcnow().isoformat()
    _save(BLACKLIST_FILE, data)
    return True


def remove_from_blacklist(ip: str) -> dict:
    removed = _remove_from_blacklist(ip)
    if not removed:
        return {"error": "IP not in blacklist"}
    return {"message": f"{ip} unblocked", "ip": ip}


def get_blacklist() -> dict:
    data    = _load(BLACKLIST_FILE)
    blocked = data.get("blocked_ips", [])
    # Normalise to list of dicts
    normalised = []
    for e in blocked:
        if isinstance(e, str):
            normalised.append(_build_block_entry(e, "Legacy entry", 0, False))
        else:
            normalised.append(e)
    return {
        "blocked_ips":  normalised,
        "total":        len(normalised),
        "last_updated": data.get("last_updated", ""),
    }


def is_blocked(ip: str) -> bool:
    data    = _load(BLACKLIST_FILE)
    blocked = data.get("blocked_ips", [])
    ips     = [e if isinstance(e, str) else e["ip"] for e in blocked]
    return ip in ips


# ── Auto-Block Engine ─────────────────────────────────────────────────────────

def evaluate_auto_block(threat_result: dict) -> dict:
    """
    Called after every scan. Automatically blocks IPs that:
      1. Have risk_score >= auto_block_threshold
      2. Are not whitelisted

    Returns info about what action was taken.
    """
    config    = get_config()
    if not config.get("auto_block_enabled", True):
        return {"action": "skipped", "reason": "auto-block disabled"}

    ip         = threat_result.get("ip", "")
    risk_score = threat_result.get("risk_score", 0)
    threshold  = config.get("auto_block_threshold", 65)

    if not ip:
        return {"action": "skipped", "reason": "no IP"}

    if risk_score < threshold:
        return {
            "action":    "no_action",
            "ip":        ip,
            "score":     risk_score,
            "threshold": threshold,
        }

    if is_whitelisted(ip):
        return {"action": "skipped", "reason": f"{ip} is whitelisted", "ip": ip}

    threat_types = threat_result.get("threat_types", [])
    reason = f"Auto-blocked: score {risk_score} | " + (
        ", ".join(threat_types) if threat_types else "Anomaly detected"
    )
    result = add_to_blacklist(ip, reason=reason, score=risk_score, auto=True)
    result["action"]    = "auto_blocked"
    result["threshold"] = threshold
    return result


# ── Threat History Management ─────────────────────────────────────────────────

def trim_threat_history():
    """Keep threat history within max_threat_history limit."""
    config   = get_config()
    max_size = int(config.get("max_threat_history", 500))
    data     = _load(THREATS_FILE)
    threats  = data.get("threats", [])
    if len(threats) > max_size:
        data["threats"] = threats[-max_size:]
        _save(THREATS_FILE, data)


def get_threat_stats() -> dict:
    """Return aggregated threat statistics."""
    data    = _load(THREATS_FILE)
    threats = data.get("threats", [])

    danger_count     = sum(1 for t in threats if t.get("risk_level") == "danger")
    suspicious_count = sum(1 for t in threats if t.get("risk_level") == "suspicious")
    safe_count       = sum(1 for t in threats if t.get("risk_level") == "safe")
    auto_blocked     = sum(1 for t in threats if t.get("auto_blocked", False))

    scores = [t.get("risk_score", 0) for t in threats if t.get("risk_score") is not None]
    avg_score = round(sum(scores) / len(scores), 1) if scores else 0
    max_score = max(scores, default=0)

    # Top threat types frequency
    from collections import Counter
    type_counter: Counter = Counter()
    for t in threats:
        for tt in t.get("threat_types", []):
            type_counter[tt] += 1
    top_types = [{"type": k, "count": v} for k, v in type_counter.most_common(5)]

    return {
        "total":          len(threats),
        "danger":         danger_count,
        "suspicious":     suspicious_count,
        "safe":           safe_count,
        "auto_blocked":   auto_blocked,
        "avg_score":      avg_score,
        "max_score":      max_score,
        "top_threat_types": top_types,
        "total_scanned":  data.get("total_scanned", 0),
        "last_scan":      data.get("last_scan", "Never"),
    }