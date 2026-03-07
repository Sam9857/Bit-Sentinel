import json
import os
import uuid
import re
from datetime import datetime

from flask import Blueprint, request, jsonify
from werkzeug.utils import secure_filename

from utils.log_parser       import parse_log_content, aggregate_by_ip
from models.threat_detector import analyze_log_entry, analyze_ip_behaviour
from utils.risk_scoring     import calculate_risk_score, score_to_level, score_to_color
# Phase 2 – prevention integration
from models.prevention_engine import (
    add_to_blacklist, remove_from_blacklist,
    get_blacklist, evaluate_auto_block,
    is_blocked, is_whitelisted,
    trim_threat_history,
)
from utils.rate_limiter import limiter

api = Blueprint("api", __name__, url_prefix="/api")

BASE_DIR     = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR     = os.path.join(BASE_DIR, "data")
THREATS_FILE = os.path.join(DATA_DIR, "threats.json")
UPLOAD_DIR   = os.path.join(BASE_DIR, "uploads")
ALLOWED_EXTS = {".log", ".txt", ".csv"}
IP_RE        = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

os.makedirs(UPLOAD_DIR, exist_ok=True)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _load_json(path: str) -> dict:
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_json(path: str, data: dict):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def _valid_ip(ip: str) -> bool:
    return bool(ip and IP_RE.match(ip))


# ── Endpoints ─────────────────────────────────────────────────────────────────

@api.route("/status", methods=["GET"])
def status():
    threats_data  = _load_json(THREATS_FILE)
    blacklist_data = get_blacklist()
    threats = threats_data.get("threats", [])
    return jsonify({
        "status":        "online",
        "total_threats": len(threats),
        "blocked_ips":   blacklist_data.get("total", 0),
        "total_scanned": threats_data.get("total_scanned", 0),
        "last_scan":     threats_data.get("last_scan", "Never"),
    })


@api.route("/threats", methods=["GET"])
def get_threats():
    data    = _load_json(THREATS_FILE)
    threats = data.get("threats", [])
    return jsonify({"threats": list(reversed(threats[-100:]))})


@api.route("/blacklist", methods=["GET"])
def get_blacklist_route():
    """Proxy to enhanced blacklist."""
    return jsonify(get_blacklist())


@api.route("/block", methods=["POST"])
def block_ip():
    """Manually block an IP (uses enhanced blacklist with metadata)."""
    body   = request.get_json(silent=True) or {}
    ip     = body.get("ip", "").strip()
    reason = body.get("reason", "Manual block").strip()

    if not _valid_ip(ip):
        return jsonify({"error": "Invalid IP address"}), 400

    result = add_to_blacklist(ip, reason=reason, score=0, auto=False)
    if result.get("whitelisted"):
        return jsonify(result), 403
    return jsonify(result)


@api.route("/unblock", methods=["POST"])
def unblock_ip():
    body = request.get_json(silent=True) or {}
    ip   = body.get("ip", "").strip()
    if not _valid_ip(ip):
        return jsonify({"error": "Invalid IP address"}), 400
    result = remove_from_blacklist(ip)
    if "error" in result:
        return jsonify(result), 404
    return jsonify(result)


@api.route("/scan/ip", methods=["POST"])
def scan_ip():
    """Scan a single IP. Auto-blocks if risk score exceeds threshold."""
    body = request.get_json(silent=True) or {}
    ip   = body.get("ip", "").strip()

    if not _valid_ip(ip):
        return jsonify({"error": "Invalid IP address"}), 400

    # Rate-limit tracking for this IP
    from models.prevention_engine import get_config
    cfg = get_config()
    if cfg.get("rate_limit_enabled", True):
        allowed, rl_info = limiter.is_allowed(ip)
        if not allowed:
            return jsonify({
                "error":       "Rate limit exceeded for this IP",
                "rate_limit":  rl_info,
            }), 429

    ip_stats = {
        "ip":              ip,
        "request_count":   int(body.get("request_count", 1)),
        "failed_attempts": int(body.get("failed_attempts", 0)),
        "unique_paths":    int(body.get("unique_paths", 1)),
        "error_rate":      float(body.get("error_rate", 0.0)),
        "avg_payload_size": float(body.get("avg_payload_size", 200.0)),
    }

    behaviour  = analyze_ip_behaviour(ip_stats)
    risk_score = calculate_risk_score(behaviour)

    result = {
        **behaviour,
        "risk_score":  risk_score,
        "risk_level":  score_to_level(risk_score),
        "risk_color":  score_to_color(risk_score),
        "scan_id":     str(uuid.uuid4()),
        "timestamp":   datetime.utcnow().isoformat(),
        "whitelisted": is_whitelisted(ip),
        "already_blocked": is_blocked(ip),
    }

    # Phase 2 — auto-block evaluation
    auto_action = evaluate_auto_block(result)
    result["auto_block_action"] = auto_action

    _append_threat(result)
    return jsonify(result)


@api.route("/scan/log", methods=["POST"])
def scan_log():
    """Upload and scan a log file. Auto-blocks dangerous IPs."""
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    if not file.filename:
        return jsonify({"error": "Empty filename"}), 400

    ext = os.path.splitext(secure_filename(file.filename))[1].lower()
    if ext not in ALLOWED_EXTS:
        return jsonify({"error": f"File type '{ext}' not allowed. Use .log .txt .csv"}), 400

    content = file.read().decode("utf-8", errors="replace")
    if len(content) > 5 * 1024 * 1024:
        return jsonify({"error": "File too large (max 5 MB)"}), 413

    entries = parse_log_content(content)
    if not entries:
        return jsonify({"error": "No parseable log entries found"}), 422

    # Per-IP behaviour analysis
    ip_aggregates = aggregate_by_ip(entries)
    ip_results    = []
    auto_blocked  = []

    for ip_stats in ip_aggregates:
        behaviour  = analyze_ip_behaviour(ip_stats)
        risk_score = calculate_risk_score(behaviour)
        entry_result = {
            **behaviour,
            "risk_score":      risk_score,
            "risk_level":      score_to_level(risk_score),
            "risk_color":      score_to_color(risk_score),
            "scan_id":         str(uuid.uuid4()),
            "timestamp":       datetime.utcnow().isoformat(),
            "whitelisted":     is_whitelisted(ip_stats["ip"]),
            "already_blocked": is_blocked(ip_stats["ip"]),
        }

        # Phase 2 — auto-block evaluation
        auto_action = evaluate_auto_block(entry_result)
        entry_result["auto_block_action"] = auto_action
        if auto_action.get("action") == "auto_blocked":
            auto_blocked.append(ip_stats["ip"])

        ip_results.append(entry_result)
        _append_threat(entry_result)

    threats_data = _load_json(THREATS_FILE)
    threats_data["total_scanned"] = threats_data.get("total_scanned", 0) + len(entries)
    threats_data["last_scan"]     = datetime.utcnow().isoformat()
    _save_json(THREATS_FILE, threats_data)

    trim_threat_history()

    danger_count     = sum(1 for r in ip_results if r["risk_level"] == "danger")
    suspicious_count = sum(1 for r in ip_results if r["risk_level"] == "suspicious")
    safe_count       = sum(1 for r in ip_results if r["risk_level"] == "safe")

    return jsonify({
        "message":       "Scan complete",
        "total_entries": len(entries),
        "unique_ips":    len(ip_results),
        "danger":        danger_count,
        "suspicious":    suspicious_count,
        "safe":          safe_count,
        "auto_blocked":  auto_blocked,
        "results":       ip_results,
    })


@api.route("/report", methods=["GET"])
def generate_report():
    threats_data   = _load_json(THREATS_FILE)
    blacklist_data = get_blacklist()
    threats        = threats_data.get("threats", [])

    danger     = [t for t in threats if t.get("risk_level") == "danger"]
    suspicious = [t for t in threats if t.get("risk_level") == "suspicious"]
    safe_list  = [t for t in threats if t.get("risk_level") == "safe"]

    report = {
        "report_id":    str(uuid.uuid4()),
        "generated_at": datetime.utcnow().isoformat(),
        "summary": {
            "total_threats":  len(threats),
            "danger":         len(danger),
            "suspicious":     len(suspicious),
            "safe":           len(safe_list),
            "blocked_ips":    blacklist_data.get("total", 0),
            "total_scanned":  threats_data.get("total_scanned", 0),
            "last_scan":      threats_data.get("last_scan", "N/A"),
        },
        "top_threats": sorted(threats, key=lambda x: x.get("risk_score", 0), reverse=True)[:10],
        "blocked_ips": blacklist_data.get("blocked_ips", []),
    }
    return jsonify(report)


@api.route("/clear", methods=["POST"])
def clear_threats():
    _save_json(THREATS_FILE, {"threats": [], "total_scanned": 0, "last_scan": ""})
    return jsonify({"message": "Threat history cleared"})


# ── Internal ──────────────────────────────────────────────────────────────────

def _append_threat(result: dict):
    data    = _load_json(THREATS_FILE)
    threats = data.get("threats", [])
    threats.append(result)
    data["threats"] = threats
    _save_json(THREATS_FILE, data)