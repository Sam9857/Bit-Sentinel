"""
monitor_routes.py — Live Monitoring API
========================================
POST /api/live-monitoring/start
POST /api/live-monitoring/stop
GET  /api/live-monitoring/status
POST /api/live-monitoring/set-log-path
GET  /api/live-monitoring/tap-feed
"""

import os
from flask import Blueprint, request, jsonify
import utils.live_monitor as monitor

live_bp = Blueprint("live_monitor", __name__, url_prefix="/api/live-monitoring")


@live_bp.route("/start", methods=["POST"])
def start_monitoring():
    body     = request.get_json(silent=True) or {}
    interval = max(2, min(int(body.get("interval", 5)), 30))
    mode     = body.get("mode", "simulate")
    if mode not in ("simulate", "self_tap", "log_tail"):
        mode = "simulate"
    return jsonify(monitor.start(interval=interval, mode=mode))


@live_bp.route("/stop", methods=["POST"])
def stop_monitoring():
    return jsonify(monitor.stop())


@live_bp.route("/status", methods=["GET"])
def monitoring_status():
    status = monitor.get_status()
    status["running"] = monitor.is_running()
    return jsonify(status)


@live_bp.route("/set-log-path", methods=["POST"])
def set_log_path():
    body = request.get_json(silent=True) or {}
    path = body.get("path", "").strip()
    if not path:
        return jsonify({"error": "path is required"}), 400
    if not os.path.isfile(path):
        return jsonify({
            "error": "File not found: {}".format(path),
            "tip":   "Provide an absolute path to a readable access.log file"
        }), 404
    from utils.log_tailer import set_path
    set_path(path)
    return jsonify({"status": "path set", "path": path})


@live_bp.route("/tap-feed", methods=["GET"])
def tap_feed():
    """Return recent real HTTP requests captured by the self-tap."""
    try:
        from utils.traffic_tap import is_enabled, get_recent_requests
        return jsonify({
            "enabled":  is_enabled(),
            "requests": get_recent_requests(50),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500