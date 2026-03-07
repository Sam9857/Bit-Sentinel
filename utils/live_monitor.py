"""
live_monitor.py — Live Threat Monitoring (3 modes)
===================================================

MODE 1: simulate  — Synthetic traffic. Always works. Great for demos.
MODE 2: self_tap  — Monitors REAL requests hitting THIS Flask app.
                    Judges browsing the dashboard = real traffic being analysed.
MODE 3: log_tail  — Tails a real Nginx/Apache access.log file.
                    Production deployment mode.

All 3 modes feed the SAME existing detection pipeline:
    analyze_ip_behaviour() → calculate_risk_score() → evaluate_auto_block()

Python 3.9 compatible. Uses analyze_ip_behaviour (correct function). is_running() present.
"""

import json
import os
import random
import threading
import uuid
from datetime import datetime

# Existing pipeline — no changes to these
from models.threat_detector   import analyze_ip_behaviour
from utils.risk_scoring       import calculate_risk_score, score_to_level, score_to_color
from models.prevention_engine import evaluate_auto_block, trim_threat_history

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR     = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR     = os.path.join(BASE_DIR, "data")
THREATS_FILE = os.path.join(DATA_DIR, "threats.json")

# ── Module state ──────────────────────────────────────────────────────────────
_thread     = None     # threading.Thread or None
_stop_event = threading.Event()
_lock       = threading.Lock()
_mode       = "simulate"

_session_stats = {
    "running":          False,
    "mode":             "simulate",
    "started_at":       None,
    "events_generated": 0,
    "threats_found":    0,
    "auto_blocked":     0,
    "interval_seconds": 5,
}

# ── Simulation profiles ───────────────────────────────────────────────────────
_PROFILES = [
    ("benign_user",      40),
    ("moderate_scanner", 20),
    ("brute_forcer",     15),
    ("high_freq_ddos",   10),
    ("sql_injector",      5),
    ("xss_attacker",      5),
    ("path_traverser",    5),
]

_IP_POOL = (
    ["45.33.32.{}".format(i)    for i in range(1, 20)] +
    ["203.0.113.{}".format(i)   for i in range(1, 15)] +
    ["198.51.100.{}".format(i)  for i in range(1, 10)] +
    ["10.0.0.{}".format(i)      for i in range(50, 65)] +
    ["172.16.0.{}".format(i)    for i in range(1, 10)]
)

_PROFILE_EXTRA_TYPES = {
    "sql_injector":   ["SQL Injection"],
    "xss_attacker":   ["XSS"],
    "path_traverser": ["Path Traversal"],
}


def _pick_profile():
    names, weights = zip(*_PROFILES)
    return random.choices(names, weights=weights, k=1)[0]


def _build_sim_stats(ip, profile):
    """Build ip_stats for simulate mode."""
    base = {"ip": ip}
    if profile == "benign_user":
        base.update(request_count=random.randint(1,25), failed_attempts=random.randint(0,1),
                    unique_paths=random.randint(1,10), error_rate=round(random.uniform(0,.08),3),
                    avg_payload_size=random.uniform(100,800))
    elif profile == "moderate_scanner":
        base.update(request_count=random.randint(30,75), failed_attempts=random.randint(2,4),
                    unique_paths=random.randint(20,55), error_rate=round(random.uniform(.15,.40),3),
                    avg_payload_size=random.uniform(100,400))
    elif profile == "brute_forcer":
        a = random.randint(6,20)
        base.update(request_count=a+random.randint(0,5), failed_attempts=a,
                    unique_paths=random.randint(1,3), error_rate=round(random.uniform(.7,.98),3),
                    avg_payload_size=random.uniform(80,300))
    elif profile == "high_freq_ddos":
        base.update(request_count=random.randint(110,400), failed_attempts=random.randint(0,3),
                    unique_paths=random.randint(1,5), error_rate=round(random.uniform(0,.15),3),
                    avg_payload_size=random.uniform(50,250))
    elif profile == "sql_injector":
        base.update(request_count=random.randint(8,30), failed_attempts=random.randint(1,5),
                    unique_paths=random.randint(3,12), error_rate=round(random.uniform(.20,.55),3),
                    avg_payload_size=random.uniform(400,2000))
    elif profile == "xss_attacker":
        base.update(request_count=random.randint(5,20), failed_attempts=random.randint(0,3),
                    unique_paths=random.randint(2,8), error_rate=round(random.uniform(.10,.40),3),
                    avg_payload_size=random.uniform(300,1500))
    elif profile == "path_traverser":
        base.update(request_count=random.randint(5,20), failed_attempts=random.randint(3,8),
                    unique_paths=random.randint(10,40), error_rate=round(random.uniform(.50,.90),3),
                    avg_payload_size=random.uniform(200,800))
    else:
        base.update(request_count=5, failed_attempts=0, unique_paths=3,
                    error_rate=0.0, avg_payload_size=200.0)
    return base


# ── Core: run ip_stats through existing pipeline and persist ──────────────────
def _analyse_and_store(ip_stats, source, extra_types=None):
    behaviour  = analyze_ip_behaviour(ip_stats)
    risk_score = calculate_risk_score(behaviour)

    for t in (extra_types or []):
        if t not in behaviour["threat_types"]:
            behaviour["threat_types"].append(t)
            risk_score = calculate_risk_score(behaviour)

    result = {
        "ip":              behaviour["ip"],
        "request_count":   behaviour.get("request_count", 0),
        "failed_attempts": behaviour.get("failed_attempts", 0),
        "unique_paths":    behaviour.get("unique_paths", 0),
        "error_rate":      behaviour.get("error_rate", 0),
        "threat_types":    behaviour.get("threat_types", []),
        "ml_anomaly":      behaviour.get("ml_anomaly", False),
        "ml_score":        behaviour.get("ml_score", 0),
        "risk_score":      risk_score,
        "risk_level":      score_to_level(risk_score),
        "risk_color":      score_to_color(risk_score),
        "scan_id":         str(uuid.uuid4()),
        "timestamp":       datetime.utcnow().isoformat(),
        "source":          source,
        "whitelisted":     False,
        "already_blocked": False,
    }
    auto = evaluate_auto_block(result)
    result["auto_block_action"] = auto
    _append_threat(result)

    with _lock:
        _session_stats["events_generated"] += 1
        if result["risk_level"] in ("danger", "suspicious"):
            _session_stats["threats_found"] += 1
        if auto.get("action") == "auto_blocked":
            _session_stats["auto_blocked"] += 1
    return result


# ── JSON helpers ──────────────────────────────────────────────────────────────
def _load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def _append_threat(result):
    data = _load_json(THREATS_FILE)
    threats = data.get("threats", [])
    threats.append(result)
    data["threats"]       = threats
    data["total_scanned"] = data.get("total_scanned", 0) + 1
    data["last_scan"]     = datetime.utcnow().isoformat()
    _save_json(THREATS_FILE, data)


# ── Mode tick functions ───────────────────────────────────────────────────────
def _tick_simulate():
    for _ in range(random.randint(2, 5)):
        ip      = random.choice(_IP_POOL)
        profile = _pick_profile()
        stats   = _build_sim_stats(ip, profile)
        extras  = _PROFILE_EXTRA_TYPES.get(profile, [])
        _analyse_and_store(stats, source="simulate", extra_types=extras)


def _tick_self_tap():
    try:
        from utils.traffic_tap import get_ip_stats
        for ip_stats in get_ip_stats():
            if ip_stats["request_count"] > 0:
                _analyse_and_store(ip_stats, source="self_tap")
    except Exception as exc:
        print("[Monitor/tap] {}".format(exc))


def _tick_log_tail():
    try:
        from utils.log_tailer import get_ip_stats_from_recent
        for ip_stats in get_ip_stats_from_recent():
            if ip_stats["request_count"] > 0:
                _analyse_and_store(ip_stats, source="log_tail")
    except Exception as exc:
        print("[Monitor/logtail] {}".format(exc))


# ── Background thread ─────────────────────────────────────────────────────────
def _monitor_loop(interval, mode):
    fn = {"simulate": _tick_simulate,
          "self_tap":  _tick_self_tap,
          "log_tail":  _tick_log_tail}.get(mode, _tick_simulate)
    while not _stop_event.is_set():
        try:
            fn()
            trim_threat_history()
        except Exception as exc:
            print("[LiveMonitor] {}".format(exc))
        _stop_event.wait(timeout=interval)


# ── Public API ────────────────────────────────────────────────────────────────
def start(interval=5, mode="simulate"):
    global _thread, _mode
    if _thread is not None and _thread.is_alive():
        return {"status": "already_running", **get_status()}

    _mode = mode
    _stop_event.clear()

    if mode == "self_tap":
        try:
            from utils.traffic_tap import enable
            enable()
        except Exception as e:
            return {"error": "traffic_tap failed: {}".format(e)}
    elif mode == "log_tail":
        try:
            from utils.log_tailer import start as lt_start, get_status as lt_status
            if not lt_status().get("log_path"):
                return {"error": "No log path set. POST /api/live-monitoring/set-log-path first."}
            lt_start()
        except Exception as e:
            return {"error": "log_tailer failed: {}".format(e)}

    with _lock:
        _session_stats.update({
            "running":          True,
            "mode":             mode,
            "started_at":       datetime.utcnow().isoformat(),
            "events_generated": 0,
            "threats_found":    0,
            "auto_blocked":     0,
            "interval_seconds": interval,
        })

    _thread = threading.Thread(
        target=_monitor_loop, args=(interval, mode),
        daemon=True, name="LiveMonitor"
    )
    _thread.start()
    return {"status": "started", **get_status()}


def stop():
    _stop_event.set()
    try:
        from utils.traffic_tap import disable
        disable()
    except Exception:
        pass
    try:
        from utils.log_tailer import stop as lt_stop
        lt_stop()
    except Exception:
        pass
    with _lock:
        _session_stats["running"] = False
    return {"status": "stopped", **get_status()}


def get_status():
    with _lock:
        return dict(_session_stats)


def is_running():
    return _thread is not None and _thread.is_alive() and not _stop_event.is_set()