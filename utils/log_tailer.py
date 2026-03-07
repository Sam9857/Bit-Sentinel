"""
log_tailer.py — Real Log File Tailer
======================================
Watches a Nginx / Apache / IIS access.log file in real time,
exactly like `tail -F`, feeding new lines into the existing
parse → aggregate → detect pipeline.

Usage:
    from utils.log_tailer import tailer
    tailer.set_path("/var/log/nginx/access.log")
    tailer.start()
    tailer.stop()
"""

import os
import threading
from datetime import datetime
from collections import defaultdict

from utils.log_parser import parse_line

_lock       = threading.Lock()
_thread     = None
_stop_event = threading.Event()
_log_path   = None
_recent     = []   # parsed entries, last 200
MAX_RECENT  = 200

_status = {
    "running":      False,
    "log_path":     None,
    "lines_read":   0,
    "started_at":   None,
    "last_line_at": None,
    "error":        None,
}


def _on_new_line(raw_line):
    entry = parse_line(raw_line)   # EXISTING log_parser function
    if not entry:
        return
    with _lock:
        _recent.append(entry)
        if len(_recent) > MAX_RECENT:
            _recent.pop(0)
        _status["lines_read"] += 1
        _status["last_line_at"] = datetime.utcnow().isoformat()


def _tail_loop(path):
    """Seek to end of file, then yield new lines as they appear (like tail -F)."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            f.seek(0, 2)   # jump to end
            while not _stop_event.is_set():
                line = f.readline()
                if line:
                    _on_new_line(line)
                else:
                    _stop_event.wait(timeout=0.5)
    except FileNotFoundError:
        with _lock:
            _status["error"]   = "File not found: {}".format(path)
            _status["running"] = False
    except Exception as exc:
        with _lock:
            _status["error"]   = str(exc)
            _status["running"] = False


def set_path(path):
    global _log_path
    _log_path = os.path.abspath(path)
    with _lock:
        _status["log_path"] = _log_path
        _status["error"]    = None


def start():
    global _thread
    if not _log_path:
        return {"error": "No log path set"}
    if _thread and _thread.is_alive():
        return {"status": "already_running", **get_status()}

    _stop_event.clear()
    with _lock:
        _status.update({
            "running":    True,
            "started_at": datetime.utcnow().isoformat(),
            "lines_read": 0,
            "error":      None,
        })

    _thread = threading.Thread(
        target=_tail_loop, args=(_log_path,),
        daemon=True, name="LogTailer"
    )
    _thread.start()
    return {"status": "started", **get_status()}


def stop():
    _stop_event.set()
    with _lock:
        _status["running"] = False
    return {"status": "stopped", **get_status()}


def is_running():
    return _thread is not None and _thread.is_alive() and not _stop_event.is_set()


def get_status():
    with _lock:
        return dict(_status)


def get_ip_stats_from_recent():
    """Aggregate recent log entries into ip_stats for the detection pipeline."""
    with _lock:
        entries = list(_recent)

    # Inline aggregation (same logic as log_parser.aggregate_by_ip)
    buckets = defaultdict(lambda: {
        "request_count": 0, "failed_attempts": 0,
        "unique_paths": set(), "error_count": 0, "total_payload_sz": 0,
    })
    for e in entries:
        ip = e["ip"]
        buckets[ip]["request_count"] += 1
        buckets[ip]["unique_paths"].add(e.get("path", "/"))
        buckets[ip]["total_payload_sz"] += len(e.get("payload", ""))
        code = int(e.get("status_code", 200))
        if code in (401, 403):
            buckets[ip]["failed_attempts"] += 1
        if code >= 400:
            buckets[ip]["error_count"] += 1

    result = []
    for ip, b in buckets.items():
        req = b["request_count"]
        result.append({
            "ip":              ip,
            "request_count":   req,
            "failed_attempts": b["failed_attempts"],
            "unique_paths":    len(b["unique_paths"]),
            "error_rate":      round(b["error_count"] / req, 4) if req else 0,
            "avg_payload_size": round(b["total_payload_sz"] / req, 2) if req else 0,
        })
    return result


def get_recent_entries(limit=50):
    with _lock:
        return list(reversed(_recent[-limit:]))