import re
from datetime import datetime

# Common log formats
# Apache/Nginx combined:  IP - - [timestamp] "METHOD /path HTTP/1.x" status size
# Simple:                 timestamp IP STATUS METHOD /path [payload]

APACHE_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'
    r'.*?\[(?P<timestamp>[^\]]+)\]'
    r'\s+"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/[\d.]+"'
    r'\s+(?P<status_code>\d{3})'
    r'(?:\s+(?P<size>\d+|-?))?'
    r'(?:.*?"(?P<payload>[^"]*)")?'
)

SIMPLE_PATTERN = re.compile(
    r'(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})?'
    r'\s*(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'
    r'\s+(?P<status_code>\d{3})'
    r'\s+(?P<method>[A-Z]+)'
    r'\s+(?P<path>\S+)'
    r'(?:\s+(?P<payload>.*))?'
)


def parse_line(line: str) -> dict | None:
    """Try to parse a single log line. Returns dict or None."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    for pattern in (APACHE_PATTERN, SIMPLE_PATTERN):
        m = pattern.search(line)
        if m:
            d = m.groupdict()
            return {
                "ip": d.get("ip", "0.0.0.0"),
                "timestamp": d.get("timestamp") or datetime.utcnow().isoformat(),
                "method": d.get("method", "GET"),
                "path": d.get("path", "/"),
                "status_code": int(d.get("status_code") or 200),
                "payload": d.get("payload") or "",
                "raw": line,
            }

    # Fallback: try to extract at least an IP
    ip_match = re.search(r'\d{1,3}(?:\.\d{1,3}){3}', line)
    if ip_match:
        return {
            "ip": ip_match.group(),
            "timestamp": datetime.utcnow().isoformat(),
            "method": "UNKNOWN",
            "path": "/",
            "status_code": 200,
            "payload": line,
            "raw": line,
        }

    return None


def parse_log_content(content: str) -> list[dict]:
    """Parse multi-line log content and return list of entry dicts."""
    entries = []
    for line in content.splitlines():
        entry = parse_line(line)
        if entry:
            entries.append(entry)
    return entries


def aggregate_by_ip(entries: list[dict]) -> list[dict]:
    """Aggregate log entries by IP address to build per-IP stats."""
    from collections import defaultdict

    stats: dict[str, dict] = defaultdict(lambda: {
        "request_count": 0,
        "failed_attempts": 0,
        "unique_paths": set(),
        "total_payload_size": 0,
        "error_count": 0,
    })

    for e in entries:
        ip = e["ip"]
        stats[ip]["request_count"] += 1
        stats[ip]["unique_paths"].add(e["path"])
        stats[ip]["total_payload_size"] += len(e.get("payload", ""))

        code = int(e.get("status_code", 200))
        if code in (401, 403):
            stats[ip]["failed_attempts"] += 1
        if code >= 400:
            stats[ip]["error_count"] += 1

    result = []
    for ip, s in stats.items():
        req = s["request_count"]
        result.append({
            "ip": ip,
            "request_count": req,
            "failed_attempts": s["failed_attempts"],
            "unique_paths": len(s["unique_paths"]),
            "error_rate": round(s["error_count"] / req, 4) if req else 0,
            "avg_payload_size": round(s["total_payload_size"] / req, 2) if req else 0,
        })

    return result