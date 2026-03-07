"""
threat_detector.py  —  Pattern-Based Threat Detection
======================================================
This module handles the PATTERN RECOGNITION layer of BitSentinel's AI.

Two levels of analysis:
  1. analyze_log_entry()   — per-request pattern matching (SQLi, XSS, etc.)
  2. analyze_ip_behaviour() — per-IP behavioral profiling via the AI engine

AI Logic Used Here:
  - Regex pattern recognition (known attack signatures)
  - Behavioral threshold analysis (brute force, high frequency)
  - Explainable AI behavioral scoring (via anomaly_model.py)
  - Multi-signal threat type classification
"""

import re

# ── AI Engine: Explainable Behavioral Analyzer (replaces IsolationForest) ───
# AI Decision: Uses rule-based behavioral analysis — no ML, fully explainable
from models.anomaly_model import detector as ai_analyzer


# ─── Attack Pattern Databases ────────────────────────────────────────────────
# These are known attack signatures used by real-world WAFs (Web Application Firewalls).
# Pattern recognition is a classic form of AI: "if it looks like an attack, it is one."

# AI Logic: SQL Injection patterns — detect database manipulation attempts
SQL_INJECTION_PATTERNS = [
    r"(?i)(\bUNION\b.+\bSELECT\b)",    # UNION-based data extraction
    r"(?i)(--|#|/\*)",                   # SQL comment injection
    r"(?i)(\bOR\b\s+\d+=\d+)",          # Boolean-based bypass (1=1)
    r"(?i)(\bDROP\b\s+\bTABLE\b)",      # Destructive DDL injection
    r"(?i)(\bINSERT\b|\bUPDATE\b|\bDELETE\b)\s+\w+",  # DML manipulation
    r"(?i)(\'.*\'--)",                   # String termination + comment
    r"(?i)(exec\s*\(|execute\s*\()",    # Stored procedure execution
    r"(?i)(xp_cmdshell|sp_executesql)", # SQL Server command execution
]

# AI Logic: XSS patterns — detect script injection into web responses
XSS_PATTERNS = [
    r"(?i)<\s*script[^>]*>",            # Direct script tag injection
    r"(?i)javascript\s*:",              # JavaScript protocol in URLs
    r"(?i)on\w+\s*=\s*[\"']",          # Event handler injection (onclick, onerror)
    r"(?i)<\s*iframe[^>]*>",            # Hidden iframe injection
    r"(?i)(alert\s*\(|confirm\s*\(|prompt\s*\()",  # Classic XSS proof-of-concept
    r"(?i)(document\.cookie|window\.location)",     # Cookie theft / redirect
    r"(?i)eval\s*\(",                   # Dynamic code execution
]

# AI Logic: Path Traversal patterns — detect directory escape attempts
PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",          # Unix-style directory traversal
    r"\.\.\\",         # Windows-style directory traversal
    r"%2e%2e%2f",      # URL-encoded traversal
    r"%252e%252e",     # Double URL-encoded traversal (bypass filter evasion)
]

# ─── Behavioral Thresholds ───────────────────────────────────────────────────
# AI Decision: If an IP hits these thresholds, it's flagged as a specific threat type.
# These values are based on typical attack traffic analysis.

BRUTE_FORCE_THRESHOLD = 5    # AI Decision: 5+ failed logins = brute force pattern
HIGH_FREQ_THRESHOLD   = 100  # AI Decision: 100+ requests = potential DDoS/automated scan


def _check_patterns(text, patterns):
    """
    AI Logic: Pattern Recognition Engine.

    Scan a text string against a list of regex patterns.
    Returns all matched patterns (not just True/False) so we can
    explain WHICH specific pattern was detected.
    """
    matched = []
    for pattern in patterns:
        if re.search(pattern, text):
            matched.append(pattern)
    return matched


def analyze_log_entry(entry):
    """
    AI Logic: Per-Request Threat Analysis.

    Examines a single HTTP log entry and identifies attack patterns.
    This is "signature-based detection" — matching against a database
    of known attack strings, similar to how antivirus works.

    AI Decision Process:
      1. Combine URL path + payload body into a single search string
      2. Run against SQL injection, XSS, and path traversal signatures
      3. Any match = threat identified, explain which type was found

    Parameters:
        entry: {ip, method, path, status_code, payload, timestamp}

    Returns:
        Enriched dict with threat_types and threats_found (matched patterns)
    """
    result = {
        "ip":           entry.get("ip", "unknown"),
        "timestamp":    entry.get("timestamp", ""),
        "method":       entry.get("method", ""),
        "path":         entry.get("path", ""),
        "status_code":  entry.get("status_code", 200),
        "threats_found": [],
        "threat_types":  [],
        "risk_score":   0,
    }

    # AI Decision: Combine path and payload — attackers embed patterns in both
    combined_text = "{} {}".format(entry.get("path", ""), entry.get("payload", ""))

    # ── AI Decision: Check for SQL Injection ─────────────────────────────────
    # Database attacks attempt to extract, modify, or destroy stored data
    sql_hits = _check_patterns(combined_text, SQL_INJECTION_PATTERNS)
    if sql_hits:
        result["threats_found"].extend(sql_hits)
        result["threat_types"].append("SQL Injection")

    # ── AI Decision: Check for Cross-Site Scripting (XSS) ────────────────────
    # XSS attacks inject malicious scripts into web pages viewed by other users
    xss_hits = _check_patterns(combined_text, XSS_PATTERNS)
    if xss_hits:
        result["threats_found"].extend(xss_hits)
        result["threat_types"].append("XSS")

    # ── AI Decision: Check for Path Traversal ────────────────────────────────
    # Traversal attacks attempt to access files outside the web root
    pt_hits = _check_patterns(combined_text, PATH_TRAVERSAL_PATTERNS)
    if pt_hits:
        result["threats_found"].extend(pt_hits)
        result["threat_types"].append("Path Traversal")

    # ── AI Decision: HTTP 401/403 = Authentication Failure signal ────────────
    # A single 401/403 is normal; a pattern of them indicates credential attack
    if int(entry.get("status_code", 200)) in (401, 403):
        result["threat_types"].append("Auth Failure")

    return result


def analyze_ip_behaviour(ip_stats):
    """
    AI Logic: Per-IP Behavioral Profile Analysis.

    This function builds a complete behavioral profile of an IP address
    by combining multiple detection methods:

      1. Threshold-based detection (brute force, DDoS)
      2. AI Explainable Behavioral Scoring (via BehavioralAnalyzer)

    AI Decision Process:
      "Look at what this IP has done in aggregate. Does the pattern
       match known attack behaviors? How severe is the deviation from
       normal baseline? What does the combination of signals tell us?"

    Parameters:
        ip_stats: {ip, request_count, failed_attempts, unique_paths,
                   error_rate, avg_payload_size}

    Returns:
        Complete behavioral analysis dict with threat types and AI scores
    """
    threat_types = []

    # ── AI Decision: Brute Force Detection ──────────────────────────────────
    # Logic: If an IP has failed to authenticate 5+ times, it is likely
    # running an automated credential stuffing or dictionary attack.
    # Human users rarely fail login more than 2-3 times.
    if ip_stats.get("failed_attempts", 0) >= BRUTE_FORCE_THRESHOLD:
        # AI Decision: Flag as Brute Force — repeated auth failure pattern
        threat_types.append("Brute Force")

    # ── AI Decision: High Frequency / DDoS Detection ─────────────────────────
    # Logic: 100+ requests in a short window far exceeds normal human browsing.
    # This pattern is consistent with automated tools, bots, or DDoS.
    if ip_stats.get("request_count", 0) >= HIGH_FREQ_THRESHOLD:
        # AI Decision: Flag as High Frequency — volume exceeds human behavior
        threat_types.append("High Frequency / DDoS")

    # ── AI Decision: Explainable Behavioral Analysis (replaces ML) ───────────
    # The AI engine scores 5 behavioral dimensions and produces:
    #   - ai_anomaly: bool (is this IP behaving abnormally?)
    #   - ai_score:   float (0-1, how abnormal is it?)
    #   - signals:    dict (which specific signals triggered)
    #   - explanation: str (plain-English reason for the verdict)
    ai_result = ai_analyzer.predict(ip_stats)

    return {
        "ip":              ip_stats["ip"],
        "request_count":   ip_stats.get("request_count", 0),
        "failed_attempts": ip_stats.get("failed_attempts", 0),
        "unique_paths":    ip_stats.get("unique_paths", 0),
        "error_rate":      round(ip_stats.get("error_rate", 0), 4),
        "threat_types":    threat_types,
        # AI Explainable fields (replaces ml_anomaly / ml_score)
        "ai_anomaly":      ai_result["anomaly"],
        "ai_score":        ai_result["score"],
        "ai_signals":      ai_result["signals"],
        "ai_explanation":  ai_result["explanation"],
        # Backward-compatible aliases so existing code doesn't break
        "ml_anomaly":      ai_result["anomaly"],
        "ml_score":        ai_result["score"],
    }