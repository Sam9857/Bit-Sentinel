"""
risk_scoring.py  —  AI-Driven Risk Scoring Engine
==================================================
Converts behavioral analysis results into a single 0-100 risk score.

This is BitSentinel's "Decision Intelligence" layer:
  - Aggregates multiple threat signals
  - Applies weighted scoring (not all threats are equal)
  - Escalates when multiple threats combine
  - Produces a final verdict: Safe / Suspicious / Danger

Risk Score Scale:
  0 – 30  → SAFE       (green)  — normal behavior
  31 – 60 → SUSPICIOUS (yellow) — warrants monitoring
  61 – 100 → DANGER    (red)    — immediate action recommended

AI Design Principle:
  Each weight reflects the real-world severity of the threat type.
  SQL Injection (30 pts) is weighted more heavily than Auth Failure (10 pts)
  because a successful SQL injection is far more damaging than a failed login.
"""

# ─── Threat Weight Table ─────────────────────────────────────────────────────
# AI Logic: These weights encode expert knowledge about threat severity.
# They answer: "If we detect this threat type, how dangerous is it?"
#
# Reasoning behind each weight:
#   failed_attempts   (3/attempt): Gradual escalation — more attempts = more risk
#   brute_force       (25 flat):   Confirms intent to gain unauthorized access
#   high_frequency    (20 flat):   May be DDoS or automated scanning
#   sql_injection     (30 flat):   CRITICAL — can expose/destroy entire database
#   xss               (25 flat):   HIGH — enables account takeover, data theft
#   path_traversal    (20 flat):   HIGH — can expose server configuration files
#   auth_failure      (10 flat):   MEDIUM — single signal, may be innocent
#   ai_anomaly        (15 flat):   AI Behavioral Analysis flagged this IP
#   ai_score_mult     (20 scaled): Scales with AI confidence in the anomaly
#   error_rate        (15 scaled): Scales with proportion of HTTP errors

WEIGHTS = {
    "failed_attempts":   3,    # Per-attempt contribution (capped at MAX_FAILED_CONTRIBUTION)
    "brute_force":      25,    # Flat score for confirmed brute force pattern
    "high_frequency":   20,    # Flat score for DDoS / scanner pattern
    "sql_injection":    30,    # Flat score — database attack (highest single threat)
    "xss":              25,    # Flat score — client-side script injection
    "path_traversal":   20,    # Flat score — file system reconnaissance
    "auth_failure":     10,    # Flat score — authentication failure signal
    "ai_anomaly":       15,    # Flat score — AI behavioral analysis flagged
    "ai_score_mult":    20,    # Multiplied by AI score (0-1) — scales with confidence
    "error_rate":       15,    # Multiplied by error_rate (0-1) — scales with volume
}

# AI Decision: Cap the contribution from failed attempts to prevent
# a single signal from dominating the entire score.
MAX_FAILED_CONTRIBUTION = 30


def calculate_risk_score(threat_data):
    """
    AI Logic: Composite Risk Score Calculation.

    Combines all threat signals into a single 0-100 risk score.
    This is the "decision output" of BitSentinel's AI — the final
    judgment on how dangerous this IP is.

    The scoring process mirrors how a security analyst mentally
    tallies up evidence: "This IP has SQLi + brute force + high error rate?
    That's three separate attack indicators — definite threat."

    Parameters:
        threat_data: {failed_attempts, threat_types, ai_anomaly,
                      ai_score, error_rate}
                      (ml_anomaly / ml_score also accepted for compatibility)

    Returns:
        int — risk score from 0 to 100
    """
    score = 0.0

    # ── AI Decision: Failed Attempts Contribution ────────────────────────────
    # Each failed login attempt adds 3 points, capped at 30 total.
    # This prevents a single brute-force signal from reaching 100 alone.
    failed_contrib = min(
        threat_data.get("failed_attempts", 0) * WEIGHTS["failed_attempts"],
        MAX_FAILED_CONTRIBUTION
    )
    score += failed_contrib

    # ── AI Decision: Threat Type Flat Score Bonuses ──────────────────────────
    # Each detected threat type adds a fixed amount based on its severity.
    # We normalize to lowercase so matching is robust.
    threat_types = [t.lower() for t in threat_data.get("threat_types", [])]

    if "brute force" in threat_types:
        # AI Decision: Increase score — repeated auth failure pattern confirmed
        score += WEIGHTS["brute_force"]

    if "high frequency / ddos" in threat_types:
        # AI Decision: Increase score — request volume exceeds human behavior
        score += WEIGHTS["high_frequency"]

    if "sql injection" in threat_types:
        # AI Decision: Increase score — database attack pattern detected in payload
        score += WEIGHTS["sql_injection"]

    if "xss" in threat_types:
        # AI Decision: Increase score — script injection pattern detected
        score += WEIGHTS["xss"]

    if "path traversal" in threat_types:
        # AI Decision: Increase score — directory escape attempt detected
        score += WEIGHTS["path_traversal"]

    if "auth failure" in threat_types:
        # AI Decision: Increase score — HTTP 401/403 response pattern
        score += WEIGHTS["auth_failure"]

    # ── AI Decision: Behavioral Anomaly Score ────────────────────────────────
    # Use ai_anomaly / ai_score if present (new explainable AI fields).
    # Fall back to ml_anomaly / ml_score for backward compatibility.
    ai_anomaly = threat_data.get("ai_anomaly", threat_data.get("ml_anomaly", False))
    ai_score   = threat_data.get("ai_score",   threat_data.get("ml_score",   0.0))

    if ai_anomaly:
        # AI Decision: Behavioral analysis flagged this IP as anomalous
        score += WEIGHTS["ai_anomaly"]

    # AI Decision: Scale additional points by AI confidence (0-1)
    # High AI confidence = proportionally higher score contribution
    score += ai_score * WEIGHTS["ai_score_mult"]

    # ── AI Decision: Error Rate Contribution ─────────────────────────────────
    # High HTTP error rate indicates automated scanning or failed exploits
    score += threat_data.get("error_rate", 0.0) * WEIGHTS["error_rate"]

    # ── AI Decision: Combination Escalation ──────────────────────────────────
    # CRITICAL INSIGHT: Multiple threat signals together are MORE dangerous
    # than the sum of their parts. A single failed login may be innocent.
    # Failed logins + SQL injection + path traversal = coordinated attack.
    active_threat_count = len(threat_types)
    if active_threat_count >= 3:
        # AI Decision: Three or more threat types = coordinated multi-vector attack
        # Apply 20% escalation bonus — this attack is well-organized
        score *= 1.20
    elif active_threat_count == 2:
        # AI Decision: Two threat types = likely not accidental, escalate slightly
        score *= 1.08

    final = int(min(score, 100))
    return final


def score_to_level(score):
    """
    AI Decision: Convert numeric score to human-readable threat level.
    These thresholds define the boundary between monitoring and action.
    """
    if score <= 30:
        return "safe"        # Normal behavior — no action needed
    elif score <= 60:
        return "suspicious"  # Worth monitoring — may escalate
    return "danger"          # Immediate action recommended — auto-block threshold


def score_to_color(score):
    """Return the UI color associated with a risk level."""
    if score <= 30:
        return "#00ff88"   # Green — safe
    elif score <= 60:
        return "#ffdd00"   # Yellow — suspicious
    return "#ff3333"       # Red — danger