"""
anomaly_model.py  —  Explainable AI Behavioral Analysis Engine
==============================================================
NO Machine Learning. NO sklearn. NO IsolationForest.

This module implements "Explainable AI" — a rule-based behavioral
analysis system that mimics how a human security analyst thinks:

  1. Examine each behavioral signal independently
  2. Assign a severity weight to each signal
  3. Combine signals to produce a composite anomaly score
  4. Explain the reasoning in plain English

Why this is considered "AI":
  - It makes decisions autonomously based on patterns
  - It reasons about multiple signals simultaneously
  - It explains WHY something is suspicious (XAI principle)
  - It adapts its verdict based on signal combinations

A human analyst would do exactly this mental process —
BitSentinel automates and standardizes it.
"""


# ─── Behavioral Thresholds ──────────────────────────────────────────────────
# These define what "normal" looks like. Values above these thresholds
# are considered suspicious by the AI decision engine.

THRESHOLDS = {
    # A normal user makes fewer than 15 requests per scan window.
    # AI Decision: More than 15 = start watching. More than 50 = escalate.
    "request_count_low":    15,
    "request_count_high":   50,

    # Normal users hit 1-2 failed auth per session (typos happen).
    # AI Decision: 3+ failures = possible credential stuffing.
    "failed_attempts_low":  3,
    "failed_attempts_high": 8,

    # Normal users visit 3-5 unique pages.
    # AI Decision: 20+ unique paths = directory enumeration / scanning.
    "unique_paths_low":     20,
    "unique_paths_high":    50,

    # Normal error rate is very low (< 5%).
    # AI Decision: >20% errors = broken exploit attempts or scanner.
    "error_rate_low":       0.20,
    "error_rate_high":      0.60,

    # Normal payloads are small (forms, JSON).
    # AI Decision: Large payloads may contain injection strings.
    "payload_size_low":     1000,
    "payload_size_high":    4000,
}

# ─── Signal Weights ──────────────────────────────────────────────────────────
# Each behavioral signal contributes differently to the anomaly score.
# Weights are based on real-world attack analysis:
#   - Failed auth is a strong indicator (brute force attacks)
#   - High error rate suggests automated scanning
#   - Path enumeration suggests reconnaissance

SIGNAL_WEIGHTS = {
    "request_count":   0.15,   # Volume-based signal
    "failed_attempts": 0.35,   # Auth failure signal (highest weight)
    "unique_paths":    0.20,   # Reconnaissance signal
    "error_rate":      0.20,   # Scanner/exploit signal
    "payload_size":    0.10,   # Injection attempt signal
}


def _score_signal(value, low_threshold, high_threshold):
    """
    AI Logic: Score a single behavioral signal on a 0.0-1.0 scale.

    0.0 = completely normal behavior
    0.5 = suspicious (above low threshold)
    1.0 = clearly malicious (above high threshold)

    Values between thresholds are interpolated linearly.
    This mirrors how an analyst would grade a signal: not binary,
    but graduated — because real attacks exist on a spectrum.
    """
    if value <= low_threshold:
        # Below suspicion threshold — AI Decision: normal behavior
        return 0.0

    if value >= high_threshold:
        # Above danger threshold — AI Decision: clearly anomalous
        return 1.0

    # AI Decision: Interpolate between 0.5 and 1.0 for the middle zone
    range_size = high_threshold - low_threshold
    position   = value - low_threshold
    return round(0.5 + (0.5 * position / range_size), 4)


def _build_signal_scores(ip_data):
    """
    AI Logic: Evaluate ALL behavioral signals for a given IP.

    Each signal is scored independently, then combined with weights.
    This is "multi-dimensional behavioral profiling" — exactly what
    a Tier-2 SOC analyst does when triaging an alert.

    Returns a dict of individual signal scores (for transparency/explanation).
    """
    scores = {}

    # ── Signal 1: Request Volume ─────────────────────────────────────────
    # AI Decision: High request count may indicate automated tools or DDoS
    scores["request_count"] = _score_signal(
        ip_data.get("request_count", 0),
        THRESHOLDS["request_count_low"],
        THRESHOLDS["request_count_high"],
    )

    # ── Signal 2: Failed Authentication Attempts ─────────────────────────
    # AI Decision: Repeated auth failures = credential brute-force pattern
    scores["failed_attempts"] = _score_signal(
        ip_data.get("failed_attempts", 0),
        THRESHOLDS["failed_attempts_low"],
        THRESHOLDS["failed_attempts_high"],
    )

    # ── Signal 3: Unique Path Count ──────────────────────────────────────
    # AI Decision: Hitting many unique endpoints = directory enumeration
    scores["unique_paths"] = _score_signal(
        ip_data.get("unique_paths", 0),
        THRESHOLDS["unique_paths_low"],
        THRESHOLDS["unique_paths_high"],
    )

    # ── Signal 4: HTTP Error Rate ─────────────────────────────────────────
    # AI Decision: High 4xx/5xx rate = automated tools probing for vulnerabilities
    scores["error_rate"] = _score_signal(
        ip_data.get("error_rate", 0.0),
        THRESHOLDS["error_rate_low"],
        THRESHOLDS["error_rate_high"],
    )

    # ── Signal 5: Average Payload Size ───────────────────────────────────
    # AI Decision: Large payloads may contain SQL/XSS injection strings
    scores["payload_size"] = _score_signal(
        ip_data.get("avg_payload_size", 0.0),
        THRESHOLDS["payload_size_low"],
        THRESHOLDS["payload_size_high"],
    )

    return scores


def _generate_explanation(signal_scores, composite_score):
    """
    AI Logic: Generate a plain-English explanation of WHY this IP is flagged.

    This is the "explainable" part of Explainable AI (XAI).
    A judge or analyst should be able to read this and immediately
    understand the decision without any ML knowledge.
    """
    reasons = []

    if signal_scores["failed_attempts"] > 0.3:
        reasons.append("repeated authentication failures suggest credential brute-force")

    if signal_scores["request_count"] > 0.3:
        reasons.append("abnormally high request volume consistent with automated tooling")

    if signal_scores["unique_paths"] > 0.3:
        reasons.append("wide path enumeration suggests directory/endpoint reconnaissance")

    if signal_scores["error_rate"] > 0.3:
        reasons.append("elevated HTTP error rate indicates exploit probing or scanner use")

    if signal_scores["payload_size"] > 0.3:
        reasons.append("oversized payloads may contain injection attack strings")

    if not reasons:
        return "Traffic pattern falls within normal behavioral baseline — no anomaly detected."

    level = "CRITICAL" if composite_score >= 0.7 else "SUSPICIOUS" if composite_score >= 0.4 else "LOW"
    return "[{}] AI Behavioral Analysis: {}. Composite anomaly score: {:.0%}".format(
        level, "; ".join(reasons), composite_score
    )


class BehavioralAnalyzer:
    """
    Explainable AI Behavioral Analysis Engine.

    Replaces IsolationForest ML with transparent rule-based reasoning.
    Every decision is explainable, auditable, and requires zero training data.

    Design principle:
        "An AI that can explain itself is more trustworthy than
         one that gives a correct answer no one understands."
    """

    def predict(self, ip_data):
        """
        Analyze IP behavioral data and produce an anomaly verdict.

        Parameters:
            ip_data (dict): {request_count, failed_attempts, unique_paths,
                             error_rate, avg_payload_size}

        Returns:
            {
              "anomaly":     bool   — True if behavior is anomalous
              "score":       float  — 0.0 (normal) to 1.0 (highly anomalous)
              "signals":     dict   — individual signal scores
              "explanation": str    — plain-English reasoning
            }
        """
        # ── Step 1: Score each behavioral signal independently ──────────
        # AI Logic: Isolate each dimension so we can explain each separately
        signal_scores = _build_signal_scores(ip_data)

        # ── Step 2: Compute weighted composite score ────────────────────
        # AI Logic: Not all signals are equally important.
        # Failed auth (weight 0.35) matters more than payload size (0.10).
        composite = sum(
            signal_scores[signal] * SIGNAL_WEIGHTS[signal]
            for signal in SIGNAL_WEIGHTS
        )
        composite = round(min(composite, 1.0), 4)

        # ── Step 3: Apply combination bonus ─────────────────────────────
        # AI Decision: If multiple HIGH signals appear together, that
        # dramatically increases confidence this is a real attack.
        # A brute-forcer ALSO scanning directories is far more dangerous
        # than someone who just had a lot of failed logins.
        active_signals = sum(1 for s in signal_scores.values() if s >= 0.5)
        if active_signals >= 3:
            # Three or more high signals = very likely coordinated attack
            composite = min(1.0, composite * 1.3)
        elif active_signals == 2:
            # Two high signals = elevated concern
            composite = min(1.0, composite * 1.15)

        composite = round(composite, 4)

        # ── Step 4: Anomaly verdict ──────────────────────────────────────
        # AI Decision: A composite score above 0.35 triggers an anomaly flag.
        # This threshold was chosen to balance false positives vs. real threats.
        is_anomaly = composite >= 0.35

        # ── Step 5: Generate explanation ─────────────────────────────────
        explanation = _generate_explanation(signal_scores, composite)

        return {
            "anomaly":     is_anomaly,
            "score":       composite,
            "signals":     signal_scores,
            "explanation": explanation,
        }


# ─── Singleton (same interface as the old ML detector) ──────────────────────
# The rest of the codebase calls: anomaly_detector.predict(ip_stats)
# This drop-in replacement requires ZERO changes to callers.
detector = BehavioralAnalyzer()