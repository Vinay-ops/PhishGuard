"""
Risk Engine
===========
Combines ML prediction, URL rules, TLS, and HTTP header checks into a
final risk score, classification, and confidence value.

Architecture:
    URL → Feature Extraction → Security Rules + ML Prediction → Risk Engine → Response

Scoring strategy (deterministic):
    ML component:       45%
    URL rules component: 25%
    TLS component:      15% (risk is inverse of security score)
    Headers component:  15% (risk is inverse of security score)

    Classification thresholds:
        0-29  → SAFE
        30-69 → SUSPICIOUS
        70-100 → PHISHING

The same URL always produces the same result.
"""

from typing import List

from services.feature_extractor import extract_url_features
from services.security_rules import analyze_security_rules
from services.ml_predictor import predict_url
from services.header_analyzer import analyze_headers
from services.tls_analyzer import analyze_tls
from services.ssrf_protector import validate_public_target


# Classification thresholds.
_THRESHOLD_PHISHING = 70
_THRESHOLD_SUSPICIOUS = 30


def calculate_risk(
    features: dict,
    indicators: List[dict],
    ml_result: dict,
    tls_analysis: dict,
    header_analysis: dict,
) -> dict:
    """
    Calculate risk score, classification, confidence, and summary.

    Combines ML phishing probability with rule-based risk score using
    a weighted formula.

    Parameters:
        features: dict returned by extract_url_features()
        indicators: list of rule dicts returned by analyze_security_rules()
        ml_result: dict returned by predict_url()

    Returns:
        {
            "classification": "SAFE" | "SUSPICIOUS" | "PHISHING",
            "risk_score": int,          # 0-100
            "confidence": int,          # 0-100
            "summary": str,
            "detected_indicators": [list of triggered rules],
            "ml_analysis": dict,        # ML prediction details
        }
    """
    # Compute individual components.
    rule_risk = _compute_rule_risk(indicators)
    ml_available = ml_result.get("available", False)
    ml_phishing_prob = ml_result.get("phishing_probability") or 0.0

    risk_breakdown = _build_risk_breakdown(
        rule_risk, ml_phishing_prob, ml_available, tls_analysis, header_analysis
    )
    risk_score = int(round(sum(item["weighted_contribution"] for item in risk_breakdown.values())))

    # Classify based on combined risk score.
    classification = _classify(risk_score)

    # Compute confidence.
    confidence = _compute_confidence(indicators, ml_result)

    # Collect detected indicators.
    detected = [ind for ind in indicators if ind["detected"]]

    # Build summary.
    summary = _build_summary(
        classification, detected, ml_result, risk_breakdown, tls_analysis, header_analysis
    )

    return {
        "classification": classification,
        "risk_score": risk_score,
        "confidence": confidence,
        "summary": summary,
        "detected_indicators": detected,
        "rules": indicators,  # All rules (both detected and not)
        "ml_analysis": ml_result,
        "risk_breakdown": risk_breakdown,
    }


def analyze_url(url: str) -> dict:
    """
    Full analysis pipeline for a URL string.

    1. Extract URL features
    2. Run security rule analysis
    3. Run ML prediction
    4. Inspect TLS and HTTP security headers with bounded network requests
    5. Combine results in risk engine
    6. Return complete analysis
    """
    validate_public_target(url)

    # Step 1: Feature extraction.
    features = extract_url_features(url)

    # Step 2: Security rule analysis.
    indicators = analyze_security_rules(features)

    # Step 3: ML prediction.
    ml_result = predict_url(url)

    # Step 4: Network security analysis. Each analyzer handles its own
    # timeout and returns an unavailable result instead of aborting analysis.
    tls_analysis = analyze_tls(url)
    header_analysis = analyze_headers(url)

    # Step 5: Risk calculation.
    risk = calculate_risk(
        features, indicators, ml_result, tls_analysis, header_analysis
    )

    # Build the API response message.
    detected_count = len(risk["detected_indicators"])
    ml_prediction = ml_result.get("prediction")
    message = _build_message(risk["classification"], detected_count, ml_prediction)

    return {
        "url": url,
        "classification": risk["classification"],
        "risk_score": risk["risk_score"],
        "confidence": risk["confidence"],
        "message": message,
        "detected_indicators": risk["detected_indicators"],
        "summary": risk["summary"],
        "features": features,
        "ml_analysis": risk["ml_analysis"],
        # Full list of every evaluated rule (detected=true/false) so the
        # frontend can show "Rules Checked" without duplicating the rule logic.
        "rules": indicators,
        "tls_analysis": tls_analysis,
        "header_analysis": header_analysis,
        "risk_breakdown": risk["risk_breakdown"],
    }


def _compute_rule_risk(indicators: List[dict]) -> int:
    """
    Compute a deterministic risk score (0-100) from triggered indicators.

    Scoring weights:
        - "high" severity: +25 points
        - "medium" severity: +12 points
        - "low" severity: +5 points

    Score is capped between 0 and 100.
    """
    score = 0

    for indicator in indicators:
        if not indicator["detected"]:
            continue

        severity = indicator["severity"]
        if severity == "high":
            score += 25
        elif severity == "medium":
            score += 12
        elif severity == "low":
            score += 5

    return min(100, max(0, score))


def _build_risk_breakdown(
    rule_risk: int,
    ml_phishing_prob: float,
    ml_available: bool,
    tls_analysis: dict,
    header_analysis: dict,
) -> dict:
    """Build risk-oriented component scores and their weighted contributions."""
    ml_score = round(ml_phishing_prob * 100) if ml_available else 0
    tls_score = 100 - int(tls_analysis.get("score", 0))
    header_score = 100 - int(header_analysis.get("score", 0))
    return {
        "ml": {"score": ml_score, "weight": 45, "weighted_contribution": ml_score * 0.45, "available": ml_available},
        "url_rules": {"score": rule_risk, "weight": 25, "weighted_contribution": rule_risk * 0.25, "available": True},
        "tls": {"score": tls_score, "weight": 15, "weighted_contribution": tls_score * 0.15, "available": tls_analysis.get("available", False)},
        "headers": {"score": header_score, "weight": 15, "weighted_contribution": header_score * 0.15, "available": header_analysis.get("available", False)},
    }


def _classify(risk_score: int) -> str:
    """Map a numeric risk score to a classification string."""
    if risk_score >= _THRESHOLD_PHISHING:
        return "PHISHING"
    elif risk_score >= _THRESHOLD_SUSPICIOUS:
        return "SUSPICIOUS"
    else:
        return "SAFE"


def _compute_confidence(indicators: List[dict], ml_result: dict) -> int:
    """
    Compute a confidence value (0-100).

    If ML is available, use the model's prediction probability as confidence.
    Otherwise, use a rule-based heuristic.

    The ML probability is already a strong signal (the model has 94.8% accuracy),
    so we use it directly as the confidence percentage.
    """
    if ml_result.get("available"):
        # Use the model's probability as confidence.
        # phishing_probability represents how confident the model is.
        phishing_prob = ml_result.get("phishing_probability", 0)
        # Convert to percentage (0-100).
        return min(99, max(1, int(round(phishing_prob * 100))))

    # Fallback: rule-based confidence.
    base = 70
    bonus = len(indicators) * 3
    return min(95, base + bonus)


def _build_summary(
    classification: str,
    detected: List[dict],
    ml_result: dict,
    risk_breakdown: dict,
    tls_analysis: dict,
    header_analysis: dict,
) -> str:
    """Generate a human-readable analysis summary."""
    flagged_names = [ind["rule"] for ind in detected]
    ml_available = ml_result.get("available", False)
    ml_prediction = ml_result.get("prediction")
    ml_phishing_prob = ml_result.get("phishing_probability")

    issues = ", ".join(flagged_names[:3]) if flagged_names else "none"
    ml_note = (
        f"ML estimates {(ml_phishing_prob or 0) * 100:.1f}% phishing probability"
        if ml_available else "ML analysis was unavailable"
    )
    tls_note = "TLS was checked" if tls_analysis.get("available") else "TLS was unavailable"
    header_note = "HTTP headers were checked" if header_analysis.get("available") else "HTTP headers were unavailable"
    return (
        f"Overall classification: {classification}. URL rules flagged {issues}; "
        f"{ml_note}; {tls_note}; {header_note}. "
        "The combined score weighs ML 45%, URL rules 25%, TLS 15%, and "
        "HTTP headers 15%. A model prediction is an interpretation, not proof; "
        "verify the site independently before sharing sensitive information."
    )


def _build_message(
    classification: str,
    flagged_count: int,
    ml_prediction: str = None,
) -> str:
    """Build the short API response message."""
    ml_suffix = ""
    if ml_prediction:
        ml_suffix = f" ML model prediction: {ml_prediction}."

    if classification == "SAFE":
        return f"No major phishing indicators were detected.{ml_suffix}"
    elif classification == "SUSPICIOUS":
        return (
            "Some characteristics commonly associated with phishing "
            f"were detected.{ml_suffix}"
        )
    else:
        return (
            "Multiple characteristics commonly associated with "
            f"phishing were detected.{ml_suffix}"
        )
