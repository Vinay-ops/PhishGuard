"""
Risk Engine
===========
Combines ML prediction and explainable security rules into a final
risk score, classification, and confidence value.

Architecture:
    URL → Feature Extraction → Security Rules + ML Prediction → Risk Engine → Response

Scoring strategy (deterministic):
    ML component:   70% weight  (phishing_probability from ONNX model)
    Rule component: 30% weight  (normalized rule risk score)

    final_risk_score = (ml_phishing_prob * 70) + (rule_risk_normalized * 30)

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


# Classification thresholds.
_THRESHOLD_PHISHING = 70
_THRESHOLD_SUSPICIOUS = 30


def calculate_risk(
    features: dict,
    indicators: List[dict],
    ml_result: dict,
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

    # Combine ML and rule-based scores.
    risk_score = _combine_scores(rule_risk, ml_phishing_prob, ml_available)

    # Classify based on combined risk score.
    classification = _classify(risk_score)

    # Compute confidence.
    confidence = _compute_confidence(indicators, ml_result)

    # Collect detected indicators.
    detected = [ind for ind in indicators if ind["detected"]]

    # Build summary.
    summary = _build_summary(classification, detected, ml_result)

    return {
        "classification": classification,
        "risk_score": risk_score,
        "confidence": confidence,
        "summary": summary,
        "detected_indicators": detected,
        "rules": indicators,  # All rules (both detected and not)
        "ml_analysis": ml_result,
    }


def analyze_url(url: str) -> dict:
    """
    Full analysis pipeline for a URL string.

    1. Extract URL features
    2. Run security rule analysis
    3. Run ML prediction
    4. Combine results in risk engine
    5. Return complete analysis

    NEVER fetches, opens, or sends the URL to any network.
    """
    # Step 1: Feature extraction.
    features = extract_url_features(url)

    # Step 2: Security rule analysis.
    indicators = analyze_security_rules(features)

    # Step 3: ML prediction.
    ml_result = predict_url(url)

    # Step 4: Risk calculation (combines ML + rules).
    risk = calculate_risk(features, indicators, ml_result)

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


def _combine_scores(rule_risk: int, ml_phishing_prob: float, ml_available: bool) -> int:
    """
    Combine ML and rule-based scores into a final risk score.

    Formula:
        final = (ml_phishing_prob * 70) + (rule_risk * 30 / 100)

    If ML is unavailable, fall back to rule-based score only.
    The result is clamped to 0-100 and rounded to an integer.
    """
    if ml_available:
        # ML contributes 70%, rules contribute 30%.
        ml_component = ml_phishing_prob * 70
        rule_component = (rule_risk / 100.0) * 30
        combined = ml_component + rule_component
    else:
        # No ML available — use rule-based score only.
        combined = rule_risk

    return min(100, max(0, int(round(combined))))


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
) -> str:
    """Generate a human-readable analysis summary."""
    flagged_names = [ind["rule"] for ind in detected]
    ml_available = ml_result.get("available", False)
    ml_prediction = ml_result.get("prediction")
    ml_phishing_prob = ml_result.get("phishing_probability")

    if classification == "SAFE":
        ml_note = ""
        if ml_available and ml_prediction == "SAFE":
            ml_note = (
                f" The ML model classifies this URL as safe with "
                f"{(ml_phishing_prob or 0) * 100:.1f}% phishing probability."
            )
        return (
            "No major phishing indicators were detected. The URL "
            "structure, protocol, and characteristics all appear "
            f"normal.{ml_note} Note: a safe classification does not "
            "guarantee the website is completely secure. Always "
            "exercise caution when visiting unfamiliar websites."
        )

    if classification == "SUSPICIOUS":
        issues = (
            ", ".join(flagged_names[:3])
            if flagged_names
            else "several characteristics"
        )
        ml_note = ""
        if ml_available:
            ml_note = (
                f" The ML model detected a "
                f"{(ml_phishing_prob or 0) * 100:.1f}% phishing probability."
            )
        return (
            "Some characteristics commonly associated with phishing "
            f"were detected: {issues}.{ml_note} "
            "It is not definitively malicious, but you should verify "
            "the source before visiting. Do not enter personal "
            "information."
        )

    # PHISHING
    issues = (
        ", ".join(flagged_names[:3])
        if flagged_names
        else "multiple indicators"
    )
    ml_note = ""
    if ml_available:
        ml_note = (
            f" The ML model classifies this URL as phishing with "
            f"{(ml_phishing_prob or 0) * 100:.1f}% confidence."
        )
    return (
        "Multiple characteristics commonly associated with phishing "
        f"were detected: {issues}.{ml_note} "
        "Do not enter personal information or credentials on this URL."
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
