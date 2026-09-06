"""
Risk Engine
===========
Combines ML prediction and phishing-specific URL rules into the final
phishing risk. TLS and HTTP headers are reported as separate security
dimensions and never contribute to phishing risk.

Architecture:
    URL → Feature Extraction → Security Rules + ML Prediction → Risk Engine → Response

Scoring strategy (deterministic):
    ML phishing probability: 70%
    URL phishing-rule risk:  30%

    These are heuristic product weights, not statistically validated model
    calibration. Connection security and HTTP hardening do not enter this
    formula because they are not direct phishing evidence.

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

    risk_breakdown = _build_risk_breakdown(rule_risk, ml_phishing_prob, ml_available)
    risk_score = int(round(sum(item["weighted_contribution"] for item in risk_breakdown.values())))

    # Classify based on combined risk score.
    classification = _classify(risk_score)

    # ML phishing probability as a percentage (0–100) for explicit UI display.
    ml_phishing_pct = risk_breakdown["ml"]["score"]

    # Compute legacy confidence field (kept for DB compatibility).
    confidence = _compute_confidence(indicators, ml_result)

    # Collect detected indicators.
    # Keep transport findings in the full rules list, but reserve detected
    # indicators for phishing-relevant URL evidence.
    detected = [
        ind for ind in indicators
        if ind["detected"] and ind.get("rule") != "Missing HTTPS"
    ]

    model_rule_status = _model_rule_status(ml_result, rule_risk)
    # Build summary.
    summary = _build_summary(
        classification, detected, ml_result, tls_analysis, header_analysis, model_rule_status
    )
    top_factors = _build_top_factors(
        detected, ml_result, tls_analysis, header_analysis, risk_breakdown
    )
    connection_security = _build_connection_security(features, tls_analysis)
    http_security = _build_http_security(header_analysis)

    why_flagged = _build_why_flagged(
        classification, detected, ml_result, tls_analysis, header_analysis,
        rule_risk, model_rule_status,
    )

    return {
        "classification": classification,
        "risk_score": risk_score,
        "confidence": confidence,
        "ml_phishing_probability_pct": ml_phishing_pct,
        "model_rule_status": model_rule_status,
        "summary": summary,
        "detected_indicators": detected,
        "rules": indicators,  # All rules (both detected and not)
        "ml_analysis": ml_result,
        "risk_breakdown": risk_breakdown,
        "top_factors": top_factors,
        "why_flagged": why_flagged,
        "rule_analysis": {
            "score": rule_risk,
            "findings": detected,
            "triggered_rules": detected,
            "model_rule_status": model_rule_status,
        },
        "phishing_analysis": {
            "phishing_risk": risk_score,
            "triggered_rules": detected,
            "rule_score": rule_risk,
            "model_rule_status": model_rule_status,
        },
        "connection_security": connection_security,
        "http_security": http_security,
        "final_assessment": {
            "risk_score": risk_score,
            "classification": classification,
            "model_rule_status": model_rule_status,
            "confidence": confidence,
            "explanation": summary,
        },
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
    # SSRF: still block private/local addresses, but do not abort the whole
    # analysis when a hostname is simply unresolvable (NXDOMAIN/DNS timeout).
    # The TLS/HTTP analyzers independently enforce SSRF before connecting and
    # report an unresolvable host as an unavailable check instead.
    validate_public_target(url, require_resolvable=False)

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
        "ml_phishing_probability_pct": risk["ml_phishing_probability_pct"],
        "model_rule_status": risk["model_rule_status"],
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
        "top_factors": risk["top_factors"],
        "why_flagged": risk["why_flagged"],
        "rule_analysis": risk["rule_analysis"],
        "phishing_analysis": risk["phishing_analysis"],
        "connection_security": risk["connection_security"],
        "http_security": risk["http_security"],
        "final_assessment": risk["final_assessment"],
        "model_info": get_model_info_safe(),
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
        if not indicator["detected"] or indicator.get("status") == "PASS":
            continue

        # HTTPS is a transport property, not phishing evidence. It is
        # represented in connection_security and must not inflate URL risk.
        if indicator.get("rule") == "Missing HTTPS":
            continue

        severity = indicator["severity"]
        if severity == "high":
            score += 25
        elif severity == "medium":
            score += 12
        elif severity == "low":
            score += 5

    return min(100, max(0, score))


def _build_risk_breakdown(rule_risk: int, ml_phishing_prob: float, ml_available: bool) -> dict:
    """Build the reproducible phishing-risk-only component breakdown."""
    ml_score = round(ml_phishing_prob * 100) if ml_available else 0
    return {
        "ml": {"score": ml_score, "weight": 70, "weighted_contribution": ml_score * 0.70, "available": ml_available},
        "url_rules": {"score": rule_risk, "weight": 30, "weighted_contribution": rule_risk * 0.30, "available": True},
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

    ML probability is used as confidence only when the verified model returned
    a probability. This is model confidence, not confidence in the final risk
    classification.
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
    tls_analysis: dict,
    header_analysis: dict,
    model_rule_status: str,
) -> str:
    """Generate a human-readable analysis summary."""
    flagged_names = [ind["rule"] for ind in detected]
    ml_available = ml_result.get("available", False)
    ml_phishing_prob = ml_result.get("phishing_probability")

    issues = ", ".join(flagged_names[:3]) if flagged_names else "none"
    ml_note = (
        f"ML model estimated {(ml_phishing_prob or 0) * 100:.1f}% phishing probability"
        if ml_available else "ML analysis was unavailable"
    )
    tls_note = (
        "TLS connection was successfully verified"
        if tls_analysis.get("available")
        else "TLS verification was unavailable"
    )
    header_note = (
        f"HTTP hardening score: {header_analysis.get('score', 0)}/100"
        if header_analysis.get("available")
        else "HTTP header analysis was unavailable"
    )
    disagreement_note = (
        " The ML model and URL rules disagree. This is a model-rule disagreement "
        "and should be independently verified."
        if model_rule_status == "MODEL-RULE DISAGREEMENT" else ""
    )
    rule_detail = (
        f"{len(detected)} phishing-specific URL indicator(s) triggered"
        if detected
        else "No phishing-specific URL indicators were detected"
    )
    return (
        f"{classification}: {ml_note}. {rule_detail}. "
        f"{tls_note}; {header_note}. "
        "Final phishing risk uses heuristic weights: ML 70% + URL rules 30%. "
        f"TLS and HTTP hardening are reported separately.{disagreement_note}"
    )


def _model_rule_status(ml_result: dict, rule_risk: int) -> str:
    """Describe agreement without turning model output into proof."""
    if not ml_result.get("available"):
        return "ML UNAVAILABLE"
    phishing_probability = ml_result.get("phishing_probability") or 0
    if phishing_probability >= 0.7 and rule_risk == 0:
        return "MODEL-RULE DISAGREEMENT"
    if phishing_probability >= 0.5 and rule_risk > 0:
        return "MODEL-RULE AGREEMENT"
    if phishing_probability < 0.5 and rule_risk > 0:
        return "MODEL-RULE DISAGREEMENT"
    return "MODEL-RULE CONSISTENT"


def _build_connection_security(features: dict, tls_analysis: dict) -> dict:
    """Return transport security without implying site legitimacy."""
    return {
        "security_score": int(tls_analysis.get("score", 0)) if tls_analysis.get("available") else 0,
        "https": features.get("uses_https", False),
        "tls_version": tls_analysis.get("version"),
        "certificate_status": "PRESENT" if tls_analysis.get("certificate") else "UNAVAILABLE",
        "available": tls_analysis.get("available", False),
        "certificate": tls_analysis.get("certificate"),
        "error": tls_analysis.get("error"),
    }


def _build_http_security(header_analysis: dict) -> dict:
    """Return header hardening details, explicitly separate from phishing risk."""
    headers = header_analysis.get("headers", {})
    present = [name for name, exists in headers.items() if exists]
    missing = [name for name, exists in headers.items() if not exists]
    return {
        "hardening_score": int(header_analysis.get("score", 0)) if header_analysis.get("available") else 0,
        "present_headers": present,
        "missing_headers": missing,
        "available": header_analysis.get("available", False),
        "status_code": header_analysis.get("status_code"),
        "error": header_analysis.get("error"),
        "phishing_evidence": False,
    }


def _build_top_factors(
    detected: List[dict],
    ml_result: dict,
    tls_analysis: dict,
    header_analysis: dict,
    risk_breakdown: dict,
) -> List[str]:
    """Return explanations backed by actual signals, ordered by contribution."""
    factors = []
    if ml_result.get("available") and (ml_result.get("phishing_probability") or 0) >= 0.5:
        ml_pct = risk_breakdown["ml"]["score"]
        factors.append((
            risk_breakdown["ml"]["weighted_contribution"],
            f"ML model phishing probability: {ml_pct}% (weighted contribution: {risk_breakdown['ml']['weighted_contribution']:.0f}/100)"
        ))
    for indicator in detected:
        if indicator.get("rule") != "Missing HTTPS":
            factors.append((
                risk_breakdown["url_rules"]["weighted_contribution"],
                f"URL rule triggered: {indicator['rule']} (severity: {indicator['severity']})"
            ))
    if tls_analysis.get("available"):
        factors.append((0, "TLS connection successfully verified — does not indicate legitimacy"))
    if header_analysis.get("available") and header_analysis.get("score", 100) < 100:
        missing = header_analysis.get("missing_count", "some")
        factors.append((0, f"HTTP security-hardening headers are missing (score: {header_analysis.get('score', 0)}/100)"))
    factors.sort(key=lambda item: item[0], reverse=True)
    return [factor for _, factor in factors[:5]]


def _build_why_flagged(
    classification: str,
    detected: List[dict],
    ml_result: dict,
    tls_analysis: dict,
    header_analysis: dict,
    rule_risk: int,
    model_rule_status: str,
) -> dict:
    """Build structured evidence categories for the Why Was This Flagged section."""
    ml_available = ml_result.get("available", False)
    ml_phishing_prob = ml_result.get("phishing_probability") or 0
    ml_pct = round(ml_phishing_prob * 100, 1)

    # --- Direct phishing evidence (URL rules) ---
    phishing_evidence = []
    if detected:
        for ind in detected:
            if ind.get("rule") != "Missing HTTPS":
                phishing_evidence.append({
                    "rule": ind["rule"],
                    "severity": ind["severity"],
                    "description": ind["description"],
                    "value": ind.get("value"),
                })

    # --- Model warning ---
    model_warning = None
    if ml_available and ml_phishing_prob >= 0.5:
        model_warning = {
            "label": "Model Prediction",
            "probability": ml_pct,
            "message": (
                f"The ML model assigns a {ml_pct:.1f}% estimated phishing probability. "
                f"This is a model prediction, not independent confirmation of phishing."
            ),
            "model_name": ml_result.get("model_name", "unknown"),
        }

    # --- Security hardening findings ---
    hardening_findings = []
    if tls_analysis.get("available"):
        hardening_findings.append({
            "category": "TLS",
            "status": "VERIFIED",
            "score": tls_analysis.get("score", 0),
            "message": "TLS connection successfully verified. This describes connection security, not website legitimacy.",
        })
    elif tls_analysis.get("error"):
        hardening_findings.append({
            "category": "TLS",
            "status": "UNAVAILABLE",
            "score": 0,
            "message": f"TLS verification failed: {tls_analysis['error']}",
        })
    if header_analysis.get("available"):
        score = header_analysis.get("score", 0)
        missing = [
            name for name, exists in header_analysis.get("headers", {}).items()
            if not exists
        ]
        hardening_findings.append({
            "category": "HTTP",
            "status": "PRESENT" if score == 100 else "PARTIAL",
            "score": score,
            "message": (
                f"HTTP security hardening score: {score}/100."
                + (f" Missing: {', '.join(missing)}." if missing else " All headers present.")
                + " This indicates HTTP hardening level, not phishing evidence."
            ),
            "missing_headers": missing,
        })
    elif header_analysis.get("error"):
        hardening_findings.append({
            "category": "HTTP",
            "status": "UNAVAILABLE",
            "score": 0,
            "message": f"HTTP header analysis failed: {header_analysis['error']}",
        })

    return {
        "phishing_evidence": phishing_evidence,
        "model_warning": model_warning,
        "hardening_findings": hardening_findings,
        "model_rule_status": model_rule_status,
    }


def get_model_info_safe() -> dict:
    """Load model metadata without allowing metadata failure to break analysis."""
    try:
        from services.ml_predictor import get_model_info
        return get_model_info()
    except Exception as exc:
        return {"available": False, "error": str(exc)}


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
