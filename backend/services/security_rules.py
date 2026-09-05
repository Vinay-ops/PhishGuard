"""
Security Rules Engine
=====================
Evaluates explainable security rules against extracted URL features.

Each rule returns a structured result describing what was checked,
what was found, and how severe the finding is.

Only analyzes URL strings — NEVER fetches URLs from the network.
"""

from typing import List

from services.feature_extractor import extract_url_features


# Thresholds for flagging URL characteristics.
_MAX_URL_LENGTH = 200
_MAX_SUBDOMAINS = 3
_MAX_SPECIAL_CHARS = 10


def analyze_security_rules(features: dict) -> List[dict]:
    """
    Evaluate all security rules against the extracted URL features.

    Parameters:
        features: dict returned by extract_url_features()

    Returns:
        A list of rule result dicts. Each dict contains:
            - rule: name of the rule
            - description: beginner-friendly explanation
            - severity: "low" | "medium" | "high"
                        - value: the specific value or detail that triggered the rule
              (varies by rule — may be bool, string, or number)
                        - status: PASS, WARNING, or DETECTED
    """
    indicators: List[dict] = []

    # Rule 1: IP address instead of domain
    indicators.append(_make_rule(
        name="IP Address Host",
        description=(
            "The URL uses an IP address instead of a conventional domain "
            "name. Attackers often use IP addresses to hide the true "
            "identity of a server."
        ),
        severity="high",
        detected=features["has_ip_address"],
        value=features["hostname"],
    ))

    # Rule 2: @ symbol present
    indicators.append(_make_rule(
        name="At Symbol (@)",
        description=(
            "The URL contains an '@' symbol. Browsers treat everything "
            "before '@' as a username and ignore it, which can be used "
            "to disguise the real destination."
        ),
        severity="high",
        detected=features["has_at_symbol"],
        value="@" if features["has_at_symbol"] else None,
    ))

    # Rule 3: Excessive URL length
    url_len = features["url_length"]
    indicators.append(_make_rule(
        name="Excessive URL Length",
        description=(
            f"The URL is {url_len} characters long, which exceeds "
            f"the recommended maximum of {_MAX_URL_LENGTH}. "
            "Long URLs may hide the actual destination from users."
        ),
        severity="medium",
        detected=url_len > _MAX_URL_LENGTH,
        value=f"{url_len} characters",
    ))

    # Rule 4: Excessive subdomains
    sub_count = features["number_of_subdomains"]
    indicators.append(_make_rule(
        name="Excessive Subdomains",
        description=(
            f"The URL has {sub_count} subdomain(s). Deeply nested "
            "subdomains can make a phishing site appear legitimate."
        ),
        severity="medium",
        detected=sub_count > _MAX_SUBDOMAINS,
        value=f"{sub_count} subdomains",
    ))

    # Rule 5: Suspicious keywords
    kw_count = features["suspicious_keyword_count"]
    if kw_count >= 3:
        kw_severity = "high"
    elif kw_count >= 1:
        kw_severity = "medium"
    else:
        kw_severity = "low"

    indicators.append(_make_rule(
        name="Suspicious Keywords",
        description=(
            "The URL contains keywords commonly associated with "
            "phishing pages (e.g. 'login', 'verify', 'account')."
        ),
        severity=kw_severity,
        detected=kw_count > 0,
        value=f"{kw_count} keyword(s) found" if kw_count > 0 else None,
    ))

    # Rule 6: Excessive special characters
    sp_count = features["number_of_special_characters"]
    indicators.append(_make_rule(
        name="Excessive Special Characters",
        description=(
            f"The URL contains {sp_count} special characters. "
            "An unusually high count may indicate obfuscation."
        ),
        severity="medium",
        detected=sp_count > _MAX_SPECIAL_CHARS,
        value=f"{sp_count} special characters",
    ))

    # Rule 7: Suspicious hostname structure
    hostname = features.get("hostname", "")
    suspicious_chars = [ch for ch in hostname if ch in ["@", "~", "!"]]
    has_suspicious_hostname = bool(suspicious_chars)
    indicators.append(_make_rule(
        name="Suspicious Hostname",
        description=(
            "The hostname contains unusual characters that may "
            "indicate an attempt to impersonate a legitimate domain."
        ),
        severity="high",
        detected=has_suspicious_hostname,
        value=hostname if has_suspicious_hostname else None,
    ))

    # Rule 8: HTTP instead of HTTPS
    indicators.append(_make_rule(
        name="Missing HTTPS",
        description=(
            "The URL uses HTTP instead of HTTPS. Data transmitted "
            "over HTTP is not encrypted and can be intercepted."
        ),
        severity="low",
        detected=not features["uses_https"],
        value="http" if not features["uses_https"] else None,
    ))

    return indicators


def _make_rule(
    name: str,
    description: str,
    severity: str,
    detected: bool,
    value=None,
) -> dict:
    """Build a single rule result dict."""
    return {
        "rule": name,
        "description": description,
        "message": description,
        "severity": severity,
        "detected": detected,
        "value": value,
        "evidence": value,
        "status": "DETECTED" if detected and name != "Missing HTTPS" else (
            "WARNING" if detected else "PASS"
        ),
    }
