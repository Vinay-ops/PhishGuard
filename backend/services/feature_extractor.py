"""
URL Feature Extractor
=====================
Extracts structural and character-level features from a URL string.

Used by the security rules engine and (later) the ML predictor.

Only analyzes the URL string — NEVER fetches the URL from the network.
"""

import ipaddress
import math
import re
from urllib.parse import urlparse

try:
    import tldextract
except ImportError:
    tldextract = None


# Keywords commonly associated with phishing pages.
SUSPICIOUS_KEYWORDS = [
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "security",
    "account",
    "update",
    "confirm",
    "password",
    "bank",
    "wallet",
    "payment",
    "invoice",
    "unlock",
    "authenticate",
    "credential",
    "signin",
]


def extract_url_features(url: str) -> dict:
    """
    Analyze a URL string and return a structured feature dictionary.

    Returns a dict with numeric, boolean, and string features describing
    the URL's structure and characteristics.

    This function ONLY parses the URL string. It never sends a network
    request, never follows redirects, and never downloads any content.
    """
    url_stripped = url.strip()

    parsed = urlparse(url_stripped)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""
    scheme = parsed.scheme.lower()

    # --- Basic lengths ---
    url_length = len(url_stripped)
    hostname_length = len(hostname)
    path_length = len(path)
    query_length = len(query)
    fragment_length = len(fragment)

    # --- Character-level counts ---
    number_of_dots = url_stripped.count(".")
    number_of_hyphens = url_stripped.count("-")
    number_of_underscores = url_stripped.count("_")
    number_of_digits = sum(c.isdigit() for c in url_stripped)

    # Special characters: anything that is not alphanumeric, a common
    # separator, or whitespace.
    special_chars = re.findall(r"[^a-zA-Z0-9.\-_/ :?=&@#~%]", url_stripped)
    number_of_special_characters = len(special_chars)

    # --- Subdomain count ---
    # Uses tldextract when available for accurate counting.
    # Falls back to a simple heuristic (total dot-separated parts minus 2
    # for the registered domain + TLD).
    if tldextract is not None:
        ext = tldextract.extract(hostname)
        # subdomain is e.g. "www.mail" for "www.mail.example.com"
        subdomain_field = ext.subdomain
        if subdomain_field:
            number_of_subdomains = len(subdomain_field.split("."))
        else:
            number_of_subdomains = 0
    else:
        parts = hostname.split(".")
        number_of_subdomains = max(0, len(parts) - 2) if len(parts) >= 2 else 0

    # --- Boolean features ---
    has_at_symbol = "@" in url_stripped

    has_ip_address = _is_ip_address(hostname)

    uses_https = scheme == "https"

    query_present = bool(query)

    # --- Suspicious keyword count ---
    lowered = url_stripped.lower()
    suspicious_keyword_count = sum(
        1 for kw in SUSPICIOUS_KEYWORDS if kw in lowered
    )

    # --- Shannon entropy ---
    url_entropy = round(calculate_entropy(url_stripped), 4)

    return {
        "url_length": url_length,
        "hostname_length": hostname_length,
        "path_length": path_length,
        "query_length": query_length,
        "fragment_length": fragment_length,
        "number_of_dots": number_of_dots,
        "number_of_hyphens": number_of_hyphens,
        "number_of_underscores": number_of_underscores,
        "number_of_digits": number_of_digits,
        "number_of_special_characters": number_of_special_characters,
        "number_of_subdomains": number_of_subdomains,
        "has_at_symbol": has_at_symbol,
        "has_ip_address": has_ip_address,
        "uses_https": uses_https,
        "suspicious_keyword_count": suspicious_keyword_count,
        "url_entropy": url_entropy,
        "hostname": hostname,
        "path": path,
        "query_present": query_present,
    }


def calculate_entropy(value: str) -> float:
    """
    Calculate the Shannon entropy of a string (bits per character).

    Returns 0.0 for empty strings.
    """
    if not value:
        return 0.0

    freq: dict[str, int] = {}
    for ch in value:
        freq[ch] = freq.get(ch, 0) + 1

    length = len(value)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


def _is_ip_address(hostname: str) -> bool:
    """
    Detect whether a hostname is an IP address (IPv4 or IPv6).

    Uses Python's ipaddress module for reliable detection.
    Returns False for normal domain names like "example.com".
    """
    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False
