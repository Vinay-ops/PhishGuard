"""TLS certificate inspection for a public HTTPS endpoint."""

import socket
import ssl
from urllib.parse import urlparse

from services.ssrf_protector import SSRFViolation, validate_public_target


def analyze_tls(url: str, timeout: float = 4.0) -> dict:
    """Return certificate metadata and a 0-100 TLS security score."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return {
            "available": False,
            "score": 0,
            "error": "TLS analysis is only available for HTTPS URLs.",
            "certificate": None,
        }

    try:
        hostname = validate_public_target(url)
        port = parsed.port or 443
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as connection:
            with context.wrap_socket(connection, server_hostname=hostname) as tls_socket:
                certificate = tls_socket.getpeercert()
                if not certificate:
                    raise ssl.SSLError("The server did not provide a certificate.")
                score = _score_certificate(certificate, tls_socket.version())
                return {
                    "available": True,
                    "score": score,
                    "version": tls_socket.version(),
                    "certificate": {
                        "issuer": _name(certificate.get("issuer")),
                        "subject": _name(certificate.get("subject")),
                        "not_before": certificate.get("notBefore"),
                        "not_after": certificate.get("notAfter"),
                    },
                    "error": None,
                }
    # Expected network/DNS/certificate failures are handled explicitly and
    # surface as an unavailable check (never as phishing evidence or a crash).
    except (
        SSRFViolation,
        OSError,          # includes TimeoutError, gaierror, ConnectionRefused
        ssl.SSLError,     # includes certificate verification failures
        ValueError,
        UnicodeError,     # non-ASCII hostnames
    ) as exc:
        return {
            "available": False,
            "score": 0,
            "error": str(exc) or "TLS handshake failed.",
            "certificate": None,
        }


def _name(value) -> str:
    if not value:
        return "Unavailable"
    return ", ".join(f"{key}={item}" for part in value for key, item in part)


def _score_certificate(certificate: dict, version: str) -> int:
    score = 70
    if version in {"TLSv1.3", "TLSv1.2"}:
        score += 20
    if certificate.get("notAfter"):
        score += 10
    return min(100, score)