"""HTTP security header inspection for a public URL."""

from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, build_opener, HTTPRedirectHandler, urlopen

from services.ssrf_protector import SSRFViolation, validate_public_target


SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
)


class LimitedRedirectHandler(HTTPRedirectHandler):
    max_redirections = 3

    def redirect_request(self, request, fp, code, msg, headers, newurl):
        # Never follow a redirect away from http(s): urllib would otherwise
        # attempt ftp:// or other schemes against the validated host.
        if urlparse(newurl).scheme.lower() not in ("http", "https"):
            raise SSRFViolation("Redirects to non-HTTP(S) protocols are blocked.")
        validate_public_target(newurl)
        return super().redirect_request(request, fp, code, msg, headers, newurl)


def analyze_headers(url: str, timeout: float = 4.0) -> dict:
    """Fetch headers and return presence details plus a 0-100 score."""
    try:
        # Only http(s) targets are ever analyzed; anything else returns a
        # controlled unavailable result instead of being handed to urllib.
        if urlparse(url).scheme.lower() not in ("http", "https"):
            raise SSRFViolation("Only HTTP(S) URLs are analyzed.")
        validate_public_target(url)
        request = Request(url, headers={"User-Agent": "PhishGuard/1.0"}, method="GET")
        opener = build_opener(LimitedRedirectHandler)
        with opener.open(request, timeout=timeout) as response:
            headers = {name.lower(): value for name, value in response.headers.items()}
            present = {
                header: bool(headers.get(header.lower())) for header in SECURITY_HEADERS
            }
            return {
                "available": True,
                "score": round(sum(present.values()) / len(SECURITY_HEADERS) * 100),
                "headers": present,
                "error": None,
                "status_code": response.status,
            }
    except (SSRFViolation, OSError, HTTPError, URLError, ValueError) as exc:
        return {
            "available": False,
            "score": 0,
            "headers": {header: False for header in SECURITY_HEADERS},
            "error": str(exc) or "HTTP header request failed.",
            "status_code": None,
        }