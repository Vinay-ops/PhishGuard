"""
Security hardening regression tests.

Run from the backend/ directory:
    python -m unittest discover -s tests -v

Coverage:
    1. SSRF block list: localhost, private IPv4/IPv6, link-local, metadata,
       CGNAT/shared address space, benchmarking ranges, IPv4-mapped IPv6,
       userinfo tricks, non-http(s) schemes
    2. SSRF allow list: ordinary public domains still resolve
    3. Analyzers return a controlled unavailable result (never crash) for
       blocked targets and non-http(s) schemes
    4. URL validation through the real /api/v1/analyze route: empty,
       over-long, wrong scheme, SSRF target, malformed port -> controlled
       status codes, never 500
    5. Redirect handler refuses non-http(s) redirect targets
"""

import os
import sys
import unittest
import unittest.mock

# Ensure the backend root is importable regardless of the CWD.
_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from services.header_analyzer import analyze_headers, LimitedRedirectHandler  # noqa: E402
from services.ssrf_protector import SSRFViolation, validate_public_target  # noqa: E402
from services.tls_analyzer import analyze_tls  # noqa: E402


# ---------------------------------------------------------------------------
# SSRF target matrix
# ---------------------------------------------------------------------------

# Every one of these must be rejected by validate_public_target.
SSRF_BLOCKED = [
    # Loopback / local
    "https://localhost/",
    "http://127.0.0.1/",
    "http://127.0.0.1:8080/admin",
    "http://0.0.0.0/",
    # RFC1918 private IPv4
    "http://10.0.0.1/",
    "http://192.168.1.1/",
    "http://172.16.0.1/",
    "http://172.31.255.254/",
    # Link-local / cloud metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.170.2/",
    # IPv6 loopback / private / link-local
    "http://[::1]/",
    "http://[fe80::1]/",
    "http://[fc00::1]/",
    "http://[fd12:3456:789a::1]/",
    # IPv4-mapped IPv6 loopback
    "http://[::ffff:127.0.0.1]/",
    # CGNAT / shared address space (gap on Python < 3.13)
    "http://100.64.0.1/",
    "http://100.127.255.254/",
    # Benchmarking range
    "http://198.18.0.1/",
    "http://198.19.255.254/",
    # Documentation ranges
    "http://192.0.2.1/",
    "http://198.51.100.1/",
    "http://203.0.113.5/",
    # Hostname tricks
    "http://localhost./",
    "http://127.0.0.1.nip.io/",
    # Userinfo tricks must still resolve the real host
    "http://example.com@127.0.0.1/",
    "http://user:pass@10.0.0.5/",
    # Non-http(s) schemes (no hostname or non-HTTP)
    "file:///etc/passwd",
    "file://127.0.0.1/etc/passwd",
    "data:text/plain,hello",
    "gopher://127.0.0.1:70/x",
]

# Ordinary public domains must still pass. (Depends on outbound DNS.)
SSRF_ALLOWED = [
    "https://example.com/",
    "https://www.google.com/",
    "https://github.com/",
]


class TestSSRFProtection(unittest.TestCase):
    def test_blocked_targets_raise(self):
        for url in SSRF_BLOCKED:
            with self.subTest(url=url):
                with self.assertRaises(SSRFViolation):
                    validate_public_target(url)

    def test_allowed_public_targets_pass(self):
        for url in SSRF_ALLOWED:
            with self.subTest(url=url):
                hostname = validate_public_target(url)
                self.assertTrue(hostname)

    def test_cgnat_range_is_explicitly_denied(self):
        """100.64.0.0/10 is not private on Python < 3.13; the explicit
        deny list must catch it on every runtime."""
        with self.assertRaises(SSRFViolation):
            validate_public_target("http://100.64.0.1/")


class TestAnalyzersNeverCrash(unittest.TestCase):
    def test_tls_analyzer_blocks_private_target(self):
        result = analyze_tls("https://127.0.0.1/admin")
        self.assertFalse(result["available"])
        self.assertEqual(result["score"], 0)
        self.assertIsNone(result["certificate"])

    def test_header_analyzer_blocks_private_target(self):
        result = analyze_headers("http://127.0.0.1/admin")
        self.assertFalse(result["available"])
        self.assertEqual(result["score"], 0)

    def test_header_analyzer_rejects_non_http_scheme(self):
        result = analyze_headers("ftp://example.com/file")
        self.assertFalse(result["available"])
        self.assertEqual(result["score"], 0)
        self.assertIn("HTTP", result["error"])

    def test_tls_analyzer_rejects_non_https_scheme(self):
        result = analyze_tls("http://example.com/")
        self.assertFalse(result["available"])
        self.assertEqual(result["error"], "TLS analysis is only available for HTTPS URLs.")

    def test_redirect_handler_refuses_non_http_redirect(self):
        handler = LimitedRedirectHandler()
        for target in ("ftp://example.com/file", "file:///etc/passwd", "data:text/plain,x"):
            with self.subTest(target=target):
                with self.assertRaises(SSRFViolation):
                    handler.redirect_request(
                        request=None, fp=None, code=302, msg="Found",
                        headers={}, newurl=target,
                    )


# ---------------------------------------------------------------------------
# API route validation (real FastAPI app via TestClient)
# ---------------------------------------------------------------------------

class TestApiValidation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient
        from app.main import app
        cls.client = TestClient(app)

    def test_empty_url_returns_400(self):
        response = self.client.post("/api/v1/analyze", json={"url": "   "})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["detail"], "URL must not be empty.")

    def test_overlong_url_returns_422(self):
        response = self.client.post("/api/v1/analyze", json={"url": "https://e.com/" + "a" * 2100})
        self.assertEqual(response.status_code, 422)

    def test_non_http_scheme_returns_400(self):
        response = self.client.post("/api/v1/analyze", json={"url": "ftp://example.com/file"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("http:// or https://", response.json()["detail"])

    def test_private_target_returns_400(self):
        response = self.client.post("/api/v1/analyze", json={"url": "http://169.254.169.254/meta"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["detail"], "Requests to private or local network addresses are blocked.")

    def test_cgnat_target_returns_400(self):
        response = self.client.post("/api/v1/analyze", json={"url": "http://100.64.0.1/"})
        self.assertEqual(response.status_code, 400)

    def test_malformed_port_returns_controlled_response(self):
        # Invalid port: TLS/header analyzers raise ValueError before any
        # connection; the route must still return a 200 analysis, not 500.
        response = self.client.post("/api/v1/analyze", json={"url": "https://example.com:99999/"})
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertFalse(body["tls_analysis"]["available"])
        self.assertFalse(body["header_analysis"]["available"])
        self.assertIn("classification", body)
        self.assertIn("risk_score", body)

    def test_error_responses_do_not_leak_stack_traces(self):
        response = self.client.post("/api/v1/analyze", json={"url": "ftp://example.com/file"})
        self.assertNotIn("Traceback", response.text)
        self.assertNotIn("File \"", response.text)
        self.assertNotIn("services\\", response.text)

    def test_cors_allows_project_vercel_origins(self):
        # Preflight from one of the project's own Vercel deployment URLs must
        # be allowed so the SPA works from any deployment/preview domain.
        origin = "https://phish-guard-4tdrj01qe-vinay-ops-projects.vercel.app"
        response = self.client.options(
            "/api/v1/analyze",
            headers={
                "Origin": origin,
                "Access-Control-Request-Method": "POST",
            },
        )
        self.assertIn(response.status_code, (200, 204))
        self.assertEqual(response.headers.get("access-control-allow-origin"), origin)

    def test_cors_allows_alias_and_localhost(self):
        for origin in ("https://phish-guard-ruby-three.vercel.app", "http://localhost:5173"):
            with self.subTest(origin=origin):
                response = self.client.options(
                    "/api/v1/analyze",
                    headers={"Origin": origin, "Access-Control-Request-Method": "POST"},
                )
                self.assertEqual(
                    response.headers.get("access-control-allow-origin"), origin
                )

    def test_cors_blocks_unrelated_origins(self):
        response = self.client.options(
            "/api/v1/analyze",
            headers={"Origin": "https://evil.example.com", "Access-Control-Request-Method": "POST"},
        )
        self.assertIsNone(response.headers.get("access-control-allow-origin"))


class TestUnreachableHostHandling(unittest.TestCase):
    """Unreachable/unresolvable public hostnames must not produce a 500.

    They must return a controlled analysis with the network checks marked
    unavailable and phishing risk driven only by ML + URL rules.
    """

    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient
        from app.main import app
        cls.client = TestClient(app)

    def test_reachable_url_still_analyzes(self):
        response = self.client.post("/api/v1/analyze", json={"url": "https://www.google.com/"})
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertIn("classification", body)
        self.assertIn("risk_score", body)

    def test_original_500_url_now_controlled(self):
        url = "https://paypal-login-verify.example.com/account/login"
        response = self.client.post("/api/v1/analyze", json={"url": url})
        self.assertEqual(response.status_code, 200)
        body = response.json()
        # Network checks unavailable, phishing risk untouched by them.
        self.assertFalse(body["connection_security"]["available"])
        self.assertFalse(body["http_security"]["available"])
        self.assertEqual(body["connection_security"]["security_score"], 0)
        self.assertEqual(body["http_security"]["hardening_score"], 0)
        # ML still analyzed the URL string (independence from reachability).
        ml = body["ml_analysis"]
        self.assertTrue(ml["available"])
        self.assertIsNotNone(ml["phishing_probability"])
        # Risk comes from ML + URL rules only.
        breakdown = body["risk_breakdown"]
        self.assertIn("ml", breakdown)
        self.assertIn("url_rules", breakdown)
        self.assertNotIn("tls", breakdown)
        self.assertNotIn("http", breakdown)

    def test_non_resolving_hostname_returns_analysis(self):
        url = "https://this-domain-definitely-does-not-exist-123456789.example/"
        response = self.client.post("/api/v1/analyze", json={"url": url})
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertFalse(body["connection_security"]["available"])
        self.assertFalse(body["http_security"]["available"])
        self.assertIsNotNone(body["ml_analysis"].get("phishing_probability"))

    def test_loopback_still_blocked(self):
        response = self.client.post("/api/v1/analyze", json={"url": "http://127.0.0.1/"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json()["detail"],
            "Requests to private or local network addresses are blocked.",
        )

    def test_metadata_still_blocked(self):
        response = self.client.post(
            "/api/v1/analyze", json={"url": "http://169.254.169.254/latest/meta-data/"}
        )
        self.assertEqual(response.status_code, 400)

    def test_cgnat_still_blocked(self):
        response = self.client.post("/api/v1/analyze", json={"url": "http://100.64.0.1/"})
        self.assertEqual(response.status_code, 400)

    def test_invalid_scheme_still_blocked(self):
        response = self.client.post("/api/v1/analyze", json={"url": "ftp://example.com/file"})
        self.assertEqual(response.status_code, 400)


class TestDnsFailureMechanism(unittest.TestCase):
    """getaddrinfo failures other than gaierror (e.g. DNS timeout on
    serverless) must be handled, not escape as an HTTP 500."""

    def test_getaddrinfo_timeout_is_handled(self):
        import socket
        import services.risk_engine as risk_engine
        with unittest.mock.patch(
            "socket.getaddrinfo",
            side_effect=TimeoutError("simulated DNS timeout"),
        ):
            result = risk_engine.analyze_url("https://example.com/")
        self.assertIn("risk_score", result)
        self.assertFalse(result["connection_security"]["available"])
        self.assertFalse(result["http_security"]["available"])

    def test_getaddrinfo_unicode_is_handled(self):
        import socket
        import services.risk_engine as risk_engine
        with unittest.mock.patch(
            "socket.getaddrinfo",
            side_effect=UnicodeError("simulated non-ascii host"),
        ):
            result = risk_engine.analyze_url("https://example.com/")
        self.assertIn("risk_score", result)
        self.assertFalse(result["connection_security"]["available"])

    def test_ssrf_blocked_when_resolution_is_internal(self):
        from services.ssrf_protector import validate_public_target, SSRFViolation
        import socket
        # Hostname that resolves to a private address must still be blocked.
        with unittest.mock.patch(
            "socket.getaddrinfo", return_value=[(socket.AF_INET, None, 6, "", ("127.0.0.1", 0))]
        ):
            with self.assertRaises(SSRFViolation):
                validate_public_target("https://evil.example.com/")

    def test_ssrf_blocked_without_resolving_private(self):
        from services.ssrf_protector import validate_public_target, SSRFViolation
        # A literal private IP never needs DNS and is always blocked.
        for url in ("http://10.0.0.1/", "http://192.168.1.5/", "http://[::1]/", "http://100.64.0.1/"):
            with self.subTest(url=url):
                with self.assertRaises(SSRFViolation):
                    validate_public_target(url)


if __name__ == "__main__":
    unittest.main()