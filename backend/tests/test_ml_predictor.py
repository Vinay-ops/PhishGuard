"""
Regression tests for the SivakumarP ML predictor integration.

Run from the backend/ directory:
    python -m unittest tests.test_ml_predictor -v
or:
    python -m unittest discover -s tests -v

Coverage:
    1. Artifact loading
    2. Feature vector shape = 187
    3. Class mapping / predict_proba output
    4. Regression predictions on the verified URLs
    5. Malformed URL handling
    6. IP-host handling
    7. HTTPS detection
    8. tldextract offline behavior
    9. Predictor caching
    10. Risk-score recomputation (70/30 heuristic, TLS/HTTP excluded)
"""

import os
import sys
import unittest

# Ensure the backend root is importable regardless of the CWD.
_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from services import ml_predictor  # noqa: E402
from services.ml_predictor import (  # noqa: E402
    build_sivakumar_feature_vector,
    extract_sivakumar_features,
    predict_url,
    get_model_info,
)

# ---------------------------------------------------------------------------
# Verified regression values (compatibility audit + live Vercel test).
# SivakumarP distinguishes paypal.com (no www) from www.paypal.com because
# the full-URL TF-IDF input differs.
# ---------------------------------------------------------------------------
REGRESSION = {
    "https://learnova-ai-8.vercel.app/": 0.540000,
    "https://www.google.com/": 0.130000,
    "https://example.com/": 0.300191,
    "https://github.com/": 0.320378,
    "https://www.paypal.com/": 0.140165,
    "https://paypal.com/": 0.450026,
}

TOL = 0.001  # tiny tolerance for floating-point variation


class TestArtifactLoading(unittest.TestCase):
    def test_artifacts_load(self):
        info = get_model_info()
        self.assertTrue(info["available"], msg=f"model not available: {info}")
        self.assertEqual(info["model_name"], "SivakumarP/PhishingURLDetection")
        self.assertEqual(info["n_features"], 187)
        self.assertEqual(info["classes"], [0, 1])

    def test_all_five_artifacts_present(self):
        from services.ml_predictor import _SIVAKUMAR_FILES, SIVAKUMAR_DIR
        for name in _SIVAKUMAR_FILES:
            self.assertTrue(
                os.path.isfile(os.path.join(SIVAKUMAR_DIR, name)),
                msg=f"missing artifact {name}",
            )


class TestFeaturePipeline(unittest.TestCase):
    def test_feature_vector_shape_187(self):
        X, feats = build_sivakumar_feature_vector("https://www.google.com/")
        self.assertEqual(X.shape, (1, 187))
        self.assertEqual(feats["registered_domain"], "google.com")
        self.assertEqual(feats["public_suffix"], "com")
        self.assertEqual(feats["is_https"], 1)

    def test_https_detection(self):
        self.assertEqual(extract_sivakumar_features("https://example.com/")["is_https"], 1)
        self.assertEqual(extract_sivakumar_features("http://example.com/")["is_https"], 0)

    def test_registered_domain_and_suffix(self):
        f = extract_sivakumar_features("https://sites.google.com/site/x")
        self.assertEqual(f["registered_domain"], "google.com")
        self.assertEqual(f["public_suffix"], "com")
        f2 = extract_sivakumar_features("https://www.google.co.uk/x")
        self.assertEqual(f2["registered_domain"], "google.co.uk")
        self.assertEqual(f2["public_suffix"], "co.uk")
        f3 = extract_sivakumar_features("https://learnova-ai-8.vercel.app/")
        self.assertEqual(f3["registered_domain"], "vercel.app")
        self.assertEqual(f3["public_suffix"], "app")
        self.assertEqual(f3["digit_cnt"], 1)

    def test_ip_host_handling(self):
        f = extract_sivakumar_features("http://192.168.1.100/login.php")
        self.assertEqual(f["registered_domain"], "192.168.1.100")
        self.assertEqual(f["public_suffix"], "")
        self.assertEqual(f["digit_cnt"], 10)
        # no crash, valid output
        r = predict_url("http://192.168.1.100/login.php")
        self.assertTrue(r["available"])
        self.assertTrue(0.0 <= r["phishing_probability"] <= 1.0)


class TestPredictions(unittest.TestCase):
    def test_class_mapping(self):
        """phishing_probability is predict_proba class 1; safe is class 0."""
        for url in REGRESSION:
            r = predict_url(url)
            self.assertTrue(r["available"])
            self.assertAlmostEqual(
                r["phishing_probability"] + r["safe_probability"], 1.0, places=4
            )
        # google.com is clearly benign -> low phishing probability
        r = predict_url("https://www.google.com/")
        self.assertEqual(r["prediction"], "SAFE")
        self.assertLess(r["phishing_probability"], 0.5)
        self.assertGreater(r["safe_probability"], r["phishing_probability"])

    def test_regression_urls(self):
        for url, expected in REGRESSION.items():
            with self.subTest(url=url):
                r = predict_url(url)
                self.assertTrue(r["available"], msg=str(r))
                self.assertAlmostEqual(
                    r["phishing_probability"], expected, delta=TOL,
                    msg=f"phishing probability for {url} drifted",
                )

    def test_output_shape_and_types(self):
        r = predict_url("https://github.com/")
        for key in ("available", "prediction", "predicted_label",
                    "phishing_probability", "safe_probability",
                    "model_status"):
            self.assertIn(key, r)
        self.assertIsInstance(r["phishing_probability"], float)
        self.assertEqual(r["model_name"], "SivakumarP/PhishingURLDetection")
        self.assertEqual(r["model_status"], "AVAILABLE")


class TestRobustness(unittest.TestCase):
    def test_malformed_urls_do_not_crash(self):
        bad_urls = [
            "",
            "   ",
            "not a url",
            "http://",
            "https://example.com:99999/path",
            "https://exa mple.com/space",
            "ftp://example.com",
            "https://" + "a" * 500 + ".com/",
        ]
        for url in bad_urls:
            with self.subTest(url=url[:40]):
                r = predict_url(url)
                self.assertTrue(r["available"] or r.get("error"))
                if r["available"]:
                    self.assertTrue(0.0 <= r["phishing_probability"] <= 1.0)

    def test_tldextract_offline_matches_bundled(self):
        """Production tldextract must not fetch the PSL over the network."""
        import tldextract
        offline = ml_predictor._TLD_EXTRACT
        self.assertIsNotNone(offline)
        for url in REGRESSION:
            a = offline(url)
            b = tldextract.extract(url)  # reference (may use cached snapshot)
            self.assertEqual(
                a.top_domain_under_public_suffix, b.top_domain_under_public_suffix
            )
            self.assertEqual(a.suffix, b.suffix)


class TestCaching(unittest.TestCase):
    def test_artifacts_cached_per_process(self):
        first = ml_predictor._load_sivakumar()
        second = ml_predictor._load_sivakumar()
        self.assertIs(first["artifacts"], second["artifacts"])
        self.assertTrue(ml_predictor._sivakumar_state["attempted"])


class TestRiskScoreRecomputation(unittest.TestCase):
    """Risk engine must still compute 70% ML + 30% rules; TLS/HTTP excluded."""

    def test_risk_score_formula(self):
        from services.risk_engine import calculate_risk

        def rule(detected, severity, name):
            return {
                "rule": name, "description": name, "severity": severity,
                "detected": detected, "value": None, "status": "DETECTED" if detected else "PASS",
                "evidence": None,
            }

        features = {
            "uses_https": True, "hostname": "example.com",
        }
        # No URL rules triggered, ML phishing = 0.54 (learnova value).
        ml_result = predict_url("https://learnova-ai-8.vercel.app/")
        indicators = [rule(False, "high", "IP Address Host")]
        tls = {"available": True, "score": 100, "version": "TLSv1.3",
               "certificate": {"issuer": "x"}}
        headers = {"available": True, "score": 100,
                   "headers": {"Strict-Transport-Security": True}}
        risk = calculate_risk(features, indicators, ml_result, tls, headers)

        # 0.7 * round(0.54*100) + 0.3 * 0 = 0.7 * 54 = 37.8 -> round 38
        expected = round(0.70 * round(0.54 * 100) + 0.30 * 0)
        self.assertEqual(risk["risk_score"], expected)
        self.assertEqual(risk["classification"], "SUSPICIOUS")
        # ML probability must flow through as phishing probability.
        self.assertEqual(risk["ml_analysis"]["phishing_probability"], 0.54)

    def test_tls_http_do_not_add_phishing_risk(self):
        from services.risk_engine import calculate_risk

        def rule(detected, severity, name):
            return {
                "rule": name, "description": name, "severity": severity,
                "detected": detected, "value": None,
                "status": "DETECTED" if detected else "PASS", "evidence": None,
            }

        features = {"uses_https": False, "hostname": "example.com"}
        ml_result = {"available": False, "phishing_probability": None,
                     "prediction": None}
        indicators = [
            rule(False, "high", "IP Address Host"),
            rule(True, "low", "Missing HTTPS"),  # transport, excluded
        ]
        tls = {"available": False, "score": 0, "error": "unavailable"}
        headers = {"available": False, "score": 0, "error": "unavailable",
                   "headers": {}}
        risk = calculate_risk(features, indicators, ml_result, tls, headers)
        # Unavailable TLS/HTTP and missing HTTPS must NOT add phishing risk.
        self.assertEqual(risk["risk_score"], 0)
        self.assertEqual(risk["classification"], "SAFE")


if __name__ == "__main__":
    unittest.main(verbosity=2)
