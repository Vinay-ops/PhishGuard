"""
Standalone SivakumarP Predictor
================================
Production-style predictor for SivakumarP/PhishingURLDetection.

Accepts a RAW URL STRING and internally performs the complete preprocessing
pipeline required by the RandomForest model. Callers never construct the
187-dimensional feature vector manually.

Feature pipeline (exact order expected by the model):
    [ TF-IDF_char(url)  |  TF-IDF_char(registered_domain)
    | TF-IDF_char(public_suffix)  |  scaled(digit_cnt, is_https) ]
    -> 96 + 57 + 32 + 2 = 187 features

Class mapping:
    classes_ = [0, 1]   ->   0 = benign/safe, 1 = phishing
    phishing_probability = model.predict_proba(X)[0][1]

NOTE: This module is isolated under benchmark/ for the compatibility gate.
It does NOT replace the production predictor (services/ml_predictor.py).
"""

import os

import joblib
import numpy as np
import tldextract
from scipy import sparse

_HERE = os.path.dirname(os.path.abspath(__file__))
_ARTIFACT_DIR = os.path.join(_HERE, "models", "sivakumarp")

_MODEL = None  # lazy-loaded singleton


def _load():
    """Load all artifacts once and cache them module-wide."""
    global _MODEL
    if _MODEL is not None:
        return _MODEL
    model = joblib.load(os.path.join(_ARTIFACT_DIR, "model.pkl"))
    enc_url = joblib.load(os.path.join(_ARTIFACT_DIR, "dataencoder_url.pkl"))
    enc_dom = joblib.load(os.path.join(_ARTIFACT_DIR, "dataencoder_dom.pkl"))
    enc_tld = joblib.load(os.path.join(_ARTIFACT_DIR, "dataencoder_tld.pkl"))
    scaler = joblib.load(os.path.join(_ARTIFACT_DIR, "datascaler.pkl"))
    _MODEL = {
        "model": model,
        "enc_url": enc_url,
        "enc_dom": enc_dom,
        "enc_tld": enc_tld,
        "scaler": scaler,
    }
    return _MODEL


def extract_features(url: str) -> dict:
    """
    Extract the raw feature components from a URL string.

    Returns dict with:
        url_text, registered_domain, public_suffix, digit_cnt, is_https
    """
    url = url.strip()
    ext = tldextract.extract(url)
    # Dataset convention (verified against URL-Phish Dataset.csv):
    #   dom  = registered domain  ("sites.google.com" -> "google.com")
    #   tld  = public suffix      ("www.google.co.uk" -> "co.uk")
    #   IPs  : dom = the IP string, tld = ""
    if ext.suffix:
        registered_domain = f"{ext.domain}.{ext.suffix}"
    else:
        registered_domain = ext.domain
    public_suffix = ext.suffix
    digit_cnt = sum(ch.isdigit() for ch in url)
    is_https = 1 if url.startswith("https") else 0
    return {
        "url_text": url,
        "registered_domain": registered_domain,
        "public_suffix": public_suffix,
        "digit_cnt": digit_cnt,
        "is_https": is_https,
    }


def build_feature_vector(url: str):
    """
    Build the exact 187-dim sparse feature vector expected by the model.

    Order: [TF-IDF(url) | TF-IDF(dom) | TF-IDF(tld) | scaled(digit_cnt, is_https)]
    """
    art = _load()
    feats = extract_features(url)
    u = art["enc_url"].transform([feats["url_text"]])
    d = art["enc_dom"].transform([feats["registered_domain"]])
    t = art["enc_tld"].transform([feats["public_suffix"]])
    n = art["scaler"].transform([[feats["digit_cnt"], feats["is_https"]]])
    X = sparse.hstack([u, d, t, sparse.csr_matrix(n)]).tocsr()
    return X, feats


def predict_url(url: str) -> dict:
    """
    Predict phishing probability for a raw URL string.

    Returns:
        {
            "prediction": "PHISHING" | "SAFE",
            "phishing_probability": float,   # 0-1 (class 1)
            "safe_probability": float,       # 0-1 (class 0)
            "available": True,
        }
    """
    art = _load()
    X, feats = build_feature_vector(url)
    proba = art["model"].predict_proba(X)[0]  # [p(benign), p(phishing)]
    phish = float(proba[1])
    return {
        "prediction": "PHISHING" if phish >= 0.5 else "SAFE",
        "phishing_probability": round(phish, 6),
        "safe_probability": round(float(proba[0]), 6),
        "features": feats,
        "available": True,
    }


def get_model_info() -> dict:
    """Return metadata about the loaded SivakumarP model."""
    art = _load()
    model = art["model"]
    return {
        "model_name": "SivakumarP/PhishingURLDetection",
        "model_type": "RandomForestClassifier",
        "n_estimators": model.n_estimators,
        "max_depth": model.max_depth,
        "n_features": model.n_features_in_,
        "classes": model.classes_.tolist(),
        "input": "raw URL string (feature pipeline applied internally)",
        "feature_order": "[TF-IDF(url) | TF-IDF(dom) | TF-IDF(tld) | scaled(digit_cnt, is_https)]",
        "available": True,
    }


if __name__ == "__main__":
    import time
    for url in [
        "https://learnova-ai-8.vercel.app/",
        "https://example.com/",
        "https://www.google.com/",
        "https://github.com/",
        "https://www.wikipedia.org/",
        "https://paypal.com/",
    ]:
        t0 = time.perf_counter()
        r = predict_url(url)
        dt = (time.perf_counter() - t0) * 1000
        f = r["features"]
        print(f"{url:40s} -> {r['prediction']:8s} phish={r['phishing_probability']*100:6.2f}%  "
              f"dom={f['registered_domain']!r:20s} tld={f['public_suffix']!r:8s} "
              f"digits={f['digit_cnt']} https={f['is_https']}  ({dt:.1f} ms)")