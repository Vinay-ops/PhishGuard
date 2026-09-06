"""
SivakumarP predictor (self-contained copy for the Vercel probe).
Accepts a raw URL string; performs the complete 187-dim feature pipeline
internally. Artifacts are loaded from ./models/sivakumarp/.
"""

import os

import joblib
import tldextract
from scipy import sparse

_HERE = os.path.dirname(os.path.abspath(__file__))
_ARTIFACT_DIR = os.path.join(_HERE, "models", "sivakumarp")

_ART = None


def _load():
    global _ART
    if _ART is not None:
        return _ART
    _ART = {
        "model": joblib.load(os.path.join(_ARTIFACT_DIR, "model.pkl")),
        "enc_url": joblib.load(os.path.join(_ARTIFACT_DIR, "dataencoder_url.pkl")),
        "enc_dom": joblib.load(os.path.join(_ARTIFACT_DIR, "dataencoder_dom.pkl")),
        "enc_tld": joblib.load(os.path.join(_ARTIFACT_DIR, "dataencoder_tld.pkl")),
        "scaler": joblib.load(os.path.join(_ARTIFACT_DIR, "datascaler.pkl")),
    }
    return _ART


def extract_features(url: str) -> dict:
    url = url.strip()
    ext = tldextract.extract(url)
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


def predict_url(url: str) -> dict:
    art = _load()
    feats = extract_features(url)
    u = art["enc_url"].transform([feats["url_text"]])
    d = art["enc_dom"].transform([feats["registered_domain"]])
    t = art["enc_tld"].transform([feats["public_suffix"]])
    n = art["scaler"].transform([[feats["digit_cnt"], feats["is_https"]]])
    X = sparse.hstack([u, d, t, sparse.csr_matrix(n)]).tocsr()
    proba = art["model"].predict_proba(X)[0]
    phish = float(proba[1])
    return {
        "prediction": "PHISHING" if phish >= 0.5 else "SAFE",
        "phishing_probability": round(phish, 6),
        "safe_probability": round(float(proba[0]), 6),
        "features": feats,
    }


def get_model_info() -> dict:
    art = _load()
    model = art["model"]
    return {
        "model_name": "SivakumarP/PhishingURLDetection",
        "model_type": "RandomForestClassifier",
        "n_estimators": model.n_estimators,
        "max_depth": model.max_depth,
        "n_features": model.n_features_in_,
        "classes": model.classes_.tolist(),
        "available": True,
    }