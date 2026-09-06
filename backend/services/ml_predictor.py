"""
ML Predictor
============
Production phishing-URL ML predictor.

The active model is SivakumarP/PhishingURLDetection, a RandomForest
classifier trained on the URL-Phish dataset. It is NOT a raw-URL model: it
consumes a fixed 187-dimension feature vector built from the URL:

    [ char TF-IDF(full URL) | char TF-IDF(registered domain)
    | char TF-IDF(public suffix / TLD) | scaled(digit_cnt, is_https) ]

    96 + 57 + 32 + 2 = 187 features

Class mapping (from the URL-Phish dataset and the model artifact):
    classes_ = [0, 1]   ->   0 = benign/safe, 1 = phishing
    phishing_probability = model.predict_proba(X)[:, 1]

The five serialized artifacts live in backend/ml/sivakumar/ and are loaded
once per Python process (cached module-level), never per request.

The legacy pirocheto ONNX model is retained as a rollback/fallback backend.
The public interface (predict_url / get_model_info) is unchanged so the
scanner, risk engine, and API need no knowledge of which model is active.

Security: never loads pickle files from untrusted sources (artifacts are
shipped with the deployment), never fetches URLs, and tldextract is used in
an offline mode that never downloads the Public Suffix List at runtime.
"""

import os
import warnings
from typing import Optional

from app.core.config import MODEL_BACKEND, MODEL_PATH, SIVAKUMAR_DIR

# Which serialized artifacts are required for the SivakumarP backend.
_SIVAKUMAR_FILES = (
    "model.pkl",
    "dataencoder_url.pkl",
    "dataencoder_dom.pkl",
    "dataencoder_tld.pkl",
    "datascaler.pkl",
)

# Module-level model references (loaded once, reused across requests).
# Each entry: {"artifacts": {...}, "error": str|None, "attempted": bool}
_sivakumar_state = {"artifacts": None, "error": None, "attempted": False}
_onnx_state = {"session": None, "error": None, "attempted": False}

# tldextract instance pinned to the bundled Public Suffix List snapshot so
# production never performs a network download at runtime.
try:
    import tldextract as _tldextract

    _TLD_EXTRACT = _tldextract.TLDExtract(
        suffix_list_urls=(),      # never fetch the PSL from the network
        cache_dir=None,           # never write a cache file
        fallback_to_snapshot=True,  # always fall back to the bundled snapshot
    )
except Exception:  # pragma: no cover - tldextract is a required dependency
    _tldextract = None
    _TLD_EXTRACT = None


# ---------------------------------------------------------------------------
# Feature extraction (SivakumarP preprocessing - isolated on purpose)
# ---------------------------------------------------------------------------

def extract_sivakumar_features(url: str) -> dict:
    """
    Extract the exact SivakumarP feature components from a raw URL string.

    The extraction semantics were verified against the original URL-Phish
    Dataset.csv during the compatibility audit:
      * registered_domain: public-suffix registered domain
        ("sites.google.com/x" -> "google.com", "www.google.co.uk" -> "google.co.uk")
      * public_suffix: public suffix ("co.uk", "com", "app", ...)
      * IP-hosted URLs: registered_domain = the IP string, public_suffix = ""
        (matches the dataset convention)
      * digit_cnt: number of numeric characters in the FULL URL string
      * is_https: 1 if the URL starts with "https", else 0

    Returns a dict with url_text, registered_domain, public_suffix,
    digit_cnt, is_https.
    """
    url_stripped = url.strip()

    if _TLD_EXTRACT is not None:
        ext = _TLD_EXTRACT(url_stripped)
        domain_part = ext.domain
        suffix_part = ext.suffix
    else:  # pragma: no cover - defensive fallback if tldextract is absent
        domain_part = ""
        suffix_part = ""
        host = url_stripped.split("://", 1)[-1].split("/", 1)[0].split("@")[-1]
        labels = [lb for lb in host.split(":")[0].split(".") if lb]
        if labels:
            domain_part = ".".join(labels)

    if suffix_part:
        registered_domain = f"{domain_part}.{suffix_part}"
    else:
        registered_domain = domain_part
    public_suffix = suffix_part

    digit_cnt = sum(ch.isdigit() for ch in url_stripped)
    is_https = 1 if url_stripped.startswith("https") else 0

    return {
        "url_text": url_stripped,
        "registered_domain": registered_domain,
        "public_suffix": public_suffix,
        "digit_cnt": digit_cnt,
        "is_https": is_https,
    }


def build_sivakumar_feature_vector(url: str):
    """
    Build the exact 187-dim feature vector expected by the RandomForest.

    Order: [TF-IDF(url) | TF-IDF(dom) | TF-IDF(tld) |
            scaled(digit_cnt, is_https)]
    Returns (scipy sparse matrix of shape (1, 187), feature dict).
    """
    from scipy import sparse

    art = _load_sivakumar()["artifacts"]
    feats = extract_sivakumar_features(url)
    enc_url, enc_dom, enc_tld, scaler = (
        art["enc_url"], art["enc_dom"], art["enc_tld"], art["scaler"],
    )
    u = enc_url.transform([feats["url_text"]])
    d = enc_dom.transform([feats["registered_domain"]])
    t = enc_tld.transform([feats["public_suffix"]])
    # The scaler was fit on a named DataFrame; passing a bare array only
    # triggers sklearn's "no feature names" UserWarning, never a wrong
    # result, so we silence that specific benign notice.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", category=UserWarning)
        n = scaler.transform([[feats["digit_cnt"], feats["is_https"]]])
    X = sparse.hstack([u, d, t, sparse.csr_matrix(n)]).tocsr()
    return X, feats


# ---------------------------------------------------------------------------
# Loaders (each backend loaded once per process)
# ---------------------------------------------------------------------------

def _load_sivakumar() -> dict:
    """Load and cache the five SivakumarP artifacts."""
    if _sivakumar_state["attempted"]:
        return _sivakumar_state

    missing = [
        name for name in _SIVAKUMAR_FILES
        if not os.path.isfile(os.path.join(SIVAKUMAR_DIR, name))
    ]
    if missing:
        _sivakumar_state["error"] = (
            f"ML model artifacts missing: {', '.join(missing)} in {SIVAKUMAR_DIR}"
        )
        _sivakumar_state["attempted"] = True
        return _sivakumar_state

    try:
        import joblib

        # sklearn version-skew on older local runtimes only produces a
        # warning; predictions remain correct (verified in the audit). Pin
        # scikit-learn==1.8.0 in the deployment to avoid it entirely.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", category=UserWarning)
            artifacts = {
                "model": joblib.load(os.path.join(SIVAKUMAR_DIR, "model.pkl")),
                "enc_url": joblib.load(os.path.join(SIVAKUMAR_DIR, "dataencoder_url.pkl")),
                "enc_dom": joblib.load(os.path.join(SIVAKUMAR_DIR, "dataencoder_dom.pkl")),
                "enc_tld": joblib.load(os.path.join(SIVAKUMAR_DIR, "dataencoder_tld.pkl")),
                "scaler": joblib.load(os.path.join(SIVAKUMAR_DIR, "datascaler.pkl")),
            }
        model = artifacts["model"]
        expected = 187
        if getattr(model, "n_features_in_", None) != expected:
            raise ValueError(
                f"RandomForest expects {model.n_features_in_} features, "
                f"expected {expected}."
            )
        if list(getattr(model, "classes_", [0, 1])) != [0, 1]:
            raise ValueError(
                f"RandomForest classes must be [0, 1], got {model.classes_}"
            )
        _sivakumar_state["artifacts"] = artifacts
    except Exception as exc:
        _sivakumar_state["error"] = f"Failed to load SivakumarP model: {exc}"
        _sivakumar_state["attempted"] = True
        return _sivakumar_state

    _sivakumar_state["attempted"] = True
    return _sivakumar_state


def _load_onnx():
    """Load and cache the legacy pirocheto ONNX session (rollback backend)."""
    if _onnx_state["attempted"]:
        return _onnx_state

    if not os.path.isfile(MODEL_PATH):
        _onnx_state["error"] = f"ONNX model file not found at {MODEL_PATH}"
        _onnx_state["attempted"] = True
        return _onnx_state

    try:
        import onnxruntime as ort
        _onnx_state["session"] = ort.InferenceSession(
            MODEL_PATH, providers=["CPUExecutionProvider"]
        )
    except Exception as exc:
        _onnx_state["error"] = f"Failed to load ONNX model: {exc}"
        _onnx_state["attempted"] = True
        return _onnx_state

    _onnx_state["attempted"] = True
    return _onnx_state


def _active_backend() -> str:
    backend = (MODEL_BACKEND or "sivakumar").strip().lower()
    return backend if backend in ("sivakumar", "pirocheto") else "sivakumar"


# ---------------------------------------------------------------------------
# Prediction backends (normalized to the shared API contract)
# ---------------------------------------------------------------------------

def _predict_sivakumar(url: str) -> dict:
    """Run the SivakumarP RandomForest pipeline on a URL string."""
    state = _load_sivakumar()
    if state["error"] or state["artifacts"] is None:
        return {
            "available": False,
            "prediction": None,
            "predicted_label": None,
            "phishing_probability": None,
            "safe_probability": None,
            "model_status": "UNAVAILABLE",
            "error": state["error"],
        }

    try:
        model = state["artifacts"]["model"]
        X, _feats = build_sivakumar_feature_vector(url)
        proba = model.predict_proba(X)[0]  # [p(class 0), p(class 1)]
        if len(proba) != 2:
            raise ValueError(
                f"predict_proba returned {len(proba)} columns; expected 2."
            )
        safe_prob = float(proba[0])
        phishing_prob = float(proba[1])
        if not all(__import__("math").isfinite(v) for v in (safe_prob, phishing_prob)):
            raise ValueError("ML model returned non-finite probabilities.")
        if min(safe_prob, phishing_prob) < 0 or max(safe_prob, phishing_prob) > 1:
            raise ValueError("ML model returned probabilities outside 0-1.")

        prediction = "PHISHING" if phishing_prob >= 0.5 else "SAFE"
        return {
            "available": True,
            "prediction": prediction,
            "predicted_label": prediction,
            # 6-decimal rounding keeps the production value identical to the
            # verified benchmark outputs (e.g. example.com -> 0.300191).
            "phishing_probability": round(phishing_prob, 6),
            "safe_probability": round(safe_prob, 6),
            "model_name": "SivakumarP/PhishingURLDetection",
            "model_type": "RandomForest (TF-IDF url/dom/tld + scaler)",
            "model_status": "AVAILABLE",
        }
    except Exception as exc:
        return {
            "available": False,
            "prediction": None,
            "predicted_label": None,
            "phishing_probability": None,
            "safe_probability": None,
            "model_status": "UNAVAILABLE",
            "error": f"ML inference failed: {exc}",
        }


def _predict_onnx(url: str) -> dict:
    """Run the legacy pirocheto ONNX model (kept for rollback)."""
    import numpy as np

    state = _load_onnx()
    session = state.get("session")
    if state["error"] or session is None:
        return {
            "available": False,
            "prediction": None,
            "predicted_label": None,
            "phishing_probability": None,
            "safe_probability": None,
            "model_status": "UNAVAILABLE",
            "error": state["error"],
        }

    try:
        if not isinstance(url, str) or not url.strip():
            raise ValueError("URL must be a non-empty string.")

        input_name = session.get_inputs()[0].name
        output_names = [output.name for output in session.get_outputs()]
        if len(output_names) < 2:
            raise ValueError("ML model must expose label and probability outputs.")

        inputs = np.array([url.strip()], dtype=np.str_)
        raw_results = session.run(None, {input_name: inputs})
        results = dict(zip(output_names, raw_results))

        labels = np.asarray(results.get("label"))
        probability_values = np.asarray(results.get("probabilities"), dtype=float)
        if labels.size < 1 or probability_values.shape != (1, 2):
            raise ValueError("ML model returned an unexpected output shape.")

        label = int(labels.reshape(-1)[0])
        safe_prob = float(probability_values[0, 0])
        phishing_prob = float(probability_values[0, 1])
        if label not in (0, 1):
            raise ValueError(f"ML model returned unknown class label: {label}")

        prediction = "PHISHING" if label == 1 else "SAFE"
        return {
            "available": True,
            "prediction": prediction,
            "predicted_label": prediction,
            "phishing_probability": round(phishing_prob, 4),
            "safe_probability": round(safe_prob, 4),
            "model_name": "pirocheto/phishing-url-detection",
            "model_type": "ONNX classifier (legacy)",
            "model_status": "AVAILABLE",
        }
    except Exception as exc:
        return {
            "available": False,
            "prediction": None,
            "predicted_label": None,
            "phishing_probability": None,
            "safe_probability": None,
            "model_status": "UNAVAILABLE",
            "error": f"ML inference failed: {exc}",
        }


# ---------------------------------------------------------------------------
# Public API (unchanged contract)
# ---------------------------------------------------------------------------

def predict_url(url: str) -> dict:
    """
    Run ML inference on a URL string and return the phishing probability.

    The active backend is MODEL_BACKEND ("sivakumar" by default; the legacy
    "pirocheto" ONNX backend is retained for rollback). If the active
    backend cannot load, the other backend is attempted so the scanner
    never silently loses ML signal; the returned model_name/error make the
    actual backend explicit.

    Returns (shape unchanged from the previous implementation):
        available: bool
        prediction: "SAFE" | "PHISHING" | None
        phishing_probability: float (0-1) | None   # class 1 probability
        safe_probability: float (0-1) | None       # class 0 probability
        model_name: str | None
        model_status: "AVAILABLE" | "UNAVAILABLE"
        error: str | None
    """
    backend = _active_backend()

    if backend == "sivakumar":
        result = _predict_sivakumar(url)
        if result.get("available"):
            return result
        # Fall back to the legacy ONNX model so a model failure never
        # silently drops ML analysis.
        fallback = _predict_onnx(url)
        if fallback.get("available"):
            fallback = dict(fallback)
            fallback["error"] = (
                f"SivakumarP backend unavailable; fell back to ONNX. "
                f"Reason: {result.get('error')}"
            )
            return fallback
        return result
    else:  # pirocheto requested explicitly
        result = _predict_onnx(url)
        if result.get("available"):
            return result
        fallback = _predict_sivakumar(url)
        if fallback.get("available"):
            fallback = dict(fallback)
            fallback["error"] = (
                f"ONNX backend unavailable; fell back to SivakumarP. "
                f"Reason: {result.get('error')}"
            )
            return fallback
        return result


def get_model_info() -> dict:
    """Return metadata about the active ML model (never raises)."""
    backend = _active_backend()
    try:
        if backend == "sivakumar":
            state = _load_sivakumar()
            if state.get("error") or state.get("artifacts") is None:
                info = {
                    "model_name": "SivakumarP/PhishingURLDetection",
                    "model_type": "RandomForest",
                    "input": "Raw URL string (TF-IDF url/dom/tld + scaled digit_cnt/is_https)",
                    "output": "phishing probability (class 1 = phishing)",
                    "available": False,
                    "error": state.get("error"),
                }
                # Report the alternate backend when this one failed.
                onnx_state = _load_onnx()
                if onnx_state.get("session") is not None:
                    info["available"] = True
                    info["fallback_active"] = True
                    info["model_name"] = "pirocheto/phishing-url-detection (fallback)"
                    info["model_type"] = "ONNX classifier"
                    info["error"] = state.get("error")
                return info

            artifacts = state["artifacts"]
            model = artifacts["model"]
            import sklearn
            return {
                "model_name": "SivakumarP/PhishingURLDetection",
                "model_type": "RandomForest",
                "n_estimators": model.n_estimators,
                "max_depth": model.max_depth,
                "n_features": model.n_features_in_,
                "classes": model.classes_.tolist(),
                "input": "Raw URL string (TF-IDF url/dom/tld + scaled digit_cnt/is_https)",
                "output": "phishing probability (class 1 = phishing)",
                "scikit_learn_version": sklearn.__version__,
                "feature_order": "[TF-IDF(url) | TF-IDF(dom) | TF-IDF(tld) | scaled(digit_cnt, is_https)] = 187",
                "available": True,
                "error": None,
            }
        else:
            state = _load_onnx()
            available = state.get("session") is not None and state.get("error") is None
            return {
                "model_name": "pirocheto/phishing-url-detection",
                "model_type": "ONNX classifier",
                "input": "Raw URL string",
                "output": "Class label and safe/phishing probabilities",
                "available": available,
                "error": state.get("error"),
            }
    except Exception as exc:  # pragma: no cover - defensive
        return {
            "model_name": None,
            "available": False,
            "error": str(exc),
        }
