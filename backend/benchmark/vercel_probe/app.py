"""
Isolated SivakumarP Live Vercel Probe
=====================================
Self-contained FastAPI app for the final live Vercel compatibility test.

Routes:
    GET /api/benchmark/sivakumar/ping
    GET /api/benchmark/sivakumar/test?url=<url>

It loads the SivakumarP predictor, runs the exact production-style
preprocessing (tldextract -> TF-IDF(url/dom/tld) + scaled digit_cnt/is_https
-> RandomForest predict_proba), and returns label + probabilities + load
status + inference timing.

This project is intentionally separate from the PhishGuard production app.
"""

import os
import time

from fastapi import FastAPI

from predictor import get_model_info, predict_url

app = FastAPI(title="SivakumarP Live Probe")

_LOAD_TIME_MS = None


@app.on_event("startup")
def _mark_startup():
    """Nothing heavy here; the predictor lazy-loads on first request."""
    pass


def _load_status():
    try:
        info = get_model_info()
        return {"loaded": True, "model": info["model_name"], "detail": info}
    except Exception as exc:  # pragma: no cover
        return {"loaded": False, "error": f"{type(exc).__name__}: {exc}"}


@app.get("/api/benchmark/sivakumar/ping")
def ping():
    status = _load_status()
    return {
        "ok": True,
        "model": status.get("model"),
        "model_loaded": status["loaded"],
        "sklearn_version": _sklearn_version(),
        "numpy_version": _numpy_version(),
        "scipy_version": _scipy_version(),
        "tldextract_version": _tldextract_version(),
    }


def _sklearn_version():
    try:
        import sklearn
        return sklearn.__version__
    except Exception:
        return None


def _numpy_version():
    try:
        import numpy
        return numpy.__version__
    except Exception:
        return None


def _scipy_version():
    try:
        import scipy
        return scipy.__version__
    except Exception:
        return None


def _tldextract_version():
    try:
        import tldextract
        return tldextract.__version__
    except Exception:
        return None


@app.get("/api/benchmark/sivakumar/test")
def test(url: str = ""):
    if not url:
        return {"error": "Provide ?url=<url>", "status": 400}

    # Cold-load timing (first request after boot loads + unpickles the model).
    t_load0 = time.perf_counter()
    status = _load_status()
    t_load = (time.perf_counter() - t_load0) * 1000

    if not status["loaded"]:
        return {"url": url, "status": "MODEL_LOAD_FAILED", "error": status.get("error")}

    t0 = time.perf_counter()
    result = predict_url(url)
    t_infer = (time.perf_counter() - t0) * 1000

    return {
        "url": url,
        "prediction": result["prediction"],
        "phishing_probability": result["phishing_probability"],
        "safe_probability": result["safe_probability"],
        "phishing_probability_pct": round(result["phishing_probability"] * 100, 4),
        "model_load_status": "OK",
        "model_load_ms": round(t_load, 2),
        "inference_ms": round(t_infer, 2),
        "total_ms": round(t_load + t_infer, 2),
        "features": result["features"],
        "sklearn_version": _sklearn_version(),
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8011)