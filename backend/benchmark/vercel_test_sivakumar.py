"""
Isolated Vercel-Compatible Test Endpoint (SivakumarP)
=====================================================
A minimal ASGI app that loads the standalone SivakumarP predictor and serves
a single prediction endpoint. It is intentionally isolated under benchmark/
so it can be deployed to Vercel for a compatibility test WITHOUT touching the
production scanner route (backend/api/index.py).

Deploy for testing:
    vercel.json functions entry -> benchmark/vercel_test_sivakumar.py:app

Endpoints:
    GET  /ping              -> {"ok": true}
    POST /test              -> {"url": ..., "prediction": ..., "phishing_probability": ...}
    POST /test?url=...      -> same (query-string convenience)
"""

import os
import sys

# Make the standalone predictor importable regardless of CWD.
_BENCH_DIR = os.path.dirname(os.path.abspath(__file__))
if _BENCH_DIR not in sys.path:
    sys.path.insert(0, _BENCH_DIR)

from fastapi import FastAPI, Query
from pydantic import BaseModel

from sivakumar_predictor import predict_url, get_model_info

app = FastAPI(title="SivakumarP Vercel Compatibility Probe")


class PredictRequest(BaseModel):
    url: str


@app.get("/ping")
def ping():
    return {"ok": True, "model": get_model_info()["model_name"]}


@app.post("/test")
def test(request: PredictRequest = None, url: str = Query(None)):
    target = (request.url if request else None) or url
    if not target:
        return {"error": "Provide a URL in the body or ?url="}
    result = predict_url(target)
    return {
        "url": target,
        "prediction": result["prediction"],
        "phishing_probability": result["phishing_probability"],
        "safe_probability": result["safe_probability"],
        "model": get_model_info()["model_name"],
        "features": result["features"],
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8010)