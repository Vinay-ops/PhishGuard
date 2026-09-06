"""
Central Application Configuration
=================================
Reads all environment-based settings used by the PhishGuard FastAPI app.
No hardcoded environment-specific values — everything comes from env vars.
"""

import os
from pathlib import Path

# Base directories
_BACKEND_DIR = Path(__file__).resolve().parent.parent.parent
_APP_DIR = _BACKEND_DIR / "app"
_DATABASE_DIR = _BACKEND_DIR / "database"
_ML_DIR = _BACKEND_DIR / "ml"

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
# Use a local SQLite file by default. Override with DATABASE_URL for
# PostgreSQL or other engines in production.
DATABASE_URL: str = os.environ.get(
    "DATABASE_URL",
    f"sqlite:///{_BACKEND_DIR / 'phishguard.db'}",
)

# ---------------------------------------------------------------------------
# ML model
# ---------------------------------------------------------------------------
_raw_model_path = os.environ.get("MODEL_PATH")
_configured_model_path = Path(_raw_model_path) if _raw_model_path else _ML_DIR / "model.onnx"
MODEL_PATH: str = str(
    _configured_model_path
    if _configured_model_path.is_absolute()
    else (_BACKEND_DIR / _configured_model_path).resolve()
)

# SivakumarP RandomForest artifacts (production model).
#   model.pkl            RandomForestClassifier (100 trees, gini, depth 32)
#   dataencoder_url.pkl  char TF-IDF of the full URL string        (96 features)
#   dataencoder_dom.pkl  char TF-IDF of the registered domain      (57 features)
#   dataencoder_tld.pkl  char TF-IDF of the public suffix / TLD    (32 features)
#   datascaler.pkl       StandardScaler(digit_cnt, is_https)       (2 features)
# Feature layout: [TF-IDF(url) | TF-IDF(dom) | TF-IDF(tld) | scaled(digit_cnt, is_https)] = 187
SIVAKUMAR_DIR: str = str(_ML_DIR / "sivakumar")

# Active ML backend. "sivakumar" = SivakumarP/PhishingURLDetection RandomForest
# (default). "pirocheto" = the legacy ONNX model (kept for rollback).
MODEL_BACKEND: str = os.environ.get("MODEL_BACKEND", "sivakumar")

# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------
# Comma-separated list of allowed origins read from the environment.
# Example: CORS_ORIGINS=http://localhost:5173,https://phishguard.vercel.app
_raw_cors = os.environ.get("CORS_ORIGINS", "")
CORS_ORIGINS: list[str] = [
    origin.strip()
    for origin in _raw_cors.split(",")
    if origin.strip()
]

# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------
API_PREFIX: str = os.environ.get("API_PREFIX", "/api/v1")

# ---------------------------------------------------------------------------
# General
# ---------------------------------------------------------------------------
DEBUG: bool = os.environ.get("DEBUG", "false").lower() == "true"
