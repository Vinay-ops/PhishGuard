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
MODEL_PATH: str = os.environ.get(
    "MODEL_PATH",
    str(_ML_DIR / "model.onnx"),
)

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
