"""
PhishGuard – FastAPI backend
=============================

Application setup and CORS configuration. Routes are registered from
the routes/ package; database initialization happens here.

Run locally from this folder:

    python main.py
    # or
    uvicorn main:app --reload --port 8000
"""

import os

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from database.database import init_db
from routes import scanner, history, dashboard

# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------
app = FastAPI(
    title="PhishGuard API",
    description=(
        "URL phishing detection & security analyzer. POST a URL to /analyze "
        "to receive a risk assessment."
    ),
    version="0.2.0",
)

# ---------------------------------------------------------------------------
# CORS — restrict to known frontend dev-server origins.
# ---------------------------------------------------------------------------
# Read allowed origins from env; fall back to common dev defaults.
_extra_origins = os.environ.get("CORS_ORIGINS", "").split(",")
_allowed_origins = [
    origin.strip()
    for origin in [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
        *_extra_origins,
    ]
    if origin
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
app.include_router(scanner.router)
app.include_router(history.router)
app.include_router(dashboard.router)


@app.get("/")
def health_check():
    """Simple health check so the frontend/developer can confirm the API is up."""
    return {"status": "ok", "service": "PhishGuard API"}


# ---------------------------------------------------------------------------
# Startup: create database tables
# ---------------------------------------------------------------------------
@app.on_event("startup")
def startup():
    init_db()


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
