"""
FastAPI Application Factory
============================
Creates and configures the FastAPI application instance.

This is the single source of truth for the FastAPI app. The Vercel entry
point (backend/api/index.py) and the local dev server both import from here.
"""

import uvicorn
from fastapi import FastAPI

from app.core.config import API_PREFIX, DEBUG
from app.core.cors import add_cors_middleware
from app.api.routes import scanner, history, dashboard
from database.database import init_db

app = FastAPI(
    title="PhishGuard API",
    description=(
        "URL phishing detection & security analyzer. POST a URL to "
        f"{API_PREFIX}/analyze to receive a risk assessment."
    ),
    version="0.2.0",
    debug=DEBUG,
)

# CORS
add_cors_middleware(app)


@app.on_event("startup")
def startup() -> None:
    """Create database tables on startup."""
    init_db()


@app.get("/")
def health_check():
    """Health check endpoint."""
    return {"status": "ok", "service": "PhishGuard API"}


# Register routers with API prefix
app.include_router(scanner.router, prefix=API_PREFIX)
app.include_router(history.router, prefix=API_PREFIX)
app.include_router(dashboard.router, prefix=API_PREFIX)


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
