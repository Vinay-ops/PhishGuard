"""
CORS Configuration
==================
Centralized CORS middleware setup for the PhishGuard FastAPI app.

Allowed origins are read from the CORS_ORIGINS environment variable
(comma-separated). This is intentionally NOT a wildcard ("*") so that
credentials can be used safely in the future.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import CORS_ORIGINS


def add_cors_middleware(app: FastAPI) -> None:
    """Register CORSMiddleware on the FastAPI application."""
    app.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ORIGINS,
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )
