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

from app.core.config import CORS_ORIGINS, CORS_ORIGINS_REGEX


def add_cors_middleware(app: FastAPI) -> None:
    """Register CORSMiddleware on the FastAPI application.

    allow_origins covers exact origins (local dev, prod alias).
    allow_origin_regex covers the project's Vercel deployment/preview URLs so
    the SPA works from any of its own deployment domains. Credentials are
    never allowed, so this scoped list is low risk for the open scanner API.
    """
    app.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ORIGINS,
        allow_origin_regex=CORS_ORIGINS_REGEX or None,
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )
