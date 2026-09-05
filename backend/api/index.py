"""
Vercel Entry Point
==================
Exposes the FastAPI application for Vercel's Python Serverless Functions.

Vercel invokes this file as a serverless function. It must expose a module-
level ``app`` object that is a callable ASGI application.
"""

import sys
from pathlib import Path

# Ensure the backend/ directory is on sys.path so that the app, database,
# and services packages are importable when Vercel runs this file.
_BACKEND_ROOT = str(Path(__file__).resolve().parent.parent)
if _BACKEND_ROOT not in sys.path:
    sys.path.insert(0, _BACKEND_ROOT)

from app.main import app

__all__ = ["app"]
