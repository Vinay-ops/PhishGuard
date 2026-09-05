"""
PhishGuard – FastAPI backend (legacy local-dev entry point)
============================================================

The canonical application factory now lives in app/main.py.
This module is kept so that ``python main.py`` and
``uvicorn main:app --reload`` continue to work.
"""

import uvicorn

from app.main import app

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
