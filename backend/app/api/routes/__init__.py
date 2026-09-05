"""
Router package — re-exports all route routers.
"""

from app.api.routes import scanner, history, dashboard

__all__ = ["scanner", "history", "dashboard"]
