"""
Database Configuration
======================
SQLite database connection and session management using SQLAlchemy.
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# Database file path relative to the backend directory.
_DB_DIR = os.path.dirname(__file__)
_DB_PATH = os.path.join(_DB_DIR, "..", "phishguard.db")
DATABASE_URL = f"sqlite:///{os.path.abspath(_DB_PATH)}"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},  # SQLite-specific
    echo=False,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """
    Dependency that provides a database session.
    Used with FastAPI's Depends() system.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Create all tables if they don't exist."""
    # Import models so Base.metadata knows about them.
    from database import models  # noqa: F401
    Base.metadata.create_all(bind=engine)
