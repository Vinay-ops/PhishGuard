"""
Database Models
===============
SQLAlchemy ORM models for PhishGuard.
"""

from datetime import datetime, timezone

from sqlalchemy import Column, Integer, String, Float, DateTime, Text
from database.database import Base


class ScanRecord(Base):
    """Stores the result of every successful URL analysis."""

    __tablename__ = "scan_records"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    url = Column(String(2048), nullable=False, index=True)
    classification = Column(String(20), nullable=False)  # SAFE, SUSPICIOUS, PHISHING
    risk_score = Column(Integer, nullable=False)
    confidence = Column(Integer, nullable=False)
    message = Column(Text, nullable=True)
    detected_indicators = Column(Text, nullable=True)  # JSON string
    security_analysis = Column(Text, nullable=True)  # JSON string
    summary = Column(Text, nullable=True)
    scanned_at = Column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    def to_dict(self) -> dict:
        """Convert to a plain dictionary for API responses."""
        return {
            "id": self.id,
            "url": self.url,
            "classification": self.classification,
            "risk_score": self.risk_score,
            "confidence": self.confidence,
            "message": self.message,
            "detected_indicators": self.detected_indicators,
            "security_analysis": self.security_analysis,
            "summary": self.summary,
            "scanned_at": self.scanned_at.isoformat() if self.scanned_at else None,
        }
