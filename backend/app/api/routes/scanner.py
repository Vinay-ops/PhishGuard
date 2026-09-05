"""
Scanner Route
=============
POST /api/v1/analyze — the main URL analysis endpoint.
"""

import json

from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session

from database.database import get_db
from database.models import ScanRecord
from database.schemas import AnalyzeRequest, AnalyzeResponse
from services.risk_engine import analyze_url

router = APIRouter()


@router.post("/analyze", response_model=AnalyzeResponse)
def analyze(request: AnalyzeRequest, db: Session = Depends(get_db)):
    """
    Analyze a URL for phishing indicators.

    1. Validate the URL string.
    2. Extract URL features.
    3. Run security rule analysis.
    4. Calculate risk score, classification, and confidence.
    5. Store the result in the database.
    6. Return the analysis result.
    """
    url = request.url.strip()

    if not url:
        raise HTTPException(status_code=400, detail="URL must not be empty.")

    if len(url) > 2048:
        raise HTTPException(
            status_code=400,
            detail="URL exceeds maximum length of 2048 characters.",
        )

    if not (url.startswith("http://") or url.startswith("https://")):
        raise HTTPException(
            status_code=400,
            detail="URL must start with http:// or https://.",
        )

    # Run the analysis pipeline.
    try:
        result = analyze_url(url)
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="An error occurred during URL analysis.",
        )

    # Persist to database (best-effort).
    try:
        record = ScanRecord(
            url=result["url"],
            classification=result["classification"],
            risk_score=result["risk_score"],
            confidence=result["confidence"],
            message=result.get("message", ""),
            detected_indicators=json.dumps(result.get("detected_indicators", [])),
            summary=result.get("summary", ""),
        )
        db.add(record)
        db.commit()
        db.refresh(record)
    except Exception:
        db.rollback()

    return result
