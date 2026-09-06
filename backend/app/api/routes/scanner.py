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
from services.ssrf_protector import SSRFViolation

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
    except SSRFViolation as exc:
        raise HTTPException(status_code=400, detail=str(exc))
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
            security_analysis=json.dumps({
                "tls_analysis": result.get("tls_analysis", {}),
                "header_analysis": result.get("header_analysis", {}),
                "risk_breakdown": result.get("risk_breakdown", {}),
                "top_factors": result.get("top_factors", []),
                "why_flagged": result.get("why_flagged", {}),
                "rule_analysis": result.get("rule_analysis", {}),
                "phishing_analysis": result.get("phishing_analysis", {}),
                "connection_security": result.get("connection_security", {}),
                "http_security": result.get("http_security", {}),
                "final_assessment": result.get("final_assessment", {}),
                "model_info": result.get("model_info", {}),
                "ml_phishing_probability_pct": result.get("ml_phishing_probability_pct"),
                "model_rule_status": result.get("model_rule_status"),
            }),
        )
        db.add(record)
        db.commit()
        db.refresh(record)
    except Exception:
        db.rollback()

    return result
