"""
Dashboard Route
===============
GET /api/v1/dashboard — return summary statistics for the security dashboard.
GET /api/v1/dashboard/trends — return daily average risk scores for the last 7 days.
"""

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from database.database import get_db
from database.models import ScanRecord
from database.schemas import DashboardResponse, TrendResponse, ScanRecordResponse

router = APIRouter()


@router.get("/dashboard", response_model=DashboardResponse)
def get_dashboard(db: Session = Depends(get_db)):
    """
    Return aggregate statistics from the scan history:
    total scans, counts per classification, average risk score,
    and the most recent scans.
    """
    total = db.query(func.count(ScanRecord.id)).scalar() or 0

    safe_count = (
        db.query(func.count(ScanRecord.id))
        .filter(ScanRecord.classification == "SAFE")
        .scalar()
        or 0
    )

    suspicious_count = (
        db.query(func.count(ScanRecord.id))
        .filter(ScanRecord.classification == "SUSPICIOUS")
        .scalar()
        or 0
    )

    phishing_count = (
        db.query(func.count(ScanRecord.id))
        .filter(ScanRecord.classification == "PHISHING")
        .scalar()
        or 0
    )

    avg_risk = (
        db.query(func.avg(ScanRecord.risk_score)).scalar() or 0
    )

    # Most recent 5 scans
    recent = (
        db.query(ScanRecord)
        .order_by(ScanRecord.scanned_at.desc())
        .limit(5)
        .all()
    )

    return {
        "total_scans": total,
        "safe_count": safe_count,
        "suspicious_count": suspicious_count,
        "phishing_count": phishing_count,
        "average_risk_score": round(float(avg_risk), 1),
        "recent_scans": [ScanRecordResponse(**r.to_dict()) for r in recent],
    }


@router.get("/dashboard/trends", response_model=TrendResponse)
def get_dashboard_trends(db: Session = Depends(get_db)):
    """
    Return the average risk score for each of the last 7 calendar days
    (oldest first), derived from real SQLite scan records.

    Days that contain no scans are reported as `null` so the chart can
    distinguish "no data" from a real risk score of 0 — no values are
    fabricated.
    """
    now = datetime.now(timezone.utc)

    # Build the 7 calendar-day windows ending today (oldest first).
    day_starts = [
        (now - timedelta(days=6 - i)).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        for i in range(7)
    ]

    labels: list[str] = []
    average_risk_scores: list = []
    total_scans = 0

    for day_start in day_starts:
        day_end = day_start + timedelta(days=1)
        day_count = (
            db.query(func.count(ScanRecord.id))
            .filter(
                ScanRecord.scanned_at >= day_start,
                ScanRecord.scanned_at < day_end,
            )
            .scalar()
            or 0
        )
        total_scans += day_count

        # Weekday abbreviation, e.g. "Mon", "Tue".
        labels.append(day_start.strftime("%a"))

        if day_count > 0:
            avg = (
                db.query(func.avg(ScanRecord.risk_score))
                .filter(
                    ScanRecord.scanned_at >= day_start,
                    ScanRecord.scanned_at < day_end,
                )
                .scalar()
            )
            average_risk_scores.append(round(float(avg), 1))
        else:
            average_risk_scores.append(None)

    return {
        "labels": labels,
        "average_risk_scores": average_risk_scores,
        "total_scans": total_scans,
    }
