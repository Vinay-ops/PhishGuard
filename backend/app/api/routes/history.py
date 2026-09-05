"""
History Route
=============
GET /api/v1/history — retrieve scan history with search, filtering, and pagination.
GET /api/v1/history/{id} — retrieve a single scan record.
DELETE /api/v1/history/{id} — delete a scan record.
"""

import math
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func

from database.database import get_db
from database.models import ScanRecord
from database.schemas import HistoryResponse, ScanRecordResponse, ScanRecordDetailResponse

router = APIRouter()


@router.get("/history/{record_id}", response_model=ScanRecordDetailResponse)
def get_history_record(record_id: int, db: Session = Depends(get_db)):
    """
    Retrieve a single stored scan record by ID.
    """
    record = (
        db.query(ScanRecord).filter(ScanRecord.id == record_id).first()
    )
    if not record:
        raise HTTPException(status_code=404, detail="Record not found.")

    return ScanRecordDetailResponse(**record.to_dict())


@router.get("/history", response_model=HistoryResponse)
def get_history(
    db: Session = Depends(get_db),
    search: str = Query("", description="Search URL substring"),
    classification: str = Query("All", description="Filter by classification"),
    risk: str = Query("All", description="Filter by risk level"),
    date: str = Query("All Time", description="Filter by date range"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(10, ge=1, le=50, description="Records per page"),
):
    """
    Retrieve scan history with optional search, classification,
    risk level, and date range filters.
    """
    query = db.query(ScanRecord).order_by(ScanRecord.scanned_at.desc())

    # Apply search filter
    if search.strip():
        query = query.filter(ScanRecord.url.contains(search.strip()))

    # Apply classification filter
    if classification != "All":
        query = query.filter(ScanRecord.classification == classification.upper())

    # Apply risk filter
    if risk != "All":
        risk_map = {
            "Low Risk": (0, 29),
            "Medium Risk": (30, 70),
            "High Risk": (71, 100),
        }
        if risk in risk_map:
            low, high = risk_map[risk]
            query = query.filter(
                ScanRecord.risk_score >= low,
                ScanRecord.risk_score <= high,
            )

    # Apply date filter
    now = datetime.now(timezone.utc)
    if date == "Today":
        start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        query = query.filter(ScanRecord.scanned_at >= start)
    elif date == "Last 7 Days":
        start = now - timedelta(days=6)
        start = start.replace(hour=0, minute=0, second=0, microsecond=0)
        query = query.filter(ScanRecord.scanned_at >= start)
    elif date == "Last 30 Days":
        start = now - timedelta(days=29)
        start = start.replace(hour=0, minute=0, second=0, microsecond=0)
        query = query.filter(ScanRecord.scanned_at >= start)

    # Count total matching records
    total = query.count()
    total_pages = max(1, math.ceil(total / page_size))

    # Paginate
    records = query.offset((page - 1) * page_size).limit(page_size).all()

    return {
        "records": [ScanRecordResponse(**r.to_dict()) for r in records],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
    }


@router.delete("/history/{record_id}")
def delete_history(record_id: int, db: Session = Depends(get_db)):
    """Delete a scan record by ID."""
    record = db.query(ScanRecord).filter(ScanRecord.id == record_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Record not found.")
    db.delete(record)
    db.commit()
    return {"message": "Record deleted successfully."}
