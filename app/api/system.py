"""
System & Dashboard API: Overall platform statistics and Test Lab status.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from ..database import get_db
from ..models import ScanJobModel, FindingModel
from ..schemas import DashboardStatsResponse, ScanJobResponse

router = APIRouter(prefix="/system", tags=["System"])


@router.get("/stats", response_model=DashboardStatsResponse)
def get_dashboard_stats(db: Session = Depends(get_db)):
    """Aggregates high-level vulnerability metrics across all scans."""
    total_scans = db.query(func.count(ScanJobModel.id)).scalar() or 0
    active_scans = db.query(func.count(ScanJobModel.id)).filter(ScanJobModel.status == "RUNNING").scalar() or 0

    total_findings = db.query(func.count(FindingModel.id)).scalar() or 0
    crit = db.query(func.count(FindingModel.id)).filter(FindingModel.severity == "CRITICAL").scalar() or 0
    high = db.query(func.count(FindingModel.id)).filter(FindingModel.severity == "HIGH").scalar() or 0
    med = db.query(func.count(FindingModel.id)).filter(FindingModel.severity == "MEDIUM").scalar() or 0
    low = db.query(func.count(FindingModel.id)).filter(FindingModel.severity == "LOW").scalar() or 0
    info = db.query(func.count(FindingModel.id)).filter(FindingModel.severity == "INFO").scalar() or 0

    avg_risk = db.query(func.avg(ScanJobModel.risk_score)).scalar() or 0.0

    recent_jobs = db.query(ScanJobModel).order_by(ScanJobModel.start_time.desc()).limit(5).all()

    return DashboardStatsResponse(
        total_scans=total_scans,
        active_scans_count=active_scans,
        total_findings=total_findings,
        critical_count=crit,
        high_count=high,
        medium_count=med,
        low_count=low,
        info_count=info,
        avg_risk_score=round(float(avg_risk), 1),
        recent_scans=recent_jobs,
    )
