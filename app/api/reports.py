"""
Report Export API: Downloads security audit reports in HTML, JSON, Markdown, and CSV formats.
"""

from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import HTMLResponse, PlainTextResponse
from sqlalchemy.orm import Session

from ..database import get_db
from ..services.report_service import report_service

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.get("/{scan_id}/html", response_class=HTMLResponse)
def get_html_report(scan_id: str, db: Session = Depends(get_db)):
    """Renders standalone executive and technical HTML report."""
    try:
        html_content = report_service.generate_html(scan_id, db)
        return HTMLResponse(content=html_content)
    except ValueError:
        raise HTTPException(status_code=404, detail="Scan job not found")


@router.get("/{scan_id}/json")
def get_json_report(scan_id: str, db: Session = Depends(get_db)):
    """Downloads structured vulnerability scan results in JSON format."""
    try:
        return report_service.generate_json(scan_id, db)
    except ValueError:
        raise HTTPException(status_code=404, detail="Scan job not found")


@router.get("/{scan_id}/markdown", response_class=PlainTextResponse)
def get_markdown_report(scan_id: str, db: Session = Depends(get_db)):
    """Downloads vulnerability findings in Markdown / PDF-ready format."""
    try:
        md = report_service.generate_markdown(scan_id, db)
        return PlainTextResponse(content=md, media_type="text/markdown; charset=utf-8")
    except ValueError:
        raise HTTPException(status_code=404, detail="Scan job not found")


@router.get("/{scan_id}/csv")
def get_csv_report(scan_id: str, db: Session = Depends(get_db)):
    """Exports findings as CSV table."""
    try:
        csv_data = report_service.generate_csv(scan_id, db)
        return Response(
            content=csv_data,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=vulnerabilities_{scan_id[:8]}.csv"},
        )
    except ValueError:
        raise HTTPException(status_code=404, detail="Scan job not found")
