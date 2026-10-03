"""
Vulnerability Finding API Endpoints: Triage, retesting, and status management.
"""

import json
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import FindingModel, RetestLogModel
from ..schemas import FindingResponse, FindingStatusUpdateRequest, RetestResponse
from ..services.retest_service import retest_service

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerabilities"])


@router.get("", response_model=List[FindingResponse])
def list_vulnerabilities(
    scan_id: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db),
):
    """Lists and filters vulnerability findings across scans."""
    query = db.query(FindingModel)
    if scan_id:
        query = query.filter(FindingModel.scan_id == scan_id)
    if severity:
        query = query.filter(FindingModel.severity == severity.upper())
    if status:
        query = query.filter(FindingModel.status == status.upper())
    if search:
        term = f"%{search}%"
        query = query.filter(
            (FindingModel.title.ilike(term)) | (FindingModel.endpoint.ilike(term)) | (FindingModel.category.ilike(term))
        )

    findings = query.order_by(FindingModel.cvss_score.desc()).offset(offset).limit(limit).all()

    result = []
    for f in findings:
        f_dict = {
            "id": f.id,
            "scan_id": f.scan_id,
            "title": f.title,
            "severity": f.severity,
            "category": f.category,
            "cwe_id": f.cwe_id,
            "cvss_score": f.cvss_score,
            "endpoint": f.endpoint,
            "method": f.method,
            "parameter": f.parameter,
            "description": f.description,
            "evidence": f.evidence,
            "remediation": f.remediation,
            "references": json.loads(f.references_json or "[]"),
            "request_data": json.loads(f.request_data_json or "{}"),
            "response_data": json.loads(f.response_data_json or "{}"),
            "status": f.status,
            "check_source": f.check_source,
            "template_id": f.template_id,
            "created_at": f.created_at,
            "updated_at": f.updated_at,
        }
        result.append(FindingResponse(**f_dict))

    return result


@router.get("/{finding_id}", response_model=FindingResponse)
def get_finding(finding_id: str, db: Session = Depends(get_db)):
    """Retrieves single finding details."""
    f = db.query(FindingModel).filter(FindingModel.id == finding_id).first()
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")

    return FindingResponse(
        id=f.id,
        scan_id=f.scan_id,
        title=f.title,
        severity=f.severity,
        category=f.category,
        cwe_id=f.cwe_id,
        cvss_score=f.cvss_score,
        endpoint=f.endpoint,
        method=f.method,
        parameter=f.parameter,
        description=f.description,
        evidence=f.evidence,
        remediation=f.remediation,
        references=json.loads(f.references_json or "[]"),
        request_data=json.loads(f.request_data_json or "{}"),
        response_data=json.loads(f.response_data_json or "{}"),
        status=f.status,
        check_source=f.check_source,
        template_id=f.template_id,
        created_at=f.created_at,
        updated_at=f.updated_at,
    )


@router.patch("/{finding_id}/status", response_model=FindingResponse)
def update_finding_status(finding_id: str, req: FindingStatusUpdateRequest, db: Session = Depends(get_db)):
    """Updates finding triage status (OPEN, TRIAGED, FALSE_POSITIVE, RESOLVED)."""
    f = db.query(FindingModel).filter(FindingModel.id == finding_id).first()
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")

    f.status = req.status.value
    db.commit()
    db.refresh(f)
    return get_finding(finding_id, db)


@router.post("/{finding_id}/retest", response_model=RetestResponse)
async def retest_finding(finding_id: str, notes: Optional[str] = None, db: Session = Depends(get_db)):
    """Retests the finding against the target endpoint and logs verification results."""
    try:
        res = await retest_service.retest_finding(finding_id, db, notes)
        return res
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Retest failed: {str(e)}")
