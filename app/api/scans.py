"""
Scan API Endpoints: Launch, monitor, stop, and retrieve security scans.
"""

import json
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import ScanJobModel, FindingModel, EndpointModel
from ..schemas import ScanLaunchRequest, ScanJobResponse, ScanDetailResponse, FindingResponse, EndpointResponse
from ..services.scan_service import scan_service

router = APIRouter(prefix="/scans", tags=["Scans"])


@router.post("", response_model=ScanJobResponse)
async def launch_scan(req: ScanLaunchRequest, db: Session = Depends(get_db)):
    """Launches an automated security scan in the background."""
    if not req.target_url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="Target URL must start with http:// or https://")
    job = await scan_service.launch_scan(req, db)
    return job


@router.get("", response_model=List[ScanJobResponse])
def list_scans(limit: int = 50, offset: int = 0, db: Session = Depends(get_db)):
    """Retrieves all scan jobs ordered by start date."""
    jobs = db.query(ScanJobModel).order_by(ScanJobModel.start_time.desc()).offset(offset).limit(limit).all()
    return jobs


@router.get("/{scan_id}", response_model=ScanDetailResponse)
def get_scan_details(scan_id: str, db: Session = Depends(get_db)):
    """Returns detailed scan information including findings and endpoints."""
    job = db.query(ScanJobModel).filter(ScanJobModel.id == scan_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")

    findings = db.query(FindingModel).filter(FindingModel.scan_id == scan_id).order_by(FindingModel.cvss_score.desc()).all()
    endpoints = db.query(EndpointModel).filter(EndpointModel.scan_id == scan_id).all()

    # Format findings
    finding_objs = []
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
        finding_objs.append(FindingResponse(**f_dict))

    endpoint_objs = []
    for ep in endpoints:
        ep_dict = {
            "id": ep.id,
            "scan_id": ep.scan_id,
            "url": ep.url,
            "method": ep.method,
            "status_code": ep.status_code,
            "content_type": ep.content_type,
            "parameters": json.loads(ep.parameters_json or "[]"),
            "source": ep.source,
            "discovered_at": ep.discovered_at,
        }
        endpoint_objs.append(EndpointResponse(**ep_dict))

    # Real-time logs if active or stored log
    current_logs = "\n".join(scan_service.get_live_logs(scan_id)) if job.status == "RUNNING" else job.log_text

    return ScanDetailResponse(
        id=job.id,
        target_url=job.target_url,
        profile=job.profile,
        status=job.status,
        progress=job.progress,
        current_phase=job.current_phase,
        start_time=job.start_time,
        end_time=job.end_time,
        duration_seconds=job.duration_seconds,
        total_endpoints=job.total_endpoints,
        risk_score=job.risk_score,
        critical_count=job.critical_count,
        high_count=job.high_count,
        medium_count=job.medium_count,
        low_count=job.low_count,
        info_count=job.info_count,
        findings=finding_objs,
        endpoints=endpoint_objs,
        log_text=current_logs or "",
    )


@router.post("/{scan_id}/stop")
def stop_scan(scan_id: str, db: Session = Depends(get_db)):
    """Aborts a currently executing scan."""
    success = scan_service.stop_scan(scan_id, db)
    if not success:
        raise HTTPException(status_code=400, detail="Scan is not currently running or not found")
    return {"message": "Scan stop signal sent successfully"}


@router.delete("/{scan_id}")
def delete_scan(scan_id: str, db: Session = Depends(get_db)):
    """Deletes a scan job and its associated data."""
    job = db.query(ScanJobModel).filter(ScanJobModel.id == scan_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    db.delete(job)
    db.commit()
    return {"message": "Scan job deleted successfully"}


@router.get("/{scan_id}/logs")
def get_scan_logs(scan_id: str, db: Session = Depends(get_db)):
    """Returns streaming or stored logs for a scan."""
    live = scan_service.get_live_logs(scan_id)
    if live:
        return {"logs": live}
    job = db.query(ScanJobModel).filter(ScanJobModel.id == scan_id).first()
    if job and job.log_text:
        return {"logs": job.log_text.splitlines()}
    return {"logs": []}
