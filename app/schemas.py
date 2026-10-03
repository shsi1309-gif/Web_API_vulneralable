"""
Pydantic API Schemas for Requests and Responses.
"""

from datetime import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from scanner.models import Severity, FindingStatus, ScanStatus, ScanProfile


class ScanLaunchRequest(BaseModel):
    target_url: str = Field(..., example="http://localhost:8888")
    profile: ScanProfile = Field(default=ScanProfile.FULL)
    max_depth: int = Field(default=3, ge=1, le=10)
    max_endpoints: int = Field(default=50, ge=5, le=300)
    concurrency: int = Field(default=10, ge=1, le=50)
    timeout: int = Field(default=10, ge=2, le=60)
    custom_headers: Dict[str, str] = Field(default_factory=dict)
    cookie: Optional[str] = None
    auth_token: Optional[str] = None
    enable_nuclei: bool = True
    nuclei_tags: List[str] = Field(default_factory=list)


class FindingResponse(BaseModel):
    id: str
    scan_id: str
    title: str
    severity: Severity
    category: str
    cwe_id: Optional[str] = None
    cvss_score: float = 5.0
    endpoint: str
    method: str = "GET"
    parameter: Optional[str] = None
    description: str
    evidence: str
    remediation: str
    references: List[str] = Field(default_factory=list)
    request_data: Dict[str, Any] = Field(default_factory=dict)
    response_data: Dict[str, Any] = Field(default_factory=dict)
    status: FindingStatus = FindingStatus.OPEN
    check_source: str = "builtin"
    template_id: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class EndpointResponse(BaseModel):
    id: str
    scan_id: str
    url: str
    method: str = "GET"
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    parameters: List[str] = Field(default_factory=list)
    source: str = "crawler"
    discovered_at: datetime

    class Config:
        from_attributes = True


class ScanJobResponse(BaseModel):
    id: str
    target_url: str
    profile: str
    status: ScanStatus
    progress: int = 0
    current_phase: str = "INITIALIZING"
    start_time: datetime
    end_time: Optional[datetime] = None
    duration_seconds: float = 0.0
    total_endpoints: int = 0
    risk_score: float = 0.0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

    class Config:
        from_attributes = True


class ScanDetailResponse(ScanJobResponse):
    findings: List[FindingResponse] = Field(default_factory=list)
    endpoints: List[EndpointResponse] = Field(default_factory=list)
    log_text: str = ""


class FindingStatusUpdateRequest(BaseModel):
    status: FindingStatus
    notes: Optional[str] = None


class RetestResponse(BaseModel):
    finding_id: str
    still_vulnerable: bool
    old_status: FindingStatus
    new_status: FindingStatus
    evidence: str
    notes: Optional[str] = None
    retested_at: datetime


class DashboardStatsResponse(BaseModel):
    total_scans: int = 0
    active_scans_count: int = 0
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    avg_risk_score: float = 0.0
    recent_scans: List[ScanJobResponse] = Field(default_factory=list)
