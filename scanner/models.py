"""
Data models and enumerations for the Vulnerability Scanner.
"""

from enum import Enum
from typing import List, Dict, Any, Optional
from datetime import datetime
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingStatus(str, Enum):
    OPEN = "OPEN"
    TRIAGED = "TRIAGED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    RESOLVED = "RESOLVED"


class ScanStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    STOPPED = "STOPPED"


class ScanProfile(str, Enum):
    FULL = "FULL"                    # Full Recon + OWASP Top 10 + API Checks + Nuclei Templates
    OWASP_TOP_10 = "OWASP_TOP_10"    # Web Vulnerabilities (SQLi, XSS, SSRF, Headers, Traversal)
    API_SECURITY = "API_SECURITY"    # REST API & GraphQL (BOLA, JWT, Secrets, Mass Assign, PII)
    NUCLEI_ONLY = "NUCLEI_ONLY"      # Nuclei Template Runner only
    QUICK_HEADERS = "QUICK_HEADERS"  # Fast SSL, Headers, CORS, Banner audit
    RECON_ONLY = "RECON_ONLY"        # Crawler, Endpoint discovery, JS secret scraping only


class EndpointItem(BaseModel):
    url: str
    method: str = "GET"
    content_type: Optional[str] = None
    status_code: Optional[int] = None
    parameters: List[str] = Field(default_factory=list)
    source: str = "crawler"  # crawler, openapi, robots, js_scraper, form
    discovered_at: datetime = Field(default_factory=datetime.utcnow)


class Finding(BaseModel):
    id: Optional[str] = None
    title: str
    severity: Severity
    category: str
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = 0.0
    endpoint: str
    method: str = "GET"
    parameter: Optional[str] = None
    description: str
    evidence: str
    request_data: Optional[Dict[str, Any]] = None
    response_data: Optional[Dict[str, Any]] = None
    remediation: str
    references: List[str] = Field(default_factory=list)
    status: FindingStatus = FindingStatus.OPEN
    check_source: str = "builtin"  # "builtin" or "nuclei"
    template_id: Optional[str] = None
    discovered_at: datetime = Field(default_factory=datetime.utcnow)


class CrawlResult(BaseModel):
    target_url: str
    endpoints: List[EndpointItem] = Field(default_factory=list)
    discovered_urls: List[str] = Field(default_factory=list)
    forms: List[Dict[str, Any]] = Field(default_factory=list)
    js_files: List[str] = Field(default_factory=list)
    api_specs: List[Dict[str, Any]] = Field(default_factory=list)
    secrets_leaked: List[Dict[str, Any]] = Field(default_factory=list)


class ScanConfig(BaseModel):
    target_url: str
    profile: ScanProfile = ScanProfile.FULL
    max_depth: int = 3
    max_endpoints: int = 50
    concurrency: int = 10
    timeout: int = 10
    user_agent: str = "Antigravity-SecScanner/1.0 (+https://antigravity-scanner.local)"
    custom_headers: Dict[str, str] = Field(default_factory=dict)
    cookie: Optional[str] = None
    auth_token: Optional[str] = None
    enable_nuclei: bool = True
    nuclei_tags: List[str] = Field(default_factory=list)


class ScanSummary(BaseModel):
    total_endpoints_tested: int = 0
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    risk_score: float = 0.0  # 0 to 100
    duration_seconds: float = 0.0


class RetestResult(BaseModel):
    vulnerability_id: str
    still_vulnerable: bool
    status: FindingStatus
    new_evidence: str
    retested_at: datetime = Field(default_factory=datetime.utcnow)
    notes: Optional[str] = None
