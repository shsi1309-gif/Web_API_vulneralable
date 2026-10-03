"""
Base Check class for all built-in vulnerability security checks.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, Callable
import uuid
import httpx

from ..models import Finding, Severity, FindingStatus, CrawlResult, ScanConfig


class BaseCheck(ABC):
    """Abstract Base Class for a security audit check."""

    name: str = "Base Check"
    category: str = "General"
    description: str = "Abstract check description"
    cwe_id: Optional[str] = None
    default_severity: Severity = Severity.MEDIUM

    def __init__(self, config: ScanConfig, log_cb: Optional[Callable[[str], None]] = None):
        self.config = config
        self.log_cb = log_cb or (lambda msg: None)

    def _log(self, msg: str):
        self.log_cb(f"[{self.name}] {msg}")

    @abstractmethod
    async def run(self, client: httpx.AsyncClient, crawl_result: CrawlResult) -> List[Finding]:
        """Execute the security check and return any identified vulnerabilities."""
        pass

    def create_finding(
        self,
        title: str,
        endpoint: str,
        severity: Severity,
        description: str,
        evidence: str,
        remediation: str,
        method: str = "GET",
        parameter: Optional[str] = None,
        cvss_score: float = 5.0,
        cwe_id: Optional[str] = None,
        references: Optional[List[str]] = None,
        request_data: Optional[Dict[str, Any]] = None,
        response_data: Optional[Dict[str, Any]] = None,
    ) -> Finding:
        """Helper to create a structured Finding instance."""
        return Finding(
            id=str(uuid.uuid4()),
            title=title,
            severity=severity,
            category=self.category,
            cwe_id=cwe_id or self.cwe_id,
            cvss_score=cvss_score,
            endpoint=endpoint,
            method=method.upper(),
            parameter=parameter,
            description=description,
            evidence=evidence,
            request_data=request_data or {},
            response_data=response_data or {},
            remediation=remediation,
            references=references or [],
            status=FindingStatus.OPEN,
            check_source="builtin",
        )
