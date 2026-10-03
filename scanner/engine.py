"""
Master Vulnerability Scanner Engine.
Orchestrates Reconnaissance, Built-in Security Checks, Nuclei Template Execution,
Deduplication, Risk Scoring, and Real-time Progress Reporting.
"""

import time
import asyncio
import uuid
import urllib.parse
from datetime import datetime
from typing import List, Dict, Any, Optional, Callable
import httpx

from .models import (
    ScanConfig,
    ScanProfile,
    Finding,
    CrawlResult,
    ScanSummary,
    Severity,
    FindingStatus,
    EndpointItem,
)
from .crawler import Crawler
from .checks.headers import SecurityHeadersCheck
from .checks.sensitive_files import SensitiveFilesCheck
from .checks.injection_sqli import SQLInjectionCheck
from .checks.injection_xss import XSSInjectionCheck
from .checks.open_redirect import OpenRedirectCheck
from .checks.path_traversal import PathTraversalCheck
from .checks.api_security import APISecurityCheck
from nuclei.runner import NucleiRunner


class ScannerEngine:
    """Master Security Audit & Vulnerability Scanner Engine."""

    def __init__(
        self,
        config: ScanConfig,
        progress_cb: Optional[Callable[[int, str, str], None]] = None,
        log_cb: Optional[Callable[[str], None]] = None,
        finding_cb: Optional[Callable[[Finding], None]] = None,
    ):
        self.config = config
        self.progress_cb = progress_cb or (lambda pct, phase, msg: None)
        self.log_cb = log_cb or (lambda msg: None)
        self.finding_cb = finding_cb or (lambda finding: None)
        self.crawler = Crawler(config, self.log_cb)
        self.nuclei_runner = NucleiRunner(log_cb=self.log_cb)
        self.stop_requested = False

    def stop(self):
        """Signals the engine to abort the active scan."""
        self.stop_requested = True
        self.log_cb("[Scanner Engine] Stop requested by user.")

    async def scan(self) -> (List[Finding], CrawlResult, ScanSummary):
        start_time = time.time()
        self.progress_cb(5, "INITIALIZATION", f"Validating target: {self.config.target_url}")
        self.log_cb(f"Starting Scan Profile '{self.config.profile}' on {self.config.target_url}")

        # 1. Target Reachability Check
        transport = httpx.AsyncHTTPTransport(verify=False)
        async with httpx.AsyncClient(timeout=self.config.timeout, follow_redirects=True, transport=transport) as client:
            try:
                test_resp = await client.get(self.config.target_url)
                self.log_cb(f"Target reachable (HTTP {test_resp.status_code}). Server: {test_resp.headers.get('Server', 'Unknown')}")
            except Exception as e:
                self.log_cb(f"Target reachability warning: {e}. Proceeding with scan...")

            # 2. Reconnaissance & Crawling Phase
            self.progress_cb(15, "RECONNAISSANCE", "Crawling web pages and discovering API endpoints...")
            crawl_result = await self.crawler.crawl()
            self.log_cb(f"Recon completed: {len(crawl_result.endpoints)} endpoints, {len(crawl_result.forms)} forms discovered.")

            if self.stop_requested:
                return [], crawl_result, ScanSummary()

            if self.config.profile == ScanProfile.RECON_ONLY:
                summary = self._calculate_summary([], len(crawl_result.endpoints), time.time() - start_time)
                self.progress_cb(100, "COMPLETED", "Reconnaissance complete.")
                return [], crawl_result, summary

            # 3. Security Audits & Vulnerability Checks
            all_findings: List[Finding] = []

            # Determine checks to run based on profile
            checks_to_run = self._select_checks(self.config.profile)
            total_checks = len(checks_to_run)

            for idx, check_cls in enumerate(checks_to_run):
                if self.stop_requested:
                    break

                check_instance = check_cls(self.config, self.log_cb)
                pct = 25 + int((idx / max(total_checks, 1)) * 50)
                self.progress_cb(pct, "VULNERABILITY_AUDIT", f"Running check: {check_instance.name}")

                try:
                    findings = await check_instance.run(client, crawl_result)
                    for f in findings:
                        all_findings.append(f)
                        self.finding_cb(f)
                except Exception as e:
                    self.log_cb(f"Error during check {check_cls.__name__}: {e}")

            # 4. Nuclei Templates Execution (if enabled or profile is NUCLEI_ONLY / FULL)
            if not self.stop_requested and (self.config.enable_nuclei or self.config.profile == ScanProfile.NUCLEI_ONLY):
                self.progress_cb(80, "NUCLEI_TEMPLATES", "Executing reusable Nuclei YAML security templates...")
                try:
                    nuclei_findings = await self.nuclei_runner.scan(self.config.target_url, self.config)
                    for nf in nuclei_findings:
                        all_findings.append(nf)
                        self.finding_cb(nf)
                except Exception as e:
                    self.log_cb(f"Error executing Nuclei templates: {e}")

        # 5. Deduplicate and finalize
        self.progress_cb(95, "FINALIZING", "Deduplicating findings and calculating CVSS risk metrics...")
        deduped_findings = self._deduplicate_findings(all_findings)
        duration = time.time() - start_time
        summary = self._calculate_summary(deduped_findings, len(crawl_result.endpoints), duration)

        self.progress_cb(100, "COMPLETED", f"Scan complete. Found {len(deduped_findings)} vulnerabilities across {len(crawl_result.endpoints)} endpoints.")
        self.log_cb(
            f"Audit finished in {duration:.1f}s. Findings: Critical={summary.critical_count}, "
            f"High={summary.high_count}, Medium={summary.medium_count}, Low={summary.low_count}, Info={summary.info_count}. "
            f"Overall Risk Score: {summary.risk_score}/100"
        )

        return deduped_findings, crawl_result, summary

    def _select_checks(self, profile: ScanProfile) -> list:
        if profile == ScanProfile.QUICK_HEADERS:
            return [SecurityHeadersCheck]
        elif profile == ScanProfile.OWASP_TOP_10:
            return [
                SecurityHeadersCheck,
                SensitiveFilesCheck,
                SQLInjectionCheck,
                XSSInjectionCheck,
                OpenRedirectCheck,
                PathTraversalCheck,
            ]
        elif profile == ScanProfile.API_SECURITY:
            return [
                SecurityHeadersCheck,
                SensitiveFilesCheck,
                APISecurityCheck,
                SQLInjectionCheck,
            ]
        elif profile == ScanProfile.NUCLEI_ONLY:
            return []
        else:  # FULL
            return [
                SecurityHeadersCheck,
                SensitiveFilesCheck,
                SQLInjectionCheck,
                XSSInjectionCheck,
                OpenRedirectCheck,
                PathTraversalCheck,
                APISecurityCheck,
            ]

    def _deduplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        seen = set()
        unique = []
        for f in findings:
            key = f"{f.title}:{f.endpoint}:{f.parameter or ''}"
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def _calculate_summary(self, findings: List[Finding], endpoints_count: int, duration: float) -> ScanSummary:
        crit = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in findings if f.severity == Severity.HIGH)
        med = sum(1 for f in findings if f.severity == Severity.MEDIUM)
        low = sum(1 for f in findings if f.severity == Severity.LOW)
        info = sum(1 for f in findings if f.severity == Severity.INFO)

        # Risk score calculation: weighted sum capped at 100
        raw_score = (crit * 30.0) + (high * 15.0) + (med * 6.0) + (low * 2.0)
        risk_score = min(100.0, round(raw_score, 1))

        return ScanSummary(
            total_endpoints_tested=endpoints_count,
            total_findings=len(findings),
            critical_count=crit,
            high_count=high,
            medium_count=med,
            low_count=low,
            info_count=info,
            risk_score=risk_score,
            duration_seconds=round(duration, 2),
        )
