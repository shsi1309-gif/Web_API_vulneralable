"""
Scan Service: Manages background execution of security scans,
progress reporting, log streaming, and database persistence.
"""

import json
import asyncio
from datetime import datetime
from typing import Dict, Any, Optional, List
from sqlalchemy.orm import Session

from scanner.engine import ScannerEngine
from scanner.models import ScanConfig, ScanProfile, Finding, CrawlResult, ScanSummary, ScanStatus, FindingStatus
from ..database import SessionLocal
from ..models import ScanJobModel, FindingModel, EndpointModel


class ScanService:
    """Manages active scan lifecycle and background task execution."""

    def __init__(self):
        # Maps scan_id -> ScannerEngine instance
        self.active_engines: Dict[str, ScannerEngine] = {}
        # Maps scan_id -> list of log strings for fast streaming
        self.live_logs: Dict[str, List[str]] = {}

    async def launch_scan(self, config_req: Any, db: Session) -> ScanJobModel:
        """Creates database record and launches background scan task."""
        # Convert request to ScanConfig
        config = ScanConfig(
            target_url=config_req.target_url,
            profile=config_req.profile,
            max_depth=config_req.max_depth,
            max_endpoints=config_req.max_endpoints,
            concurrency=config_req.concurrency,
            timeout=config_req.timeout,
            custom_headers=config_req.custom_headers,
            cookie=config_req.cookie,
            auth_token=config_req.auth_token,
            enable_nuclei=config_req.enable_nuclei,
            nuclei_tags=config_req.nuclei_tags,
        )

        scan_job = ScanJobModel(
            target_url=config.target_url,
            profile=config.profile.value,
            status="RUNNING",
            progress=0,
            current_phase="INITIALIZING",
            start_time=datetime.utcnow(),
            config_json=config.model_dump_json(),
        )
        db.add(scan_job)
        db.commit()
        db.refresh(scan_job)

        scan_id = scan_job.id
        self.live_logs[scan_id] = [f"[{datetime.utcnow().strftime('%H:%M:%S')}] Scan initiated for {config.target_url}"]

        # Launch async task
        asyncio.create_task(self._run_scan_background(scan_id, config))

        return scan_job

    def stop_scan(self, scan_id: str, db: Session) -> bool:
        """Aborts an in-progress scan."""
        if scan_id in self.active_engines:
            self.active_engines[scan_id].stop()
            job = db.query(ScanJobModel).filter(ScanJobModel.id == scan_id).first()
            if job:
                job.status = "STOPPED"
                job.current_phase = "ABORTED_BY_USER"
                db.commit()
            return True
        return False

    def get_live_logs(self, scan_id: str) -> List[str]:
        """Returns recent in-memory log entries."""
        return self.live_logs.get(scan_id, [])

    async def _run_scan_background(self, scan_id: str, config: ScanConfig):
        """Asynchronous worker that executes the scanner engine."""
        db = SessionLocal()

        def log_callback(msg: str):
            timestamp = datetime.utcnow().strftime("%H:%M:%S")
            entry = f"[{timestamp}] {msg}"
            if scan_id in self.live_logs:
                self.live_logs[scan_id].append(entry)
                # Keep last 500 lines in memory
                if len(self.live_logs[scan_id]) > 500:
                    self.live_logs[scan_id].pop(0)

        def progress_callback(percent: int, phase: str, msg: str):
            try:
                job = db.query(ScanJobModel).filter(ScanJobModel.id == scan_id).first()
                if job:
                    job.progress = percent
                    job.current_phase = phase
                    db.commit()
            except Exception:
                pass

        def finding_callback(finding: Finding):
            # Proactively save finding as it is discovered
            try:
                f_model = FindingModel(
                    id=finding.id,
                    scan_id=scan_id,
                    title=finding.title,
                    severity=finding.severity.value,
                    category=finding.category,
                    cwe_id=finding.cwe_id,
                    cvss_score=finding.cvss_score or 5.0,
                    endpoint=finding.endpoint,
                    method=finding.method,
                    parameter=finding.parameter,
                    description=finding.description,
                    evidence=finding.evidence,
                    remediation=finding.remediation,
                    references_json=json.dumps(finding.references),
                    request_data_json=json.dumps(finding.request_data or {}),
                    response_data_json=json.dumps(finding.response_data or {}),
                    status="OPEN",
                    check_source=finding.check_source,
                    template_id=finding.template_id,
                    created_at=datetime.utcnow(),
                )
                db.add(f_model)
                db.commit()
            except Exception:
                db.rollback()

        engine = ScannerEngine(
            config=config,
            progress_cb=progress_callback,
            log_cb=log_callback,
            finding_cb=finding_callback,
        )
        self.active_engines[scan_id] = engine

        try:
            findings, crawl_result, summary = await engine.scan()

            job = db.query(ScanJobModel).filter(ScanJobModel.id == scan_id).first()
            if job:
                # Save discovered endpoints
                for ep in crawl_result.endpoints:
                    ep_model = EndpointModel(
                        scan_id=scan_id,
                        url=ep.url,
                        method=ep.method,
                        status_code=ep.status_code,
                        content_type=ep.content_type,
                        parameters_json=json.dumps(ep.parameters),
                        source=ep.source,
                        discovered_at=datetime.utcnow(),
                    )
                    db.add(ep_model)

                # Update job summary
                job.status = "COMPLETED" if not engine.stop_requested else "STOPPED"
                job.progress = 100
                job.end_time = datetime.utcnow()
                job.duration_seconds = summary.duration_seconds
                job.total_endpoints = len(crawl_result.endpoints)
                job.risk_score = summary.risk_score
                job.critical_count = summary.critical_count
                job.high_count = summary.high_count
                job.medium_count = summary.medium_count
                job.low_count = summary.low_count
                job.info_count = summary.info_count
                job.log_text = "\n".join(self.live_logs.get(scan_id, []))
                db.commit()

        except Exception as e:
            log_callback(f"FATAL ERROR during scan: {str(e)}")
            job = db.query(ScanJobModel).filter(ScanJobModel.id == scan_id).first()
            if job:
                job.status = "FAILED"
                job.current_phase = f"ERROR: {str(e)[:100]}"
                job.end_time = datetime.utcnow()
                job.log_text = "\n".join(self.live_logs.get(scan_id, []))
                db.commit()
        finally:
            self.active_engines.pop(scan_id, None)
            db.close()


scan_service = ScanService()
