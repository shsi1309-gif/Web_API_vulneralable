"""
End-to-End Test Suite for Automated Web & API Vulnerability Scanner.
"""

import asyncio
import json
from pathlib import Path
from sqlalchemy.orm import Session

from app.database import SessionLocal, init_db
from app.models import ScanJobModel, FindingModel, EndpointModel
from app.schemas import ScanLaunchRequest, FindingStatusUpdateRequest
from app.services.scan_service import scan_service
from app.services.retest_service import retest_service
from app.services.report_service import report_service
from nuclei.runner import NucleiRunner
from scanner.models import ScanConfig, ScanProfile


def test_database_init():
    init_db()
    db = SessionLocal()
    assert db is not None
    db.close()
    print("✅ Database initialization: PASSED")


def test_nuclei_template_loading():
    runner = NucleiRunner()
    templates = runner.list_templates()
    assert len(templates) >= 8, f"Expected at least 8 templates, found {len(templates)}"
    print(f"✅ Nuclei Templates: PASSED ({len(templates)} templates loaded)")


async def test_full_scan_execution():
    db = SessionLocal()
    req = ScanLaunchRequest(
        target_url="http://127.0.0.1:8888",
        profile=ScanProfile.FULL,
        max_depth=2,
        max_endpoints=20,
    )
    job = await scan_service.launch_scan(req, db)
    assert job.id is not None
    assert job.status == "RUNNING"

    # Wait for scan completion
    for _ in range(30):
        await asyncio.sleep(0.5)
        db.refresh(job)
        if job.status in ["COMPLETED", "FAILED"]:
            break

    assert job.status == "COMPLETED", f"Scan status was {job.status}"
    assert job.total_endpoints > 0, "No endpoints discovered"
    assert job.risk_score > 0, "Risk score should be > 0 on vulnerable target"
    assert job.critical_count > 0, "Critical findings expected on vulnerable target"

    findings = db.query(FindingModel).filter(FindingModel.scan_id == job.id).all()
    assert len(findings) > 0, "No findings saved in database"

    # Test Retesting
    first_finding = findings[0]
    retest_res = await retest_service.retest_finding(first_finding.id, db)
    assert retest_res.finding_id == first_finding.id

    # Test Reports
    html_rep = report_service.generate_html(job.id, db)
    assert "Security Audit Report" in html_rep
    assert "http://127.0.0.1:8888" in html_rep

    json_rep = report_service.generate_json(job.id, db)
    assert json_rep["scan_metadata"]["id"] == job.id

    md_rep = report_service.generate_markdown(job.id, db)
    assert "# Security Audit Report" in md_rep

    csv_rep = report_service.generate_csv(job.id, db)
    assert "Title,Severity,Category" in csv_rep

    db.close()
    print(f"✅ Full Scan & Report Pipeline: PASSED (Found {len(findings)} findings on {job.total_endpoints} endpoints)")


def main():
    print("=" * 60)
    print("🚀 Running Vulnerability Scanner Test Suite...")
    print("=" * 60)
    test_database_init()
    test_nuclei_template_loading()
    asyncio.run(test_full_scan_execution())
    print("=" * 60)
    print("🎉 ALL TESTS PASSED SUCCESSFULLY!")
    print("=" * 60)


if __name__ == "__main__":
    main()
