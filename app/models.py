"""
SQLAlchemy ORM Models for Scans, Findings, Endpoints, and Retest Logs.
"""

import uuid
from datetime import datetime
from sqlalchemy import (
    Column,
    String,
    Integer,
    Float,
    Text,
    DateTime,
    Boolean,
    ForeignKey,
)
from sqlalchemy.orm import relationship
from .database import Base


class ScanJobModel(Base):
    __tablename__ = "scan_jobs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target_url = Column(String(512), nullable=False)
    profile = Column(String(50), default="FULL")
    status = Column(String(50), default="PENDING")  # PENDING, RUNNING, COMPLETED, FAILED, STOPPED
    progress = Column(Integer, default=0)
    current_phase = Column(String(100), default="INITIALIZING")
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime, nullable=True)
    duration_seconds = Column(Float, default=0.0)

    # Metrics
    total_endpoints = Column(Integer, default=0)
    risk_score = Column(Float, default=0.0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)

    # Logs & Config
    log_text = Column(Text, default="")
    config_json = Column(Text, default="{}")

    # Relationships
    findings = relationship("FindingModel", back_populates="scan", cascade="all, delete-orphan")
    endpoints = relationship("EndpointModel", back_populates="scan", cascade="all, delete-orphan")


class EndpointModel(Base):
    __tablename__ = "discovered_endpoints"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False)
    url = Column(String(1024), nullable=False)
    method = Column(String(20), default="GET")
    status_code = Column(Integer, nullable=True)
    content_type = Column(String(255), nullable=True)
    parameters_json = Column(Text, default="[]")
    source = Column(String(50), default="crawler")
    discovered_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("ScanJobModel", back_populates="endpoints")


class FindingModel(Base):
    __tablename__ = "vulnerability_findings"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False)
    title = Column(String(255), nullable=False)
    severity = Column(String(50), default="MEDIUM")  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category = Column(String(100), default="General")
    cwe_id = Column(String(50), nullable=True)
    cvss_score = Column(Float, default=5.0)
    endpoint = Column(String(1024), nullable=False)
    method = Column(String(20), default="GET")
    parameter = Column(String(255), nullable=True)
    description = Column(Text, nullable=False)
    evidence = Column(Text, nullable=False)
    remediation = Column(Text, nullable=False)
    references_json = Column(Text, default="[]")
    request_data_json = Column(Text, default="{}")
    response_data_json = Column(Text, default="{}")
    status = Column(String(50), default="OPEN")  # OPEN, TRIAGED, FALSE_POSITIVE, RESOLVED
    check_source = Column(String(50), default="builtin")  # builtin, nuclei
    template_id = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    scan = relationship("ScanJobModel", back_populates="findings")
    retest_logs = relationship("RetestLogModel", back_populates="finding", cascade="all, delete-orphan")


class RetestLogModel(Base):
    __tablename__ = "retest_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    finding_id = Column(String(36), ForeignKey("vulnerability_findings.id", ondelete="CASCADE"), nullable=False)
    still_vulnerable = Column(Boolean, default=True)
    old_status = Column(String(50), default="OPEN")
    new_status = Column(String(50), default="OPEN")
    evidence = Column(Text, nullable=False)
    notes = Column(Text, nullable=True)
    retested_at = Column(DateTime, default=datetime.utcnow)

    finding = relationship("FindingModel", back_populates="retest_logs")
