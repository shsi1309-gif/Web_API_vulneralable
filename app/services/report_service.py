"""
Report Generation Service: Exports executive and technical vulnerability reports
in standalone HTML, JSON, Markdown, and CSV formats.
"""

import csv
import io
import json
from datetime import datetime
from typing import Dict, Any, List
from jinja2 import Template
from sqlalchemy.orm import Session

from ..models import ScanJobModel, FindingModel, EndpointModel


HTML_REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Audit Report - {{ scan.target_url }}</title>
    <style>
        :root {
            --bg-base: #0B0F19;
            --bg-card: #111827;
            --bg-card-alt: #1F2937;
            --text-main: #F9FAFB;
            --text-muted: #9CA3AF;
            --border-color: #374151;
            --accent-primary: #06B6D4;
            --crit-color: #EF4444;
            --high-color: #F97316;
            --med-color: #FBBF24;
            --low-color: #3B82F6;
            --info-color: #10B981;
        }
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background-color: var(--bg-base);
            color: var(--text-main);
            margin: 0;
            padding: 40px 20px;
            line-height: 1.6;
        }
        .container {
            max-width: 1100px;
            margin: 0 auto;
        }
        .header {
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 24px;
            margin-bottom: 32px;
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            flex-wrap: wrap;
            gap: 16px;
        }
        .logo-title {
            display: flex;
            align-items: center;
            gap: 14px;
        }
        .shield-icon {
            width: 44px;
            height: 44px;
            background: linear-gradient(135deg, #06B6D4, #3B82F6);
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
        }
        h1 { margin: 0; font-size: 26px; font-weight: 800; color: #FFF; }
        .subtitle { color: var(--text-muted); font-size: 14px; margin-top: 4px; }
        .badge-risk {
            padding: 8px 18px;
            border-radius: 9999px;
            font-weight: 700;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .risk-high { background: rgba(239, 68, 68, 0.2); color: #F87171; border: 1px solid #EF4444; }
        .risk-med { background: rgba(245, 158, 11, 0.2); color: #FBBF24; border: 1px solid #F59E0B; }
        .risk-low { background: rgba(16, 185, 129, 0.2); color: #34D399; border: 1px solid #10B981; }

        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 36px;
        }
        .metric-card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 20px;
            text-align: center;
        }
        .metric-val { font-size: 32px; font-weight: 800; margin-top: 4px; }
        .metric-lbl { font-size: 12px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.8px; }

        .crit-text { color: var(--crit-color); }
        .high-text { color: var(--high-color); }
        .med-text { color: var(--med-color); }
        .low-text { color: var(--low-color); }
        .info-text { color: var(--info-color); }

        .section-title {
            font-size: 20px;
            font-weight: 700;
            margin: 40px 0 20px 0;
            display: flex;
            align-items: center;
            gap: 10px;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 10px;
        }
        .finding-card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
        }
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 16px;
            gap: 12px;
        }
        .finding-title { font-size: 18px; font-weight: 700; margin: 0; }
        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
        }
        .badge-CRITICAL { background: #7F1D1D; color: #FCA5A5; }
        .badge-HIGH { background: #7C2D12; color: #FDBA74; }
        .badge-MEDIUM { background: #78350F; color: #FDE68A; }
        .badge-LOW { background: #1E3A8A; color: #93C5FD; }
        .badge-INFO { background: #064E3B; color: #6EE7B7; }

        .finding-meta {
            display: flex;
            flex-wrap: wrap;
            gap: 16px;
            color: var(--text-muted);
            font-size: 13px;
            margin-bottom: 16px;
            background: var(--bg-card-alt);
            padding: 10px 14px;
            border-radius: 8px;
        }
        .code-box {
            background: #030712;
            border: 1px solid #1F2937;
            border-radius: 8px;
            padding: 14px;
            font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
            font-size: 13px;
            color: #E2E8F0;
            overflow-x: auto;
            white-space: pre-wrap;
            margin: 10px 0;
        }
        .remediation-box {
            background: rgba(6, 182, 212, 0.08);
            border-left: 4px solid var(--accent-primary);
            padding: 14px 18px;
            border-radius: 0 8px 8px 0;
            margin-top: 16px;
        }
        .remediation-title { font-weight: 700; color: #38BDF8; margin-bottom: 4px; font-size: 14px; }
        .footer {
            margin-top: 60px;
            text-align: center;
            color: var(--text-muted);
            font-size: 13px;
            border-top: 1px solid var(--border-color);
            padding-top: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo-title">
                <div class="shield-icon">🛡️</div>
                <div>
                    <h1>Automated Security Audit Report</h1>
                    <div class="subtitle">Target: <strong>{{ scan.target_url }}</strong> &bull; Generated: {{ generated_at }}</div>
                </div>
            </div>
            <div>
                <span class="badge-risk {% if scan.risk_score >= 50 %}risk-high{% elif scan.risk_score >= 20 %}risk-med{% else %}risk-low{% endif %}">
                    Risk Score: {{ scan.risk_score }}/100
                </span>
            </div>
        </div>

        <!-- Executive Metrics -->
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-lbl">Total Endpoints</div>
                <div class="metric-val">{{ scan.total_endpoints }}</div>
            </div>
            <div class="metric-card">
                <div class="metric-lbl">Critical Flaws</div>
                <div class="metric-val crit-text">{{ scan.critical_count }}</div>
            </div>
            <div class="metric-card">
                <div class="metric-lbl">High Severity</div>
                <div class="metric-val high-text">{{ scan.high_count }}</div>
            </div>
            <div class="metric-card">
                <div class="metric-lbl">Medium Severity</div>
                <div class="metric-val med-text">{{ scan.medium_count }}</div>
            </div>
            <div class="metric-card">
                <div class="metric-lbl">Low & Info</div>
                <div class="metric-val low-text">{{ scan.low_count + scan.info_count }}</div>
            </div>
        </div>

        <!-- Findings List -->
        <div class="section-title">
            <span>Detailed Vulnerability Findings ({{ findings|length }})</span>
        </div>

        {% if findings %}
            {% for f in findings %}
            <div class="finding-card">
                <div class="finding-header">
                    <div>
                        <h3 class="finding-title">{{ f.title }}</h3>
                    </div>
                    <span class="badge badge-{{ f.severity }}">{{ f.severity }}</span>
                </div>

                <div class="finding-meta">
                    <div><strong>Category:</strong> {{ f.category }}</div>
                    <div><strong>Endpoint:</strong> <code>{{ f.method }} {{ f.endpoint }}</code></div>
                    {% if f.parameter %}<div><strong>Parameter:</strong> <code>{{ f.parameter }}</code></div>{% endif %}
                    {% if f.cwe_id %}<div><strong>CWE:</strong> {{ f.cwe_id }}</div>{% endif %}
                    <div><strong>CVSS v3.1:</strong> {{ f.cvss_score }}</div>
                    <div><strong>Status:</strong> {{ f.status }}</div>
                </div>

                <p><strong>Description:</strong> {{ f.description }}</p>

                <div><strong>Technical Evidence:</strong></div>
                <div class="code-box">{{ f.evidence }}</div>

                <div class="remediation-box">
                    <div class="remediation-title">💡 Remediation & Mitigation Guidance</div>
                    <div>{{ f.remediation }}</div>
                </div>
            </div>
            {% endfor %}
        {% else %}
            <div class="finding-card" style="text-align: center; padding: 40px;">
                <h3>🎉 No security vulnerabilities detected!</h3>
                <p class="subtitle">All automated security checks and Nuclei templates passed successfully.</p>
            </div>
        {% endif %}

        <div class="footer">
            Generated automatically by Antigravity Web & API Vulnerability Scanner &bull; Profile: {{ scan.profile }} &bull; Scan Duration: {{ scan.duration_seconds }}s
        </div>
    </div>
</body>
</html>
"""


class ReportService:
    """Compiles and exports scan results into multiple report formats."""

    def generate_html(self, scan_id: str, db: Session) -> str:
        scan = db.query(ScanJobModel).filter(ScanJobModel.id == scan_id).first()
        if not scan:
            raise ValueError("Scan not found")

        findings = db.query(FindingModel).filter(FindingModel.scan_id == scan_id).order_by(FindingModel.cvss_score.desc()).all()
        template = Template(HTML_REPORT_TEMPLATE)
        return template.render(
            scan=scan,
            findings=findings,
            generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        )

    def generate_json(self, scan_id: str, db: Session) -> Dict[str, Any]:
        scan = db.query(ScanJobModel).filter(ScanJobModel.id == scan_id).first()
        if not scan:
            raise ValueError("Scan not found")

        findings = db.query(FindingModel).filter(FindingModel.scan_id == scan_id).all()
        endpoints = db.query(EndpointModel).filter(EndpointModel.scan_id == scan_id).all()

        return {
            "scan_metadata": {
                "id": scan.id,
                "target_url": scan.target_url,
                "profile": scan.profile,
                "status": scan.status,
                "start_time": scan.start_time.isoformat() if scan.start_time else None,
                "end_time": scan.end_time.isoformat() if scan.end_time else None,
                "duration_seconds": scan.duration_seconds,
                "total_endpoints": scan.total_endpoints,
                "risk_score": scan.risk_score,
                "summary": {
                    "critical": scan.critical_count,
                    "high": scan.high_count,
                    "medium": scan.medium_count,
                    "low": scan.low_count,
                    "info": scan.info_count,
                },
            },
            "findings": [
                {
                    "id": f.id,
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
                    "status": f.status,
                    "check_source": f.check_source,
                    "template_id": f.template_id,
                    "created_at": f.created_at.isoformat() if f.created_at else None,
                }
                for f in findings
            ],
            "discovered_endpoints": [
                {
                    "url": ep.url,
                    "method": ep.method,
                    "status_code": ep.status_code,
                    "content_type": ep.content_type,
                    "parameters": json.loads(ep.parameters_json or "[]"),
                    "source": ep.source,
                }
                for ep in endpoints
            ],
        }

    def generate_markdown(self, scan_id: str, db: Session) -> str:
        scan = db.query(ScanJobModel).filter(ScanJobModel.id == scan_id).first()
        findings = db.query(FindingModel).filter(FindingModel.scan_id == scan_id).order_by(FindingModel.cvss_score.desc()).all()

        lines = [
            f"# Security Audit Report: {scan.target_url}",
            f"**Scan Date:** {scan.start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
            f"**Profile:** {scan.profile} | **Risk Score:** {scan.risk_score}/100 | **Endpoints Audited:** {scan.total_endpoints}  ",
            "",
            "## Executive Summary",
            f"- **Critical:** {scan.critical_count}",
            f"- **High:** {scan.high_count}",
            f"- **Medium:** {scan.medium_count}",
            f"- **Low:** {scan.low_count}",
            f"- **Info:** {scan.info_count}",
            "",
            "## Vulnerability Details",
            "",
        ]

        for idx, f in enumerate(findings, 1):
            lines.extend([
                f"### {idx}. {f.title} [{f.severity}]",
                f"- **Endpoint:** `{f.method} {f.endpoint}`",
                f"- **Parameter:** `{f.parameter or 'N/A'}`",
                f"- **CWE:** {f.cwe_id or 'N/A'} | **CVSS v3.1:** {f.cvss_score}",
                f"- **Status:** `{f.status}`",
                "",
                "**Description:**",
                f.description,
                "",
                "**Technical Evidence:**",
                "```http",
                f.evidence,
                "```",
                "",
                "**Remediation Guidance:**",
                f.remediation,
                "",
                "---",
                "",
            ])

        return "\n".join(lines)

    def generate_csv(self, scan_id: str, db: Session) -> str:
        findings = db.query(FindingModel).filter(FindingModel.scan_id == scan_id).all()
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["ID", "Title", "Severity", "Category", "CWE", "CVSS", "Method", "Endpoint", "Parameter", "Status", "Remediation"])
        for f in findings:
            writer.writerow([f.id, f.title, f.severity, f.category, f.cwe_id or "", f.cvss_score, f.method, f.endpoint, f.parameter or "", f.status, f.remediation])
        return output.getvalue()


report_service = ReportService()
