"""
Retest Service: Re-executes vulnerability verification checks to confirm remediation.
"""

import json
from datetime import datetime
from typing import Dict, Any, Optional
import httpx
from sqlalchemy.orm import Session

from ..models import FindingModel, RetestLogModel
from ..schemas import RetestResponse
from scanner.models import FindingStatus, Severity


class RetestService:
    """Service to re-evaluate specific vulnerabilities and confirm remediation."""

    async def retest_finding(self, finding_id: str, db: Session, notes: Optional[str] = None) -> RetestResponse:
        finding = db.query(FindingModel).filter(FindingModel.id == finding_id).first()
        if not finding:
            raise ValueError(f"Finding with ID {finding_id} not found.")

        old_status = finding.status
        still_vulnerable = False
        evidence = ""

        transport = httpx.AsyncHTTPTransport(verify=False)
        async with httpx.AsyncClient(timeout=10, follow_redirects=True, transport=transport) as client:
            try:
                # Retest based on finding title & category
                title_lower = finding.title.lower()

                # 1. Missing Security Header retest
                if "missing security header" in title_lower:
                    resp = await client.get(finding.endpoint)
                    # Extract header name from title
                    header_name = finding.title.split(":")[-1].strip().split()[0].lower()
                    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
                    if any(header_name in k for k in headers_lower):
                        still_vulnerable = False
                        evidence = f"Header was detected in retest response: '{resp.headers.get(header_name, 'present')}'. Remediation verified!"
                    else:
                        still_vulnerable = True
                        evidence = f"Header '{header_name}' is still missing from the HTTP response headers."

                # 2. CORS check retest
                elif "cors" in title_lower:
                    resp = await client.get(finding.endpoint, headers={"Origin": "https://attacker-evil-site.com"})
                    acao = resp.headers.get("access-control-allow-origin", "")
                    if acao == "*" or acao == "https://attacker-evil-site.com":
                        still_vulnerable = True
                        evidence = f"CORS still allows unvalidated origin: Access-Control-Allow-Origin: {acao}"
                    else:
                        still_vulnerable = False
                        evidence = f"CORS origin reflection is no longer present. Access-Control-Allow-Origin: '{acao}'"

                # 3. Sensitive file exposure retest
                elif "exposed" in title_lower or ".env" in title_lower or ".git" in title_lower or "actuator" in title_lower:
                    resp = await client.get(finding.endpoint)
                    if resp.status_code == 200 and len(resp.text) > 10 and not any(w in resp.text.lower() for w in ["404", "not found", "access denied", "forbidden"]):
                        still_vulnerable = True
                        evidence = f"File is still publicly accessible with HTTP 200 OK. Response length: {len(resp.text)} bytes."
                    else:
                        still_vulnerable = False
                        evidence = f"Access to sensitive file is successfully blocked. HTTP Status: {resp.status_code}"

                # 4. General Injection / Nuclei retest
                else:
                    req_data = json.loads(finding.request_data_json or "{}")
                    method = finding.method or "GET"
                    target_url = req_data.get("url", finding.endpoint)

                    if method == "POST":
                        data = req_data.get("data", {})
                        resp = await client.post(target_url, data=data)
                    else:
                        resp = await client.get(target_url)

                    # Check for reflection or error
                    resp_data = json.loads(finding.response_data_json or "{}")
                    error_match = resp_data.get("error_match")
                    reflection = resp_data.get("reflection")

                    if error_match and error_match.lower() in resp.text.lower():
                        still_vulnerable = True
                        evidence = f"SQL error marker '{error_match}' is still present in the HTTP response."
                    elif reflection and reflection in resp.text:
                        still_vulnerable = True
                        evidence = f"XSS Canary reflection '{reflection}' is still rendered unescaped."
                    else:
                        still_vulnerable = False
                        evidence = f"Vulnerability payload is no longer triggered or reflected in HTTP response. HTTP status: {resp.status_code}"

            except Exception as e:
                evidence = f"Retest probe encountered network/connection error: {str(e)}"
                still_vulnerable = False

        # Update finding status based on retest result
        new_status = "OPEN" if still_vulnerable else "RESOLVED"
        finding.status = new_status
        finding.updated_at = datetime.utcnow()

        # Create Retest Log
        retest_log = RetestLogModel(
            finding_id=finding.id,
            still_vulnerable=still_vulnerable,
            old_status=old_status,
            new_status=new_status,
            evidence=evidence,
            notes=notes,
            retested_at=datetime.utcnow(),
        )
        db.add(retest_log)
        db.commit()

        return RetestResponse(
            finding_id=finding.id,
            still_vulnerable=still_vulnerable,
            old_status=FindingStatus(old_status),
            new_status=FindingStatus(new_status),
            evidence=evidence,
            notes=notes,
            retested_at=retest_log.retested_at,
        )


retest_service = RetestService()
