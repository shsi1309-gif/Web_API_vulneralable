"""
OWASP API Security Top 10 Checks:
- BOLA / IDOR (Broken Object Level Authorization)
- Broken Authentication & JWT 'none' Algorithm
- Excessive Data Exposure & PII Leakage
- Lack of Rate Limiting
- Verbose API Stack Traces & Debug Error Leaks
"""

import base64
import json
import re
import urllib.parse
from typing import List, Dict, Any, Tuple
import httpx
from ..models import Finding, Severity, CrawlResult, EndpointItem
from .base import BaseCheck


class APISecurityCheck(BaseCheck):
    name = "OWASP API Security Top 10 Checks"
    category = "API Security"
    cwe_id = "CWE-284"

    # Regex patterns for PII & Secrets in JSON
    PII_PATTERNS = [
        ("Credit Card Number", re.compile(r"""\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"""), Severity.CRITICAL, 8.8),
        ("Social Security Number (SSN)", re.compile(r"""\b\d{3}-\d{2}-\d{4}\b"""), Severity.CRITICAL, 8.8),
        ("Plaintext Password Field", re.compile(r'''"(?:password|passwd|pwd|secret_key|private_key)"\s*:\s*"([^"]+)"''', re.IGNORECASE), Severity.HIGH, 7.5),
        ("Password Hash (Bcrypt/MD5/SHA)", re.compile(r'''\$(?:2a|2b|2y)\$[0-9]{2}\$[a-zA-Z0-9./]{53}|[a-f0-9]{32}|[a-f0-9]{64}'''), Severity.HIGH, 7.0),
    ]

    # Stack trace signatures
    STACK_TRACE_PATTERNS = [
        ("Python Traceback", re.compile(r"Traceback \(most recent call last\):")),
        ("Java Stacktrace", re.compile(r"(?:java\.lang\.|org\.springframework\.|javax\.servlet\.)[\w\.]*Exception")),
        ("Node.js / Express Error", re.compile(r"TypeError:.*?\n\s+at\s+")),
        ("PHP Fatal Error", re.compile(r"Fatal error:.*?\bon line\b")),
    ]

    async def run(self, client: httpx.AsyncClient, crawl_result: CrawlResult) -> List[Finding]:
        findings: List[Finding] = []
        self._log(f"Auditing REST & GraphQL APIs for OWASP API Security Top 10 risks")

        api_endpoints = [ep for ep in crawl_result.endpoints if "/api" in ep.url.lower() or ep.source in ["openapi", "graphql", "api_json"]]
        # If no explicit api endpoints, audit all endpoints
        if not api_endpoints:
            api_endpoints = crawl_result.endpoints[:15]

        # 1. Check Excessive Data Exposure / PII in API Responses
        pii_findings = await self._check_data_exposure(client, api_endpoints)
        findings.extend(pii_findings)

        # 2. Check BOLA / IDOR (Broken Object Level Authorization)
        bola_findings = await self._check_bola(client, api_endpoints)
        findings.extend(bola_findings)

        # 3. Check JWT 'none' algorithm bypass
        jwt_findings = await self._check_jwt_none(client, api_endpoints)
        findings.extend(jwt_findings)

        # 4. Check Rate Limiting on API endpoints
        ratelimit_findings = await self._check_rate_limiting(client, api_endpoints)
        findings.extend(ratelimit_findings)

        # 5. Check Verbose Error / Stack Trace Disclosure on Bad Input
        debug_findings = await self._check_stack_trace_leak(client, api_endpoints)
        findings.extend(debug_findings)

        return findings

    async def _check_data_exposure(self, client: httpx.AsyncClient, endpoints: List[EndpointItem]) -> List[Finding]:
        findings = []
        for ep in endpoints:
            try:
                resp = await client.get(ep.url)
                if resp.status_code == 200:
                    text = resp.text
                    for pii_name, pattern, sev, cvss in self.PII_PATTERNS:
                        m = pattern.search(text)
                        if m:
                            matched = m.group(0)
                            evidence = f"API endpoint '{ep.url}' returned response body containing sensitive pattern: {pii_name}\nSnippet: {matched[:40]}..."
                            findings.append(
                                self.create_finding(
                                    title=f"API3: Excessive Data Exposure ({pii_name})",
                                    endpoint=ep.url,
                                    severity=sev,
                                    description=f"The API endpoint exposes sensitive data ({pii_name}) directly in its HTTP response body, allowing unauthorized data harvesting.",
                                    evidence=evidence,
                                    remediation="Implement response data filtering (Data Transfer Objects / Pydantic schemas) to ensure only required, non-sensitive fields are returned to clients.",
                                    cvss_score=cvss,
                                    cwe_id="CWE-200",
                                    references=["https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"],
                                    response_data={"snippet": matched[:40]},
                                )
                            )
            except Exception:
                pass
        return findings

    async def _check_bola(self, client: httpx.AsyncClient, endpoints: List[EndpointItem]) -> List[Finding]:
        """Probes for numeric ID parameters in REST URL paths or query params (IDOR/BOLA)."""
        findings = []
        # Find paths with digits e.g. /api/users/1
        id_pattern = re.compile(r"(\b\d+\b)")

        for ep in endpoints:
            parsed = urllib.parse.urlparse(ep.url)
            m = id_pattern.search(parsed.path)
            if m:
                original_id = m.group(1)
                # Test with another ID (e.g. 2, 9999)
                new_id = "2" if original_id != "2" else "3"
                mutated_path = id_pattern.sub(new_id, parsed.path, count=1)
                test_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, mutated_path, parsed.params, parsed.query, ""))

                try:
                    resp_orig = await client.get(ep.url)
                    resp_test = await client.get(test_url)

                    # If mutated returns 200 and different valid JSON data without auth check
                    if resp_test.status_code == 200 and resp_orig.status_code == 200:
                        if resp_test.text != resp_orig.text and len(resp_test.text) > 20:
                            evidence = (
                                f"Potential BOLA / IDOR vulnerability on endpoint:\n"
                                f"Original: {ep.url} -> HTTP 200\n"
                                f"Mutated Object ID: {test_url} -> HTTP 200\n"
                                f"Response preview:\n{resp_test.text[:200]}"
                            )
                            findings.append(
                                self.create_finding(
                                    title="API1: Broken Object Level Authorization (BOLA / IDOR)",
                                    endpoint=ep.url,
                                    severity=Severity.HIGH,
                                    description="The API allows accessing object records across different IDs without validating user authorization or tenant ownership.",
                                    evidence=evidence,
                                    remediation="Implement authorization checks verifying that the currently logged-in user has permission to read or manipulate the requested object ID.",
                                    cvss_score=8.1,
                                    cwe_id="CWE-639",
                                    references=["https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"],
                                )
                            )
                            break
                except Exception:
                    pass
        return findings

    async def _check_jwt_none(self, client: httpx.AsyncClient, endpoints: List[EndpointItem]) -> List[Finding]:
        """Tests if API accepts JWT tokens with alg 'none' or missing signature."""
        findings = []
        # Craft an unsigned JWT with alg: none
        header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
        payload = base64.urlsafe_b64encode(b'{"user":"admin","role":"admin","sub":"1","iat":1700000000}').decode().rstrip("=")
        jwt_none_token = f"{header}.{payload}."

        for ep in endpoints[:5]:
            try:
                resp = await client.get(ep.url, headers={"Authorization": f"Bearer {jwt_none_token}"})
                if resp.status_code == 200 and ("admin" in resp.text.lower() or "success" in resp.text.lower()):
                    evidence = (
                        f"JWT 'none' algorithm accepted on endpoint {ep.url}:\n"
                        f"Authorization: Bearer {jwt_none_token}\n"
                        f"HTTP Response: {resp.status_code}\n"
                        f"Body: {resp.text[:200]}"
                    )
                    findings.append(
                        self.create_finding(
                            title="API2: Broken Authentication - JWT 'none' Algorithm Accepted",
                            endpoint=ep.url,
                            severity=Severity.CRITICAL,
                            description="The API server accepts unsigned JSON Web Tokens (JWT) configured with the 'none' algorithm, permitting full authentication bypass.",
                            evidence=evidence,
                            remediation="Reject any JWTs with 'alg: none' and enforce strict signature verification using secure cryptographic algorithms (e.g. RS256, EdDSA, HS256).",
                            cvss_score=9.8,
                            cwe_id="CWE-287",
                            references=["https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"],
                        )
                    )
                    break
            except Exception:
                pass
        return findings

    async def _check_rate_limiting(self, client: httpx.AsyncClient, endpoints: List[EndpointItem]) -> List[Finding]:
        """Sends a rapid burst of requests to identify lack of rate limiting."""
        findings = []
        target_ep = endpoints[0] if endpoints else None
        if not target_ep:
            return findings

        try:
            responses = []
            for _ in range(12):
                r = await client.get(target_ep.url)
                responses.append(r)

            statuses = [r.status_code for r in responses]
            has_429 = 429 in statuses
            has_ratelimit_header = any(
                "x-ratelimit" in k.lower() or "ratelimit" in k.lower() or "retry-after" in k.lower()
                for k in responses[-1].headers.keys()
            )

            if not has_429 and not has_ratelimit_header and all(s == 200 for s in statuses):
                evidence = (
                    f"Sent 12 rapid consecutive requests to '{target_ep.url}'.\n"
                    f"All 12 requests returned HTTP 200 OK without rate-limiting headers or HTTP 429 status."
                )
                findings.append(
                    self.create_finding(
                        title="API4: Unrestricted Resource Consumption (Missing Rate Limiting)",
                        endpoint=target_ep.url,
                        severity=Severity.LOW,
                        description="The API endpoint lacks rate limiting or request throttling, leaving it vulnerable to Denial of Service (DoS) and brute force attacks.",
                        evidence=evidence,
                        remediation="Implement rate limiting (e.g., token bucket, redis-based rate limiting) and return HTTP 429 Too Many Requests with standard Retry-After headers.",
                        cvss_score=4.0,
                        cwe_id="CWE-770",
                        references=["https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/"],
                    )
                )
        except Exception:
            pass
        return findings

    async def _check_stack_trace_leak(self, client: httpx.AsyncClient, endpoints: List[EndpointItem]) -> List[Finding]:
        """Sends malformed JSON to API endpoints to test for verbose error stack traces."""
        findings = []
        for ep in endpoints[:5]:
            try:
                # Send invalid JSON
                resp = await client.post(ep.url, content="{'invalid_json': true", headers={"Content-Type": "application/json"})
                for trace_name, pattern in self.STACK_TRACE_PATTERNS:
                    m = pattern.search(resp.text)
                    if m:
                        matched = m.group(0)
                        evidence = (
                            f"Detailed stack trace leaked upon sending malformed JSON payload:\n"
                            f"Endpoint: POST {ep.url}\n"
                            f"Pattern Match: {trace_name} -> '{matched}'\n"
                            f"Response snippet:\n{resp.text[:300]}"
                        )
                        findings.append(
                            self.create_finding(
                                title=f"API7: Security Misconfiguration - Verbose Error / {trace_name} Leaked",
                                endpoint=ep.url,
                                severity=Severity.MEDIUM,
                                description=f"The API exposes internal stack traces and debugging information ({trace_name}) in response to invalid input, disclosing server internals and file paths.",
                                evidence=evidence,
                                remediation="Disable debug mode in production and implement a global exception handler that returns generic error responses with unique correlation IDs.",
                                cvss_score=5.3,
                                cwe_id="CWE-209",
                                references=["https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/"],
                            )
                        )
                        break
            except Exception:
                pass
        return findings
