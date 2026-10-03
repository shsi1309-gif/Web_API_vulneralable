"""
Cross-Site Scripting (XSS) Vulnerability Check.
Detects Reflected XSS vulnerabilities across GET parameters and POST forms using contextual canary payloads.
"""

import re
import uuid
import urllib.parse
from typing import List, Dict, Any, Tuple
import httpx
from ..models import Finding, Severity, CrawlResult
from .base import BaseCheck


class XSSInjectionCheck(BaseCheck):
    name = "Cross-Site Scripting (Reflected XSS)"
    category = "A03:2021-Injection"
    cwe_id = "CWE-79"

    PAYLOAD_TEMPLATES = [
        ("<script>alert('{canary}')</script>", "<script>alert('{canary}')</script>", "Direct Script Tag Injection"),
        ("\"><script>alert('{canary}')</script>", "<script>alert('{canary}')</script>", "Attribute Breakout Script Injection"),
        ("\"><img src=x onerror=alert('{canary}')>", "<img src=x onerror=alert('{canary}')>", "Image onerror Event Injection"),
        ("';alert('{canary}');//", "alert('{canary}')", "JavaScript Context Breakout"),
        ("<svg/onload=alert('{canary}')>", "<svg/onload=alert('{canary}')>", "SVG Tag OnLoad Injection"),
    ]

    async def run(self, client: httpx.AsyncClient, crawl_result: CrawlResult) -> List[Finding]:
        findings: List[Finding] = []
        tested_keys = set()

        self._log(f"Testing for Reflected XSS across {len(crawl_result.endpoints)} endpoints")

        for ep in crawl_result.endpoints:
            # 1. Test Query Parameters on GET
            parsed = urllib.parse.urlparse(ep.url)
            if parsed.query:
                qs = urllib.parse.parse_qs(parsed.query)
                for param_name, param_vals in qs.items():
                    key = f"GET:{parsed.path}:{param_name}"
                    if key in tested_keys:
                        continue
                    tested_keys.add(key)

                    f = await self._test_get_xss(client, ep.url, param_name)
                    if f:
                        findings.append(f)

            # 2. Test Form Fields
            for form in crawl_result.forms:
                form_action = form.get("action", ep.url)
                form_method = form.get("method", "POST").upper()
                for param in form.get("parameters", []):
                    key = f"{form_method}:{form_action}:{param}"
                    if key in tested_keys:
                        continue
                    tested_keys.add(key)

                    f = await self._test_form_xss(client, form_action, form_method, param, form.get("parameters", []))
                    if f:
                        findings.append(f)

        return findings

    async def _test_get_xss(self, client: httpx.AsyncClient, base_url: str, param_name: str) -> Finding | None:
        parsed = urllib.parse.urlparse(base_url)
        qs = urllib.parse.parse_qs(parsed.query)

        for raw_payload_tmpl, expected_reflection_tmpl, desc in self.PAYLOAD_TEMPLATES:
            canary = f"canary_{uuid.uuid4().hex[:8]}"
            payload = raw_payload_tmpl.format(canary=canary)
            expected_reflection = expected_reflection_tmpl.format(canary=canary)

            mutated_qs = dict(qs)
            mutated_qs[param_name] = [payload]
            new_query = urllib.parse.urlencode(mutated_qs, doseq=True)
            test_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, ""))

            try:
                resp = await client.get(test_url)
                content_type = resp.headers.get("content-type", "").lower()

                # XSS requires execution in HTML or SVG content
                if ("html" in content_type or "xml" in content_type or not content_type) and expected_reflection in resp.text:
                    # Verify it's unencoded reflection
                    evidence = (
                        f"Reflected XSS confirmed via parameter '{param_name}':\n"
                        f"Target URL: {test_url}\n"
                        f"Technique: {desc}\n"
                        f"Injected Payload: {payload}\n"
                        f"Unescaped Reflection in HTTP Response:\n...{expected_reflection}...\n"
                        f"Content-Type: {content_type}"
                    )
                    return self.create_finding(
                        title=f"Reflected Cross-Site Scripting (XSS) in Parameter '{param_name}'",
                        endpoint=base_url,
                        severity=Severity.HIGH,
                        description=f"The parameter '{param_name}' is reflected in the web page response without adequate HTML sanitization or context-aware encoding, allowing attackers to execute arbitrary JavaScript in the victim's browser.",
                        evidence=evidence,
                        remediation="Apply context-sensitive output encoding (HTML entity encoding, JavaScript encoding) and utilize modern templating engines with auto-escaping enabled.",
                        method="GET",
                        parameter=param_name,
                        cvss_score=7.2,
                        cwe_id="CWE-79",
                        references=[
                            "https://owasp.org/www-community/attacks/xss/",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                        ],
                        request_data={"url": test_url, "param": param_name, "payload": payload},
                        response_data={"status": resp.status_code, "reflection": expected_reflection},
                    )
            except Exception:
                pass
        return None

    async def _test_form_xss(self, client: httpx.AsyncClient, action_url: str, method: str, param_name: str, all_params: List[str]) -> Finding | None:
        for raw_payload_tmpl, expected_reflection_tmpl, desc in self.PAYLOAD_TEMPLATES:
            canary = f"canary_{uuid.uuid4().hex[:8]}"
            payload = raw_payload_tmpl.format(canary=canary)
            expected_reflection = expected_reflection_tmpl.format(canary=canary)

            data = {p: "test" for p in all_params}
            data[param_name] = payload

            try:
                if method == "POST":
                    resp = await client.post(action_url, data=data)
                else:
                    resp = await client.get(action_url, params=data)

                content_type = resp.headers.get("content-type", "").lower()
                if ("html" in content_type or not content_type) and expected_reflection in resp.text:
                    evidence = (
                        f"Reflected XSS confirmed in {method} Form Field '{param_name}'\n"
                        f"Action: {action_url}\n"
                        f"Technique: {desc}\n"
                        f"Payload: {payload}\n"
                        f"Status: {resp.status_code}"
                    )
                    return self.create_finding(
                        title=f"Reflected XSS in Form Field '{param_name}'",
                        endpoint=action_url,
                        severity=Severity.HIGH,
                        description=f"Form input '{param_name}' reflects unsanitized user content, enabling arbitrary JavaScript execution.",
                        evidence=evidence,
                        remediation="Enforce strict HTML encoding on all user input prior to rendering in HTML responses.",
                        method=method,
                        parameter=param_name,
                        cvss_score=7.2,
                        cwe_id="CWE-79",
                        references=["https://owasp.org/www-community/attacks/xss/"],
                        request_data={"url": action_url, "method": method, "data": data},
                        response_data={"status": resp.status_code, "reflection": expected_reflection},
                    )
            except Exception:
                pass
        return None
