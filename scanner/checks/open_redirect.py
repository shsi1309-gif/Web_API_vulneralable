"""
Open Redirect / SSRF Vulnerability Check.
Detects unvalidated redirect parameters and open forwarders.
"""

import re
import urllib.parse
from typing import List, Dict, Any, Tuple
import httpx
from ..models import Finding, Severity, CrawlResult
from .base import BaseCheck


class OpenRedirectCheck(BaseCheck):
    name = "Open Redirect & SSRF Detector"
    category = "A01:2021-Broken Access Control"
    cwe_id = "CWE-601"

    REDIRECT_PARAM_NAMES = [
        "url", "redirect", "next", "return_to", "return", "dest",
        "destination", "target", "r", "continue", "goto", "out",
        "forward", "link", "callback", "redirect_uri", "ref"
    ]

    PAYLOADS = [
        ("https://example.com/sec-probe-redirect", "Direct HTTPS URL"),
        ("//example.com/sec-probe-redirect", "Protocol-Relative URL"),
        ("/\\example.com/sec-probe-redirect", "Backslash Bypass"),
    ]

    async def run(self, client: httpx.AsyncClient, crawl_result: CrawlResult) -> List[Finding]:
        findings: List[Finding] = []
        tested_keys = set()

        self._log(f"Testing for Open Redirect vulnerabilities across {len(crawl_result.endpoints)} endpoints")

        # Create a non-redirecting client to inspect Location headers
        transport = httpx.AsyncHTTPTransport(verify=False)
        async with httpx.AsyncClient(headers=client.headers, timeout=self.config.timeout, follow_redirects=False, transport=transport) as no_redirect_client:
            for ep in crawl_result.endpoints:
                parsed = urllib.parse.urlparse(ep.url)
                qs = urllib.parse.parse_qs(parsed.query)

                # Check existing params
                candidate_params = [p for p in qs.keys() if any(r == p.lower() or r in p.lower() for r in self.REDIRECT_PARAM_NAMES)]
                # If no explicit param in query, but path looks like a redirect endpoint (e.g. /login, /logout, /redirect), probe standard names
                if not candidate_params and any(word in parsed.path.lower() for word in ["redirect", "goto", "link", "jump", "forward", "login", "oauth"]):
                    candidate_params = ["url", "next", "redirect"]

                for param in candidate_params:
                    key = f"REDIRECT:{parsed.path}:{param}"
                    if key in tested_keys:
                        continue
                    tested_keys.add(key)

                    for payload, technique in self.PAYLOADS:
                        mutated_qs = dict(qs)
                        mutated_qs[param] = [payload]
                        new_query = urllib.parse.urlencode(mutated_qs, doseq=True)
                        test_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, ""))

                        try:
                            resp = await no_redirect_client.get(test_url)
                            loc = resp.headers.get("location", "")

                            # Vulnerable if status is 3xx and Location matches payload target domain
                            if resp.status_code in [301, 302, 303, 307, 308] and "example.com" in loc:
                                evidence = (
                                    f"Open Redirect detected on parameter '{param}':\n"
                                    f"Request URL: {test_url}\n"
                                    f"Technique: {technique}\n"
                                    f"Status Code: {resp.status_code}\n"
                                    f"Location Header: {loc}"
                                )
                                findings.append(
                                    self.create_finding(
                                        title=f"Open Redirect in Parameter '{param}'",
                                        endpoint=ep.url,
                                        severity=Severity.MEDIUM,
                                        description=f"The endpoint accepts an untrusted destination URL in parameter '{param}' and redirects users without validation, facilitating phishing and credential theft.",
                                        evidence=evidence,
                                        remediation="Implement a whitelist of approved redirect URLs, or restrict redirects strictly to relative paths starting with a single forward slash.",
                                        method="GET",
                                        parameter=param,
                                        cvss_score=6.1,
                                        cwe_id="CWE-601",
                                        references=[
                                            "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"
                                        ],
                                        request_data={"url": test_url, "param": param, "payload": payload},
                                        response_data={"status": resp.status_code, "location": loc},
                                    )
                                )
                                break
                        except Exception:
                            pass

        return findings
