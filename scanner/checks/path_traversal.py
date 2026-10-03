"""
Path Traversal / Local File Inclusion (LFI) Check.
Detects directory traversal vulnerabilities accessing system files (/etc/passwd, win.ini).
"""

import re
import urllib.parse
from typing import List, Dict, Any, Tuple
import httpx
from ..models import Finding, Severity, CrawlResult
from .base import BaseCheck


class PathTraversalCheck(BaseCheck):
    name = "Path Traversal & Local File Inclusion (LFI)"
    category = "A01:2021-Broken Access Control"
    cwe_id = "CWE-22"

    SUSPICIOUS_PARAMS = [
        "file", "filename", "filepath", "path", "page", "doc",
        "document", "view", "template", "include", "read", "load",
        "item", "dir", "folder", "dest", "src"
    ]

    PAYLOADS: List[Tuple[str, re.Pattern, str, str]] = [
        (
            "../../../../etc/passwd",
            re.compile(r"root:.*?:0:0:", re.MULTILINE),
            "Unix /etc/passwd root entry",
            "Linux /etc/passwd traversal",
        ),
        (
            "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
            re.compile(r"root:.*?:0:0:", re.MULTILINE),
            "Unix /etc/passwd root entry (URL-encoded)",
            "URL-encoded traversal",
        ),
        (
            "....//....//....//....//etc/passwd",
            re.compile(r"root:.*?:0:0:", re.MULTILINE),
            "Unix /etc/passwd root entry (Double slash bypass)",
            "Double slash bypass traversal",
        ),
        (
            "../../../../windows/win.ini",
            re.compile(r"\[(?:fonts|extensions|mci extensions)\]", re.IGNORECASE),
            "Windows win.ini header",
            "Windows win.ini traversal",
        ),
    ]

    async def run(self, client: httpx.AsyncClient, crawl_result: CrawlResult) -> List[Finding]:
        findings: List[Finding] = []
        tested_keys = set()

        self._log(f"Testing for Path Traversal across {len(crawl_result.endpoints)} endpoints")

        for ep in crawl_result.endpoints:
            parsed = urllib.parse.urlparse(ep.url)
            qs = urllib.parse.parse_qs(parsed.query)

            candidate_params = [p for p in qs.keys() if any(s == p.lower() or s in p.lower() for s in self.SUSPICIOUS_PARAMS)]
            # If no obvious params, test any param present
            if not candidate_params and qs:
                candidate_params = list(qs.keys())

            for param in candidate_params:
                key = f"LFI:{parsed.path}:{param}"
                if key in tested_keys:
                    continue
                tested_keys.add(key)

                for payload, pattern, match_desc, tech_desc in self.PAYLOADS:
                    mutated_qs = dict(qs)
                    mutated_qs[param] = [payload]
                    new_query = urllib.parse.urlencode(mutated_qs, doseq=True)
                    test_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, ""))

                    try:
                        resp = await client.get(test_url)
                        if resp.status_code == 200:
                            m = pattern.search(resp.text)
                            if m:
                                matched_text = m.group(0)
                                evidence = (
                                    f"Path Traversal confirmed on parameter '{param}':\n"
                                    f"Target URL: {test_url}\n"
                                    f"Payload: {payload} ({tech_desc})\n"
                                    f"Disclosed File Signature: {match_desc} -> '{matched_text}'\n"
                                    f"Status: HTTP {resp.status_code}"
                                )
                                findings.append(
                                    self.create_finding(
                                        title=f"Path Traversal / Arbitrary File Read in Parameter '{param}'",
                                        endpoint=ep.url,
                                        severity=Severity.CRITICAL,
                                        description=f"The application fails to properly sanitize path input in parameter '{param}', permitting unauthorized reading of sensitive server files like /etc/passwd.",
                                        evidence=evidence,
                                        remediation="Use a whitelist of allowed file names, resolve paths using safe path canonicalization APIs (e.g. os.path.abspath / realpath), and verify files stay within intended directories.",
                                        method="GET",
                                        parameter=param,
                                        cvss_score=8.6,
                                        cwe_id="CWE-22",
                                        references=[
                                            "https://owasp.org/www-community/attacks/Path_Traversal",
                                            "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html",
                                        ],
                                        request_data={"url": test_url, "param": param, "payload": payload},
                                        response_data={"status": resp.status_code, "match": matched_text},
                                    )
                                )
                                break
                    except Exception:
                        pass

        return findings
