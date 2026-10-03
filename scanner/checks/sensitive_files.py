"""
Sensitive Files, Exposed Repositories, and Debug Endpoint Exposure Checks.
"""

import urllib.parse
from typing import List, Dict, Any, Tuple
import httpx
from ..models import Finding, Severity, CrawlResult
from .base import BaseCheck


class SensitiveFilesCheck(BaseCheck):
    name = "Exposed Sensitive Files & Endpoints"
    category = "A01:2021-Broken Access Control"
    cwe_id = "CWE-552"

    PROBE_TARGETS: List[Dict[str, Any]] = [
        {
            "path": "/.env",
            "title": "Exposed Environment Configuration File (.env)",
            "severity": Severity.CRITICAL,
            "cvss": 9.8,
            "cwe": "CWE-552",
            "keywords": ["DB_PASSWORD", "SECRET_KEY", "DATABASE_URL", "AWS_ACCESS_KEY_ID", "API_KEY", "JWT_SECRET", "APP_ENV"],
            "description": "The application's environment configuration file (.env) is publicly accessible, leaking database credentials, API keys, and sensitive secrets.",
            "remediation": "Restrict web server access to dotfiles like '.env' and place sensitive configuration outside the web root directory.",
        },
        {
            "path": "/.git/config",
            "title": "Exposed Git Repository Configuration (.git/config)",
            "severity": Severity.HIGH,
            "cvss": 7.5,
            "cwe": "CWE-538",
            "keywords": ["[core]", "repositoryformatversion", "[remote"],
            "description": "The Git directory is exposed via the web root, allowing attackers to reconstruct source code, commit history, and hidden credentials.",
            "remediation": "Configure the web server (Nginx/Apache) to deny all HTTP requests to the '/.git' directory.",
        },
        {
            "path": "/.git/HEAD",
            "title": "Exposed Git HEAD Reference (.git/HEAD)",
            "severity": Severity.HIGH,
            "cvss": 7.5,
            "cwe": "CWE-538",
            "keywords": ["ref: refs/heads/"],
            "description": "The '.git/HEAD' file is accessible, indicating the whole source control repository is exposed.",
            "remediation": "Block access to the '.git' folder on the web server level.",
        },
        {
            "path": "/actuator/env",
            "title": "Exposed Spring Boot Actuator Environment (/actuator/env)",
            "severity": Severity.CRITICAL,
            "cvss": 9.1,
            "cwe": "CWE-200",
            "keywords": ["activeProfiles", "propertySources", "systemProperties"],
            "description": "Spring Boot Actuator '/env' endpoint is exposed without authentication, leaking internal environment properties and credentials.",
            "remediation": "Disable or enforce strict Spring Security authentication on all '/actuator/*' endpoints.",
        },
        {
            "path": "/actuator/health",
            "title": "Exposed Spring Boot Actuator Health (/actuator/health)",
            "severity": Severity.LOW,
            "cvss": 3.7,
            "cwe": "CWE-200",
            "keywords": ['"status":', '"UP"', '"components":'],
            "description": "Spring Boot Actuator health endpoint is publicly accessible, disclosing system status and components.",
            "remediation": "Limit actuator endpoint exposure to internal monitoring networks.",
        },
        {
            "path": "/phpinfo.php",
            "title": "Exposed PHP Information Page (phpinfo.php)",
            "severity": Severity.MEDIUM,
            "cvss": 5.3,
            "cwe": "CWE-200",
            "keywords": ["<title>phpinfo()</title>", "PHP Version", "Configuration File (php.ini) Path"],
            "description": "A phpinfo() diagnostic page is publicly accessible, disclosing PHP environment configuration, loaded modules, and internal server paths.",
            "remediation": "Remove phpinfo() diagnostic scripts from production environments.",
        },
        {
            "path": "/.DS_Store",
            "title": "Exposed macOS Metadata File (.DS_Store)",
            "severity": Severity.LOW,
            "cvss": 3.7,
            "cwe": "CWE-538",
            "keywords": ["Bud1"],
            "binary_check": True,
            "description": "A .DS_Store file is exposed, allowing attackers to enumerate hidden directory listings and files.",
            "remediation": "Block access to .DS_Store files and remove them from web directories.",
        },
        {
            "path": "/config.json",
            "title": "Exposed Application Configuration (config.json)",
            "severity": Severity.HIGH,
            "cvss": 7.5,
            "cwe": "CWE-552",
            "keywords": ["database", "password", "secret", "apiKey", "connectionString"],
            "description": "Configuration file config.json is exposed, potentially revealing sensitive database strings or internal API keys.",
            "remediation": "Move configuration files out of the public web root or deny direct HTTP serving.",
        },
    ]

    async def run(self, client: httpx.AsyncClient, crawl_result: CrawlResult) -> List[Finding]:
        findings: List[Finding] = []
        parsed = urllib.parse.urlparse(self.config.target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        self._log(f"Testing for exposed sensitive files & endpoints on {base_url}")

        for target in self.PROBE_TARGETS:
            probe_url = urllib.parse.urljoin(base_url, target["path"])
            try:
                resp = await client.get(probe_url)
                if resp.status_code == 200:
                    text = resp.text
                    matched_keyword = None

                    # Check for keywords
                    if target.get("binary_check"):
                        # Match binary signature
                        if b"\x00\x00\x00\x01Bud1" in resp.content or b"Bud1" in resp.content:
                            matched_keyword = "DS_Store Binary Signature"
                    else:
                        for kw in target["keywords"]:
                            if kw.lower() in text.lower():
                                matched_keyword = kw
                                break

                    if matched_keyword:
                        snippet = text[:300].strip() if not target.get("binary_check") else "[Binary Content]"
                        evidence = f"GET {probe_url} returned HTTP 200 OK with matching fingerprint: '{matched_keyword}'.\n\nResponse preview:\n{snippet}"

                        findings.append(
                            self.create_finding(
                                title=target["title"],
                                endpoint=probe_url,
                                severity=target["severity"],
                                description=target["description"],
                                evidence=evidence,
                                remediation=target["remediation"],
                                cvss_score=target["cvss"],
                                cwe_id=target["cwe"],
                                references=["https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"],
                                response_data={"status": resp.status_code, "preview": snippet},
                            )
                        )
            except Exception as e:
                self._log(f"Error probing {probe_url}: {str(e)}")

        return findings
