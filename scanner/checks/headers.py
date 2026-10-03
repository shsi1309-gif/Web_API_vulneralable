"""
Security Headers, CORS Misconfigurations, Cookie Security, and Server Banner Disclosure Checks.
"""

from typing import List
import httpx
from ..models import Finding, Severity, CrawlResult
from .base import BaseCheck


class SecurityHeadersCheck(BaseCheck):
    name = "Security Headers & Insecure Configurations"
    category = "A05:2021-Security Misconfiguration"
    cwe_id = "CWE-693"

    RECOMMENDED_HEADERS = {
        "strict-transport-security": {
            "name": "Strict-Transport-Security (HSTS)",
            "severity": Severity.MEDIUM,
            "cwe": "CWE-319",
            "cvss": 4.3,
            "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to all HTTPS responses.",
            "description": "The HTTP Strict-Transport-Security response header informs browsers that the site should only be accessed using HTTPS.",
        },
        "content-security-policy": {
            "name": "Content-Security-Policy (CSP)",
            "severity": Severity.MEDIUM,
            "cwe": "CWE-1021",
            "cvss": 5.4,
            "remediation": "Implement a strong Content-Security-Policy header restricting script-src, object-src, and default-src directives.",
            "description": "Content-Security-Policy helps prevent Cross-Site Scripting (XSS), data injection, and clickjacking attacks.",
        },
        "x-frame-options": {
            "name": "X-Frame-Options (Clickjacking Protection)",
            "severity": Severity.MEDIUM,
            "cwe": "CWE-1021",
            "cvss": 4.7,
            "remediation": "Set 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' to prevent framing attacks.",
            "description": "Missing X-Frame-Options header allows malicious websites to embed this site in an <iframe> for clickjacking attacks.",
        },
        "x-content-type-options": {
            "name": "X-Content-Type-Options (MIME-Sniffing)",
            "severity": Severity.LOW,
            "cwe": "CWE-16",
            "cvss": 3.1,
            "remediation": "Set 'X-Content-Type-Options: nosniff' to disable MIME-type sniffing.",
            "description": "Without this header, older browsers might inspect response contents and execute malicious scripts disguised as images or text.",
        },
        "referrer-policy": {
            "name": "Referrer-Policy",
            "severity": Severity.LOW,
            "cwe": "CWE-200",
            "cvss": 2.5,
            "remediation": "Set 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
            "description": "Specifies how much referrer information (URL parameters, tokens) is sent along with requests.",
        },
        "permissions-policy": {
            "name": "Permissions-Policy",
            "severity": Severity.LOW,
            "cwe": "CWE-16",
            "cvss": 2.0,
            "remediation": "Implement Permissions-Policy to explicitly declare allowed browser features (camera, microphone, geolocation).",
            "description": "Permissions-Policy allows site administrators to declare which browser features can be used.",
        },
    }

    DISCLOSURE_HEADERS = [
        ("server", "Web Server Banner Disclosure", Severity.LOW, "CWE-200", 3.0),
        ("x-powered-by", "Backend Technology / Framework Disclosure", Severity.LOW, "CWE-200", 3.0),
        ("x-aspnet-version", "ASP.NET Version Disclosure", Severity.LOW, "CWE-200", 3.0),
        ("x-runtime", "Internal Application Runtime Disclosure", Severity.INFO, "CWE-200", 1.5),
    ]

    async def run(self, client: httpx.AsyncClient, crawl_result: CrawlResult) -> List[Finding]:
        findings: List[Finding] = []
        target_url = self.config.target_url
        self._log(f"Auditing security headers and CORS on {target_url}")

        try:
            resp = await client.get(target_url)
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}

            # 1. Missing Security Headers
            for header_key, meta in self.RECOMMENDED_HEADERS.items():
                # HSTS only matters on HTTPS
                if header_key == "strict-transport-security" and not target_url.startswith("https://"):
                    continue

                if header_key not in headers_lower:
                    findings.append(
                        self.create_finding(
                            title=f"Missing Security Header: {meta['name']}",
                            endpoint=target_url,
                            severity=meta["severity"],
                            description=meta["description"],
                            evidence=f"HTTP response headers returned from {target_url} did not include '{header_key}'.",
                            remediation=meta["remediation"],
                            cvss_score=meta["cvss"],
                            cwe_id=meta["cwe"],
                            references=["https://owasp.org/www-project-secure-headers/"],
                            response_data=dict(resp.headers),
                        )
                    )

            # 2. Server & Technology Banner Disclosures
            for header_key, title, sev, cwe, cvss in self.DISCLOSURE_HEADERS:
                if header_key in headers_lower:
                    val = headers_lower[header_key]
                    findings.append(
                        self.create_finding(
                            title=title,
                            endpoint=target_url,
                            severity=sev,
                            description=f"The server exposes internal technology and version details via the '{header_key}' header.",
                            evidence=f"Header '{header_key}: {val}' was found in the HTTP response.",
                            remediation=f"Configure the web server or reverse proxy to strip or obscure the '{header_key}' header.",
                            cvss_score=cvss,
                            cwe_id=cwe,
                            references=["https://cwe.mitre.org/data/definitions/200.html"],
                            response_data={header_key: val},
                        )
                    )

            # 3. CORS Misconfiguration Checks
            cors_findings = await self._check_cors(client, target_url)
            findings.extend(cors_findings)

            # 4. Cookie Security Flags Check
            cookie_findings = self._check_cookies(resp, target_url)
            findings.extend(cookie_findings)

        except Exception as e:
            self._log(f"Header check error: {str(e)}")

        return findings

    async def _check_cors(self, client: httpx.AsyncClient, target_url: str) -> List[Finding]:
        findings = []
        test_origin = "https://attacker-evil-site.com"
        try:
            resp = await client.get(target_url, headers={"Origin": test_origin})
            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "").lower()

            if acao == "*" and acac == "true":
                findings.append(
                    self.create_finding(
                        title="CORS Misconfiguration: Wildcard Origin with Credentials Allowed",
                        endpoint=target_url,
                        severity=Severity.HIGH,
                        description="The CORS configuration permits arbitrary origins (*) while simultaneously enabling credentials (cookies, auth headers).",
                        evidence=f"Request Origin: {test_origin}\nResponse Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                        remediation="Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. Implement a strict whitelist of trusted origins.",
                        cvss_score=7.5,
                        cwe_id="CWE-346",
                        references=["https://portswigger.net/web-security/cors"],
                        response_data=dict(resp.headers),
                    )
                )
            elif acao == test_origin:
                sev = Severity.HIGH if acac == "true" else Severity.MEDIUM
                findings.append(
                    self.create_finding(
                        title="CORS Misconfiguration: Arbitrary Origin Reflection",
                        endpoint=target_url,
                        severity=sev,
                        description="The server dynamically reflects the untrusted Origin header back in Access-Control-Allow-Origin, allowing any domain to perform cross-origin read requests.",
                        evidence=f"Sent Origin: '{test_origin}'\nReceived: 'Access-Control-Allow-Origin: {acao}' (Credentials: {acac or 'false'})",
                        remediation="Validate the incoming Origin header against an explicit, strictly validated server-side whitelist.",
                        cvss_score=8.1 if acac == "true" else 5.3,
                        cwe_id="CWE-346",
                        references=["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"],
                        response_data=dict(resp.headers),
                    )
                )
        except Exception:
            pass
        return findings

    def _check_cookies(self, resp: httpx.Response, target_url: str) -> List[Finding]:
        findings = []
        raw_cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else [resp.headers.get("set-cookie", "")]
        for raw_cookie in raw_cookies:
            if not raw_cookie:
                continue
            cookie_parts = [p.strip().lower() for p in raw_cookie.split(";")]
            cookie_name = raw_cookie.split("=")[0].strip()

            # Missing HttpOnly
            if "httponly" not in cookie_parts:
                findings.append(
                    self.create_finding(
                        title=f"Insecure Cookie: Missing HttpOnly Flag ({cookie_name})",
                        endpoint=target_url,
                        severity=Severity.LOW,
                        description=f"Cookie '{cookie_name}' lacks the HttpOnly attribute, making it accessible to client-side JavaScript and vulnerable to theft via XSS.",
                        evidence=f"Set-Cookie: {raw_cookie}",
                        remediation="Add the 'HttpOnly' flag to all sensitive and session cookies.",
                        cvss_score=4.3,
                        cwe_id="CWE-1004",
                        references=["https://owasp.org/www-community/HttpOnly"],
                    )
                )

            # Missing Secure (if HTTPS)
            if target_url.startswith("https://") and "secure" not in cookie_parts:
                findings.append(
                    self.create_finding(
                        title=f"Insecure Cookie: Missing Secure Flag ({cookie_name})",
                        endpoint=target_url,
                        severity=Severity.LOW,
                        description=f"Cookie '{cookie_name}' lacks the Secure attribute, allowing it to be transmitted over unencrypted HTTP channels.",
                        evidence=f"Set-Cookie: {raw_cookie}",
                        remediation="Add the 'Secure' flag to all cookies transmitted over HTTPS.",
                        cvss_score=3.7,
                        cwe_id="CWE-614",
                        references=["https://owasp.org/www-community/controls/SecureCookieAttribute"],
                    )
                )

            # Missing SameSite
            has_samesite = any(p.startswith("samesite=") for p in cookie_parts)
            if not has_samesite:
                findings.append(
                    self.create_finding(
                        title=f"Insecure Cookie: Missing SameSite Attribute ({cookie_name})",
                        endpoint=target_url,
                        severity=Severity.LOW,
                        description=f"Cookie '{cookie_name}' does not specify a SameSite policy (Strict or Lax), increasing susceptibility to Cross-Site Request Forgery (CSRF).",
                        evidence=f"Set-Cookie: {raw_cookie}",
                        remediation="Explicitly set 'SameSite=Lax' or 'SameSite=Strict' on all cookies.",
                        cvss_score=3.5,
                        cwe_id="CWE-1275",
                        references=["https://owasp.org/www-community/SameSite"],
                    )
                )
        return findings
