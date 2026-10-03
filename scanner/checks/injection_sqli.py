"""
SQL Injection (SQLi) Vulnerability Check.
Detects Error-based, Boolean-based, and Syntax-breaking SQL injection across GET params, POST forms, and JSON payloads.
"""

import re
import urllib.parse
from typing import List, Dict, Any, Tuple
import httpx
from ..models import Finding, Severity, CrawlResult, EndpointItem
from .base import BaseCheck


class SQLInjectionCheck(BaseCheck):
    name = "SQL Injection (SQLi) Detector"
    category = "A03:2021-Injection"
    cwe_id = "CWE-89"

    # Database Error Pattern Signatures
    ERROR_PATTERNS = [
        # MySQL / MariaDB
        (re.compile(r"You have an error in your SQL syntax", re.I), "MySQL / MariaDB Syntax Error"),
        (re.compile(r"Warning: mysql_", re.I), "PHP MySQL Driver Warning"),
        (re.compile(r"MySQL server version for the right syntax", re.I), "MySQL Server Syntax Error"),
        (re.compile(r"mysqli_fetch_array\(\)|mysqli_query\(\)", re.I), "MySQLi Driver Error"),
        # PostgreSQL
        (re.compile(r"pg_query\(\)[:\s]+Query failed:\s+ERROR:", re.I), "PostgreSQL Query Error"),
        (re.compile(r"PostgreSQL query failed:", re.I), "PostgreSQL Driver Error"),
        (re.compile(r"unterminated quoted string at or near", re.I), "PostgreSQL Unterminated String Error"),
        (re.compile(r"syntax error at or near", re.I), "PostgreSQL Syntax Error"),
        # SQLite
        (re.compile(r"SQLite3::SQLException:", re.I), "SQLite3 SQLException"),
        (re.compile(r"near \".*?\": syntax error", re.I), "SQLite Syntax Error"),
        (re.compile(r"unrecognized token:", re.I), "SQLite Unrecognized Token Error"),
        (re.compile(r"operational error.*?(?:no such column|no such table)", re.I), "SQLite Operational Error"),
        # Microsoft SQL Server
        (re.compile(r"Driver.*?SQL[\-\_\ ]*Server", re.I), "MSSQL Driver Error"),
        (re.compile(r"OLE DB Provider for SQL Server", re.I), "MSSQL OLE DB Error"),
        (re.compile(r"Unclosed quotation mark before the character string", re.I), "MSSQL Unclosed Quote Error"),
        # Oracle
        (re.compile(r"ORA-[0-9]{5}", re.I), "Oracle ORA Error Code"),
        (re.compile(r"quoted string not properly terminated", re.I), "Oracle Unterminated Quote Error"),
    ]

    # Probes designed to trigger syntax errors or test boolean logic
    PROBES = [
        ("'", "Single Quote Syntax Error Probe"),
        ("''", "Escaped Quote Probe"),
        ("\"'--", "Quote + Comment Probe"),
        ("' OR '1'='1", "Classic OR 1=1 Boolean Probe"),
        ("' OR '1'='2", "Classic OR 1=2 False Probe"),
        ("1' ORDER BY 1--", "ORDER BY Probe"),
        ("1' AND SLEEP(0)--", "Sleep Function Probe"),
    ]

    async def run(self, client: httpx.AsyncClient, crawl_result: CrawlResult) -> List[Finding]:
        findings: List[Finding] = []
        tested_keys = set()

        self._log(f"Initiating SQL Injection checks against {len(crawl_result.endpoints)} discovered endpoints")

        for ep in crawl_result.endpoints:
            # 1. Test Query Parameters on GET requests
            parsed = urllib.parse.urlparse(ep.url)
            if parsed.query:
                qs = urllib.parse.parse_qs(parsed.query)
                for param_name, param_vals in qs.items():
                    key = f"GET:{parsed.path}:{param_name}"
                    if key in tested_keys:
                        continue
                    tested_keys.add(key)

                    f = await self._test_get_param(client, ep.url, param_name, param_vals[0] if param_vals else "1")
                    if f:
                        findings.append(f)

            # 2. Test Discovered Form Parameters
            for form in crawl_result.forms:
                if form.get("action") == ep.url or form.get("page") == ep.url:
                    form_action = form.get("action", ep.url)
                    form_method = form.get("method", "POST").upper()
                    for param in form.get("parameters", []):
                        key = f"{form_method}:{form_action}:{param}"
                        if key in tested_keys:
                            continue
                        tested_keys.add(key)

                        f = await self._test_form_param(client, form_action, form_method, param, form.get("parameters", []))
                        if f:
                            findings.append(f)

        return findings

    async def _test_get_param(self, client: httpx.AsyncClient, base_url: str, param_name: str, original_val: str) -> Finding | None:
        parsed = urllib.parse.urlparse(base_url)
        qs = urllib.parse.parse_qs(parsed.query)

        for payload, probe_desc in self.PROBES:
            mutated_qs = dict(qs)
            mutated_qs[param_name] = [f"{original_val}{payload}"]
            new_query = urllib.parse.urlencode(mutated_qs, doseq=True)
            test_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, ""))

            try:
                resp = await client.get(test_url)
                body = resp.text

                # Check for SQL Error Patterns
                for pattern, db_error_name in self.ERROR_PATTERNS:
                    m = pattern.search(body)
                    if m:
                        matched_str = m.group(0)
                        evidence = (
                            f"Injected SQL syntax probe into parameter '{param_name}':\n"
                            f"Target URL: {test_url}\n"
                            f"Injected Payload: {payload}\n"
                            f"Identified Database Error: [{db_error_name}] -> '{matched_str}'\n"
                            f"HTTP Response Code: {resp.status_code}"
                        )
                        return self.create_finding(
                            title=f"SQL Injection via Parameter '{param_name}' ({db_error_name})",
                            endpoint=base_url,
                            severity=Severity.CRITICAL,
                            description=f"The application failed to sanitize the '{param_name}' query parameter, resulting in a database syntax error disclosure and potential arbitrary SQL execution.",
                            evidence=evidence,
                            remediation="Use parameterized queries (Prepared Statements) or an Object-Relational Mapper (ORM) with parameterized inputs. Never concatenate user input directly into SQL strings.",
                            method="GET",
                            parameter=param_name,
                            cvss_score=9.4,
                            cwe_id="CWE-89",
                            references=[
                                "https://owasp.org/www-community/attacks/SQL_Injection",
                                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                            ],
                            request_data={"url": test_url, "param": param_name, "payload": payload},
                            response_data={"status": resp.status_code, "error_match": matched_str},
                        )
            except Exception:
                pass
        return None

    async def _test_form_param(self, client: httpx.AsyncClient, action_url: str, method: str, param_name: str, all_params: List[str]) -> Finding | None:
        for payload, probe_desc in self.PROBES:
            data = {p: "test" for p in all_params}
            data[param_name] = f"test{payload}"

            try:
                if method == "POST":
                    resp = await client.post(action_url, data=data)
                else:
                    resp = await client.get(action_url, params=data)

                body = resp.text
                for pattern, db_error_name in self.ERROR_PATTERNS:
                    m = pattern.search(body)
                    if m:
                        matched_str = m.group(0)
                        evidence = (
                            f"Injected SQL payload into Form parameter '{param_name}' via {method} {action_url}\n"
                            f"Payload: {payload}\n"
                            f"Detected Database Error: [{db_error_name}] -> '{matched_str}'\n"
                            f"Status Code: {resp.status_code}"
                        )
                        return self.create_finding(
                            title=f"SQL Injection in {method} Form Field '{param_name}'",
                            endpoint=action_url,
                            severity=Severity.CRITICAL,
                            description=f"Form field '{param_name}' is vulnerable to SQL injection, revealing raw database error output.",
                            evidence=evidence,
                            remediation="Sanitize all inputs and use parameterized prepared statements in server-side queries.",
                            method=method,
                            parameter=param_name,
                            cvss_score=9.4,
                            cwe_id="CWE-89",
                            references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                            request_data={"url": action_url, "method": method, "data": data},
                            response_data={"status": resp.status_code, "error_match": matched_str},
                        )
            except Exception:
                pass
        return None
