"""
Native Python Nuclei YAML Template Parser & Execution Engine.
Executes Nuclei-compatible YAML templates natively using HTTP requests, matchers, and extractors.
"""

import os
import re
import uuid
import yaml
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable
import httpx

from scanner.models import Finding, Severity, FindingStatus, ScanConfig


class NucleiTemplateEngine:
    """Evaluates standard Nuclei YAML templates against a target URL."""

    def __init__(self, templates_dir: Optional[str] = None, log_cb: Optional[Callable[[str], None]] = None):
        if templates_dir:
            self.templates_dir = Path(templates_dir)
        else:
            self.templates_dir = Path(__file__).parent / "templates"
        self.log_cb = log_cb or (lambda msg: None)

    def _log(self, msg: str):
        self.log_cb(f"[Nuclei Engine] {msg}")

    def load_all_templates(self, filter_tags: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Loads and parses all YAML templates in the templates directory."""
        templates = []
        if not self.templates_dir.exists():
            return templates

        for yaml_path in self.templates_dir.rglob("*.yaml"):
            try:
                with open(yaml_path, "r", encoding="utf-8") as f:
                    doc = yaml.safe_load(f)
                    if isinstance(doc, dict) and "id" in doc:
                        doc["_filepath"] = str(yaml_path)
                        # Filter by tags if specified
                        if filter_tags:
                            doc_tags = doc.get("info", {}).get("tags", "")
                            if isinstance(doc_tags, str):
                                tag_list = [t.strip().lower() for t in doc_tags.split(",")]
                            else:
                                tag_list = [str(t).lower() for t in doc_tags]

                            if not any(ft.lower() in tag_list for ft in filter_tags):
                                continue

                        templates.append(doc)
            except Exception as e:
                self._log(f"Error loading template {yaml_path}: {e}")
        return templates

    async def execute_templates(
        self,
        target_url: str,
        config: ScanConfig,
        templates: Optional[List[Dict[str, Any]]] = None,
    ) -> List[Finding]:
        """Executes a collection of Nuclei templates against the target URL."""
        if templates is None:
            templates = self.load_all_templates(config.nuclei_tags)

        self._log(f"Running {len(templates)} Nuclei templates against {target_url}")
        findings: List[Finding] = []

        transport = httpx.AsyncHTTPTransport(verify=False)
        async with httpx.AsyncClient(timeout=config.timeout, follow_redirects=True, transport=transport) as client:
            for tmpl in templates:
                try:
                    tmpl_findings = await self._run_single_template(client, target_url, tmpl)
                    findings.extend(tmpl_findings)
                except Exception as e:
                    self._log(f"Error executing template {tmpl.get('id')}: {e}")

        return findings

    async def _run_single_template(
        self, client: httpx.AsyncClient, target_url: str, template: Dict[str, Any]
    ) -> List[Finding]:
        findings = []
        tmpl_id = template.get("id", "unknown-template")
        info = template.get("info", {})
        title = info.get("name", tmpl_id)
        severity_str = info.get("severity", "medium").upper()
        severity = getattr(Severity, severity_str, Severity.MEDIUM)
        description = info.get("description", "Vulnerability detected by Nuclei template.")
        remediation = info.get("remediation", "Apply vendor security patches and validate input.")
        refs = info.get("reference", [])
        if isinstance(refs, str):
            refs = [refs]

        # Nuclei supports 'http' or 'requests' block
        http_blocks = template.get("http") or template.get("requests") or []
        if not isinstance(http_blocks, list):
            http_blocks = [http_blocks]

        for block in http_blocks:
            method = block.get("method", "GET").upper()
            paths = block.get("path", ["{{BaseURL}}"])
            if isinstance(paths, str):
                paths = [paths]

            headers = block.get("headers", {})
            body = block.get("body", None)
            matchers = block.get("matchers", [])
            matchers_condition = block.get("matchers-condition", "or").lower()

            for path_tmpl in paths:
                # Interpolate {{BaseURL}} and {{RootURL}}
                req_url = path_tmpl.replace("{{BaseURL}}", target_url.rstrip("/")).replace("{{RootURL}}", target_url.rstrip("/"))
                if not req_url.startswith("http"):
                    req_url = f"{target_url.rstrip('/')}/{req_url.lstrip('/')}"

                try:
                    req_headers = {k: v.replace("{{BaseURL}}", target_url) for k, v in headers.items()}
                    if method == "POST":
                        resp = await client.post(req_url, headers=req_headers, content=body)
                    elif method == "PUT":
                        resp = await client.put(req_url, headers=req_headers, content=body)
                    elif method == "DELETE":
                        resp = await client.delete(req_url, headers=req_headers)
                    elif method == "OPTIONS":
                        resp = await client.options(req_url, headers=req_headers)
                    else:
                        resp = await client.get(req_url, headers=req_headers)

                    # Evaluate Matchers
                    matched, match_evidence = self._evaluate_matchers(resp, matchers, matchers_condition)
                    if matched:
                        evidence_str = (
                            f"[Nuclei Match] Template: {tmpl_id}\n"
                            f"Target: {method} {req_url}\n"
                            f"HTTP Response Status: {resp.status_code}\n"
                            f"Match Evidence:\n{match_evidence}"
                        )
                        finding = Finding(
                            id=str(uuid.uuid4()),
                            title=title,
                            severity=severity,
                            category="Nuclei Security Check",
                            cvss_score=self._severity_to_cvss(severity),
                            endpoint=req_url,
                            method=method,
                            description=description,
                            evidence=evidence_str,
                            remediation=remediation,
                            references=refs,
                            status=FindingStatus.OPEN,
                            check_source="nuclei",
                            template_id=tmpl_id,
                            request_data={"url": req_url, "method": method, "headers": req_headers},
                            response_data={"status": resp.status_code, "preview": resp.text[:300]},
                        )
                        findings.append(finding)

                except Exception:
                    pass

        return findings

    def _evaluate_matchers(self, resp: httpx.Response, matchers: List[Dict[str, Any]], condition: str) -> (bool, str):
        """Evaluates word, regex, and status matchers against HTTP response."""
        if not matchers:
            return False, ""

        results = []
        evidence_items = []

        for m in matchers:
            m_type = m.get("type", "word").lower()
            part = m.get("part", "body").lower()
            m_cond = m.get("condition", "or").lower()
            is_negative = m.get("negative", False)

            # Determine content to test
            if part in ["header", "headers", "all_headers"]:
                target_content = "\r\n".join(f"{k}: {v}" for k, v in resp.headers.items())
            elif part == "status":
                target_content = str(resp.status_code)
            else:
                target_content = resp.text

            sub_matched = False
            sub_evidence = []

            # Word Matcher
            if m_type in ["word", "words"]:
                words = m.get("words") or m.get("word") or []
                if isinstance(words, str):
                    words = [words]

                word_matches = [w for w in words if w in target_content]
                if m_cond == "and":
                    sub_matched = len(word_matches) == len(words)
                else:
                    sub_matched = len(word_matches) > 0

                if sub_matched:
                    sub_evidence.append(f"Matched words in {part}: {word_matches}")

            # Regex Matcher
            elif m_type in ["regex"]:
                patterns = m.get("regex") or []
                if isinstance(patterns, str):
                    patterns = [patterns]

                regex_matches = []
                for pat in patterns:
                    r = re.search(pat, target_content, re.IGNORECASE | re.MULTILINE)
                    if r:
                        regex_matches.append(r.group(0))

                if m_cond == "and":
                    sub_matched = len(regex_matches) == len(patterns)
                else:
                    sub_matched = len(regex_matches) > 0

                if sub_matched:
                    sub_evidence.append(f"Matched regex in {part}: {regex_matches}")

            # Status Matcher
            elif m_type == "status":
                statuses = m.get("status", [200])
                if isinstance(statuses, int):
                    statuses = [statuses]
                sub_matched = resp.status_code in statuses
                if sub_matched:
                    sub_evidence.append(f"Status {resp.status_code} in {statuses}")

            if is_negative:
                sub_matched = not sub_matched

            results.append(sub_matched)
            if sub_matched and sub_evidence:
                evidence_items.extend(sub_evidence)

        if condition == "and":
            final_match = all(results)
        else:
            final_match = any(results)

        return final_match, "\n".join(evidence_items)

    def _severity_to_cvss(self, sev: Severity) -> float:
        mapping = {
            Severity.CRITICAL: 9.5,
            Severity.HIGH: 7.8,
            Severity.MEDIUM: 5.5,
            Severity.LOW: 3.2,
            Severity.INFO: 1.0,
        }
        return mapping.get(sev, 5.0)
