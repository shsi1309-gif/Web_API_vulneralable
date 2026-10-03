#!/usr/bin/env python3
"""
Antigravity Automated Web & API Vulnerability Scanner CLI.
Ideal for CI/CD pipelines, DevOps automation, and command-line terminal auditing.
"""

import sys
import os
import argparse
import asyncio
import json
import time
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from scanner.models import ScanConfig, ScanProfile, Severity
from scanner.engine import ScannerEngine
from jinja2 import Template
from app.services.report_service import HTML_REPORT_TEMPLATE


# ANSI Terminal Colors
class Colors:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    END = "\033[0m"


BANNER = r"""\033[96m\033[1m
   ___          __                       __           __   ____
  / _ | __ __  / /____  __ _  ___ _ ____/ /_ ___  ___/ /  / __/__ ____
 / __ |/ // / / __/ _ \/  ' \/ _ `// __/ __// -_)/ _  /  _\ \ / -_) __/
/_/ |_|\_,_/  \__/\___/_/_/_/\_,_/ \__/\__/ \__/ \_,_/  /___/ \__/\__/
          Automated Web & API Vulnerability Scanner v2.0
\033[0m"""


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Automated Web & REST API Vulnerability Scanner with Nuclei Integration and OWASP Top 10 Auditing.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("-t", "--target", required=True, help="Target URL (e.g. http://localhost:8888 or https://example.com)")
    parser.add_argument("-p", "--profile", default="FULL", choices=["FULL", "OWASP_TOP_10", "API_SECURITY", "NUCLEI_ONLY", "QUICK_HEADERS", "RECON_ONLY"], help="Scan Profile (Default: FULL)")
    parser.add_argument("-d", "--depth", type=int, default=3, help="Max crawling depth (Default: 3)")
    parser.add_argument("-m", "--max-endpoints", type=int, default=50, help="Max endpoints to crawl (Default: 50)")
    parser.add_argument("-c", "--concurrency", type=int, default=10, help="Concurrent workers (Default: 10)")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP request timeout in seconds (Default: 10)")
    parser.add_argument("--header", action="append", help="Custom HTTP header in 'Key: Value' format (Can specify multiple)")
    parser.add_argument("--cookie", help="Custom Cookie string")
    parser.add_argument("--auth", help="Authorization Bearer token")
    parser.add_argument("--no-nuclei", action="store_true", help="Disable Nuclei template scanner")
    parser.add_argument("--report-html", help="Path to save standalone HTML report")
    parser.add_argument("--report-json", help="Path to save JSON findings report")
    parser.add_argument("--report-md", help="Path to save Markdown findings report")
    parser.add_argument("--fail-on-critical", action="store_true", help="Exit with code 1 if CRITICAL or HIGH findings are detected (CI/CD mode)")
    return parser.parse_args()


async def run_cli_scan(args):
    print(BANNER)
    print(f"{Colors.BOLD}[*] Initializing Scan on Target:{Colors.END} {args.target}")
    print(f"[*] Profile: {Colors.CYAN}{args.profile}{Colors.END} | Max Depth: {args.depth} | Endpoints Cap: {args.max_endpoints}")

    # Parse headers
    custom_headers = {}
    if args.header:
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                custom_headers[k.strip()] = v.strip()

    config = ScanConfig(
        target_url=args.target,
        profile=getattr(ScanProfile, args.profile),
        max_depth=args.depth,
        max_endpoints=args.max_endpoints,
        concurrency=args.concurrency,
        timeout=args.timeout,
        custom_headers=custom_headers,
        cookie=args.cookie,
        auth_token=args.auth,
        enable_nuclei=not args.no_nuclei,
    )

    def log_cb(msg: str):
        print(f"  {Colors.BLUE}[LOG]{Colors.END} {msg}")

    def progress_cb(pct: int, phase: str, msg: str):
        bar_len = 30
        filled = int(bar_len * (pct / 100.0))
        bar = "█" * filled + "░" * (bar_len - filled)
        sys.stdout.write(f"\r  {Colors.CYAN}[{pct:3d}%]{Colors.END} |{bar}| {Colors.BOLD}{phase:<18}{Colors.END} : {msg[:50]:<50}")
        sys.stdout.flush()
        if pct == 100:
            sys.stdout.write("\n")

    def finding_cb(f):
        sev_color = {
            Severity.CRITICAL: Colors.FAIL,
            Severity.HIGH: Colors.WARNING,
            Severity.MEDIUM: Colors.WARNING,
            Severity.LOW: Colors.BLUE,
            Severity.INFO: Colors.GREEN,
        }.get(f.severity, Colors.END)
        print(f"\n  {sev_color}{Colors.BOLD}[!] [{f.severity.value}] {f.title}{Colors.END} on {f.endpoint}")

    engine = ScannerEngine(
        config=config,
        progress_cb=progress_cb,
        log_cb=log_cb,
        finding_cb=finding_cb,
    )

    findings, crawl_result, summary = await engine.scan()

    print("\n" + "=" * 70)
    print(f"{Colors.BOLD}{Colors.HEADER}AUDIT SUMMARY RESULTS{Colors.END}")
    print("=" * 70)
    print(f" Target URL            : {args.target}")
    print(f" Endpoints Audited     : {summary.total_endpoints_tested}")
    print(f" Execution Duration    : {summary.duration_seconds} seconds")
    print(f" Overall Risk Score    : {Colors.BOLD}{summary.risk_score}/100{Colors.END}")
    print("-" * 70)
    print(f" {Colors.FAIL}{Colors.BOLD}CRITICAL Findings     : {summary.critical_count}{Colors.END}")
    print(f" {Colors.WARNING}HIGH Findings         : {summary.high_count}{Colors.END}")
    print(f" {Colors.WARNING}MEDIUM Findings       : {summary.medium_count}{Colors.END}")
    print(f" {Colors.BLUE}LOW Findings          : {summary.low_count}{Colors.END}")
    print(f" {Colors.GREEN}INFO Findings         : {summary.info_count}{Colors.END}")
    print("=" * 70)

    # Save HTML report if requested
    if args.report_html:
        scan_mock = type("MockScan", (), {
            "target_url": args.target,
            "profile": args.profile,
            "total_endpoints": summary.total_endpoints_tested,
            "risk_score": summary.risk_score,
            "critical_count": summary.critical_count,
            "high_count": summary.high_count,
            "medium_count": summary.medium_count,
            "low_count": summary.low_count,
            "info_count": summary.info_count,
            "duration_seconds": summary.duration_seconds,
        })()
        tmpl = Template(HTML_REPORT_TEMPLATE)
        html_out = tmpl.render(scan=scan_mock, findings=findings, generated_at=time.strftime("%Y-%m-%d %H:%M:%S UTC"))
        with open(args.report_html, "w", encoding="utf-8") as f:
            f.write(html_out)
        print(f"\n{Colors.GREEN}[+] Standalone HTML Report saved to:{Colors.END} {args.report_html}")

    # Save JSON report if requested
    if args.report_json:
        data = {
            "target": args.target,
            "summary": summary.model_dump(),
            "findings": [f.model_dump() for f in findings],
            "endpoints": [ep.model_dump() for ep in crawl_result.endpoints],
        }
        with open(args.report_json, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        print(f"{Colors.GREEN}[+] JSON Findings Report saved to:{Colors.END} {args.report_json}")

    # Fail on critical in CI/CD mode
    if args.fail_on_critical and (summary.critical_count > 0 or summary.high_count > 0):
        print(f"\n{Colors.FAIL}[!] Security Gate Failure: Found {summary.critical_count} critical and {summary.high_count} high vulnerabilities!{Colors.END}")
        sys.exit(1)


def main():
    args = parse_arguments()
    asyncio.run(run_cli_scan(args))


if __name__ == "__main__":
    main()
