# 🛡️ Automated Web & REST API Vulnerability Scanner

[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?style=flat&logo=fastapi)](https://fastapi.tiangolo.com)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat&logo=python)](https://python.org)
[![Nuclei](https://img.shields.io/badge/Templates-Nuclei%20YAML-6366F1?style=flat)](https://projectdiscovery.io)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

An enterprise-grade, automated security scanner engineered to discover web application and REST/GraphQL API endpoints, audit HTTP responses for common vulnerabilities, execute reusable Nuclei YAML security templates, and generate actionable vulnerability triage reports.

---

## 🌟 Key Highlights & Capabilities

- **🔍 Intelligent Web & API Reconnaissance & Discovery Engine**:
  - Crawls single-page apps, traditional web apps, and APIs using `BeautifulSoup` & `httpx`.
  - Automatically discovers OpenAPI/Swagger schemas (`/openapi.json`, `/swagger.json`, `/api-docs`) and parses REST route parameters.
  - GraphQL endpoint detection (`/graphql`, `/graphiql`) with automated introspection querying.
  - Scrapes JavaScript assets for hidden routes, endpoints, JWTs, AWS credentials, and API secret tokens.
  - Parses HTML forms, hidden inputs, query parameters, `robots.txt`, and `sitemap.xml`.

- **⚡ Comprehensive OWASP Top 10 & API Security Checks**:
  - **SQL Injection (SQLi)**: Multi-vector syntax breaking, database error signatures (MySQL, PostgreSQL, SQLite, MSSQL, Oracle), and boolean reflection heuristics.
  - **Cross-Site Scripting (XSS)**: Context-aware reflected XSS detection with canary tags and unescaped response reflection verification.
  - **Sensitive File & Endpoint Exposure**: Probes for `/.env`, `/.git/config`, `/actuator/env`, `/phpinfo.php`, `config.json`, `.DS_Store`, and backup files.
  - **Open Redirect / SSRF**: Detects and verifies unvalidated destination redirects.
  - **Path Traversal / LFI**: Detects arbitrary file disclosure (`/etc/passwd`, `win.ini`).
  - **OWASP API Top 10**: BOLA/IDOR object enumeration, JWT `alg: none` unsigned bypass, excessive data exposure (PII, SSN, Credit Cards), and missing rate-limiting headers.
  - **Security Headers & CORS**: Audits missing CSP, HSTS, X-Frame-Options, X-Content-Type-Options, wildcard CORS with credentials, origin reflection, and insecure cookie flags.

- **🧬 Native Nuclei Template Engine & Reusable Templates**:
  - Includes a standalone Python-native YAML template parser and execution engine with 100% Nuclei YAML format compatibility.
  - Ships with pre-built templates across `owasp-top-10`, `api-security`, `headers`, and `misconfigurations`.
  - Built-in **Nuclei Template Studio** for drafting and live-testing custom YAML templates in real time.

- **🔄 One-Click Vulnerability Retesting & Triage**:
  - Track triage states: `OPEN`, `TRIAGED`, `FALSE_POSITIVE`, `RESOLVED`.
  - One-click **Retest Vulnerability** button triggers focused re-evaluations against target endpoints to verify developer remediation.

- **📑 Multi-Format Executive & Technical Reports**:
  - **Standalone Interactive HTML Report**: Executive summaries, risk score gauge, CVSS v3.1 metrics, technical HTTP request/response evidence, and remediation guidance.
  - **JSON, Markdown, and CSV Exports**: Ready for Jira, Redmine, SIEM, or compliance audits.

- **🚀 CI/CD Automation & CLI Tool**:
  - Full CLI interface (`cli.py`) with rich ANSI terminal outputs, colored severity flags, and `--fail-on-critical` exit codes for GitHub Actions, GitLab CI, and DevSecOps pipelines.

---

## 🛠️ Tech Stack

| Component | Technologies |
| :--- | :--- |
| **Backend API** | Python 3, FastAPI, Uvicorn, Pydantic v2 |
| **Scanning Engine** | Requests, BeautifulSoup4, HTTPX (Async), PyYAML |
| **Template Runner** | Nuclei YAML Engine (Native Python + CLI support) |
| **Database** | SQLAlchemy ORM (SQLite zero-config default / PostgreSQL support) |
| **Frontend UI** | Cyber Red-Team SPA (Vanilla JS + CSS Glassmorphism) |
| **Deployment** | Docker, Docker Compose, Bash Startup Script |

---

## 🚀 Quick Start Guide

### 1. Single Command Launch (Recommended)

Run the included startup script which sets up the virtual environment, launches the intentionally vulnerable test target on port `8888`, and starts the Dashboard on port `8000`:

```bash
./run.sh
```

- **Dashboard UI:** [http://localhost:8000](http://localhost:8000)
- **Interactive Swagger API Docs:** [http://localhost:8000/docs](http://localhost:8000/docs)
- **Built-in Vulnerable Testbed:** [http://localhost:8888](http://localhost:8888)

---

### 2. Manual Local Installation

```bash
# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start the Scanner Server
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

In a separate terminal, launch the demo testbed to test immediately:
```bash
python3 test_target/vulnerable_app.py
```

---

### 3. Docker & Docker Compose (Production Setup)

To run the scanner with PostgreSQL in Docker containers:

```bash
docker-compose up --build
```

---

## 💻 CLI Usage (DevSecOps & CI/CD Pipelines)

Run scans directly from your terminal or CI/CD pipelines:

```bash
# Run Full Audit on target
python3 cli.py --target http://localhost:8888 --profile FULL

# Run OWASP Top 10 Scan and export HTML & JSON reports
python3 cli.py --target https://example.com --profile OWASP_TOP_10 --report-html report.html --report-json report.json

# CI/CD Gate: Fail build if Critical/High vulnerabilities are found
python3 cli.py --target http://staging.internal:8080 --fail-on-critical
```

### Available CLI Options:
```
-t, --target            Target URL to audit (Required)
-p, --profile           Scan profile: FULL, OWASP_TOP_10, API_SECURITY, NUCLEI_ONLY, QUICK_HEADERS, RECON_ONLY
-d, --depth             Maximum crawling depth (Default: 3)
-m, --max-endpoints     Maximum endpoint count cap (Default: 50)
-c, --concurrency       Concurrent HTTP workers (Default: 10)
--timeout               HTTP request timeout in seconds (Default: 10)
--header                Custom HTTP header (e.g. --header "X-Custom: value")
--auth                  Bearer Authorization token
--report-html           Save standalone HTML report file
--report-json           Save JSON findings file
--report-md             Save Markdown report file
--fail-on-critical      Exit with code 1 if Critical or High severity flaws are found
```

---

## 📁 Repository Structure

```
Automated Web & API Vulnerability Scanner/
├── app/                        # FastAPI Backend & Dashboard UI
│   ├── api/                    # API Route endpoints (Scans, Vulns, Endpoints, Templates, Reports)
│   ├── services/               # Scan service, Retest service, Report generator
│   ├── static/                 # Cyber Dark SPA UI (HTML, CSS, JS)
│   ├── config.py               # Application settings
│   ├── database.py             # Database engine & session
│   ├── models.py               # SQLAlchemy ORM models
│   ├── schemas.py              # Pydantic request/response schemas
│   └── main.py                 # FastAPI application root
├── scanner/                    # Core Scanning Engine
│   ├── checks/                 # Built-in Security Checks (SQLi, XSS, Headers, Files, Traversal, API)
│   ├── crawler.py              # Web & REST/GraphQL Crawler & Secret Scraper
│   ├── engine.py               # Master Orchestrator & Risk Scorer
│   └── models.py               # Internal data models & enums
├── nuclei/                     # Nuclei YAML Engine & Templates
│   ├── native_engine.py        # Native Python YAML template evaluator
│   ├── runner.py               # Unified Nuclei runner
│   └── templates/              # Reusable Nuclei YAML templates
├── test_target/                # Intentionally Vulnerable Testbed (Demo Target)
│   └── vulnerable_app.py       # OWASP Top 10 demo target API
├── cli.py                      # Command-line interface for CI/CD
├── run.sh                      # One-click startup script
├── Dockerfile                  # Container definition
├── docker-compose.yml          # Scanner + PostgreSQL compose
└── requirements.txt            # Python dependencies
```

---

## 🔒 Security & Ethical Notice

This tool is designed strictly for authorized penetration testing, security auditing, and defensive vulnerability management on systems you own or have explicit written permission to test. Unauthorized testing of target systems is strictly illegal.
