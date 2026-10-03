"""
Web Application and REST API Crawler & Endpoint Discovery Engine.
Extracts links, forms, JS endpoints, API definitions (OpenAPI/Swagger), GraphQL endpoints, and secrets.
"""

import re
import urllib.parse
from typing import List, Set, Dict, Any, Optional, Callable
import httpx
from bs4 import BeautifulSoup

from .models import EndpointItem, CrawlResult, ScanConfig


class Crawler:
    """Intelligent crawler for web pages, single page apps, and REST/GraphQL APIs."""

    # Common API Spec paths
    API_SPEC_PATHS = [
        "/openapi.json",
        "/swagger.json",
        "/api/swagger.json",
        "/api/openapi.json",
        "/v1/openapi.json",
        "/v2/api-docs",
        "/v3/api-docs",
        "/api-docs",
        "/docs",
        "/redoc",
    ]

    # GraphQL endpoint candidates
    GRAPHQL_PATHS = [
        "/graphql",
        "/api/graphql",
        "/v1/graphql",
        "/graphiql",
        "/query",
    ]

    # Sensitive / Interesting paths
    COMMON_PROBE_PATHS = [
        "/robots.txt",
        "/sitemap.xml",
        "/.well-known/security.txt",
        "/api/",
        "/api/v1/",
        "/api/v2/",
        "/actuator",
        "/actuator/health",
        "/actuator/env",
        "/health",
        "/status",
        "/metrics",
    ]

    # Regex patterns for finding API routes in JS files
    API_ROUTE_REGEX = re.compile(
        r"""(?:["'`])((?:/api/|/v1/|/v2/|/v3/|/auth/|/users/|/admin/|/graphql)[a-zA-Z0-9_\-/{}]*)(?:["'`])""",
        re.IGNORECASE,
    )

    # Regex patterns for finding secrets / API keys in JS files or HTML
    SECRET_PATTERNS = [
        ("Generic API Key", re.compile(r"""(?:api_key|apikey|secret_key|apiSecret|access_token)\s*[:=]\s*["']([A-Za-z0-9_\-]{16,64})["']""", re.IGNORECASE)),
        ("JWT Token", re.compile(r"""eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*""")),
        ("AWS Access Key ID", re.compile(r"""(AKIA[0-9A-Z]{16})""")),
        ("Generic Private Key", re.compile(r"""-----BEGIN PRIVATE KEY-----""")),
        ("Slack Webhook", re.compile(r"""https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+""")),
    ]

    def __init__(self, config: ScanConfig, log_cb: Optional[Callable[[str], None]] = None):
        self.config = config
        self.log_cb = log_cb or (lambda msg: None)
        self.visited_urls: Set[str] = set()
        self.discovered_endpoints: Dict[str, EndpointItem] = {}
        self.forms: List[Dict[str, Any]] = []
        self.js_files: Set[str] = set()
        self.api_specs: List[Dict[str, Any]] = []
        self.secrets: List[Dict[str, Any]] = []

        parsed = urllib.parse.urlparse(config.target_url)
        self.base_domain = parsed.netloc
        self.base_scheme = parsed.scheme or "http"
        self.base_url = f"{self.base_scheme}://{self.base_domain}"

    def _log(self, msg: str):
        self.log_cb(f"[Crawler] {msg}")

    def _get_headers(self) -> Dict[str, str]:
        headers = {
            "User-Agent": self.config.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,application/json,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }
        if self.config.cookie:
            headers["Cookie"] = self.config.cookie
        if self.config.auth_token:
            headers["Authorization"] = f"Bearer {self.config.auth_token}" if not self.config.auth_token.lower().startswith("bearer ") else self.config.auth_token
        headers.update(self.config.custom_headers)
        return headers

    def _normalize_url(self, raw_url: str, current_url: str) -> Optional[str]:
        """Normalize URL and check if within scope."""
        if not raw_url or raw_url.startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
            return None
        joined = urllib.parse.urljoin(current_url, raw_url)
        parsed = urllib.parse.urlparse(joined)
        # Remove fragment
        cleaned = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, parsed.query, ""))
        if parsed.netloc.lower() == self.base_domain.lower():
            return cleaned
        return None

    def _extract_query_params(self, url: str) -> List[str]:
        parsed = urllib.parse.urlparse(url)
        if parsed.query:
            qs = urllib.parse.parse_qs(parsed.query)
            return list(qs.keys())
        return []

    async def crawl(self) -> CrawlResult:
        """Main crawl execution routine."""
        self._log(f"Starting reconnaissance on target: {self.config.target_url}")

        transport = httpx.AsyncHTTPTransport(verify=False)
        async with httpx.AsyncClient(
            headers=self._get_headers(),
            timeout=self.config.timeout,
            follow_redirects=True,
            transport=transport,
        ) as client:
            # Step 1: Probe standard discovery endpoints (OpenAPI, GraphQL, robots.txt, etc.)
            await self._probe_standard_paths(client)

            # Step 2: Crawl HTML & REST links up to max depth / max endpoints
            queue = [(self.config.target_url, 0)]
            self.visited_urls.add(self.config.target_url)

            while queue and len(self.discovered_endpoints) < self.config.max_endpoints:
                current_url, depth = queue.pop(0)
                if depth > self.config.max_depth:
                    continue

                try:
                    self._log(f"Crawling (depth {depth}): {current_url}")
                    resp = await client.get(current_url)
                    content_type = resp.headers.get("content-type", "")

                    # Register current endpoint
                    params = self._extract_query_params(current_url)
                    self._add_endpoint(
                        url=current_url,
                        method="GET",
                        status_code=resp.status_code,
                        content_type=content_type,
                        params=params,
                        source="crawler",
                    )

                    # Check for secrets in response text
                    self._scan_for_secrets(resp.text, current_url)

                    # If HTML, parse links, scripts, and forms
                    if "text/html" in content_type:
                        soup = BeautifulSoup(resp.text, "html.parser")

                        # 1. Extract Links
                        for a_tag in soup.find_all("a", href=True):
                            norm_link = self._normalize_url(a_tag["href"], current_url)
                            if norm_link and norm_link not in self.visited_urls:
                                self.visited_urls.add(norm_link)
                                queue.append((norm_link, depth + 1))

                        # 2. Extract Forms & inputs
                        for form in soup.find_all("form"):
                            form_action = form.get("action", "") or current_url
                            form_method = form.get("method", "GET").upper()
                            norm_action = self._normalize_url(form_action, current_url) or current_url

                            form_params = []
                            for input_tag in form.find_all(["input", "textarea", "select"]):
                                name = input_tag.get("name")
                                if name:
                                    form_params.append(name)

                            form_data = {
                                "action": norm_action,
                                "method": form_method,
                                "page": current_url,
                                "parameters": form_params,
                            }
                            self.forms.append(form_data)
                            self._add_endpoint(
                                url=norm_action,
                                method=form_method,
                                params=form_params,
                                source="form",
                            )

                        # 3. Extract JS scripts
                        for script in soup.find_all("script", src=True):
                            js_url = self._normalize_url(script["src"], current_url)
                            if js_url and js_url not in self.js_files:
                                self.js_files.add(js_url)

                    # If JSON response, inspect keys
                    elif "application/json" in content_type:
                        try:
                            json_obj = resp.json()
                            if isinstance(json_obj, list) and json_obj:
                                first = json_obj[0]
                                if isinstance(first, dict):
                                    self._add_endpoint(
                                        url=current_url,
                                        method="GET",
                                        status_code=resp.status_code,
                                        content_type=content_type,
                                        params=list(first.keys())[:10],
                                        source="api_json",
                                    )
                        except Exception:
                            pass

                except Exception as e:
                    self._log(f"Error requesting {current_url}: {str(e)}")

            # Step 3: Analyze JS files for hidden API routes & tokens
            await self._analyze_js_files(client)

        self._log(f"Recon complete. Discovered {len(self.discovered_endpoints)} endpoints, {len(self.forms)} forms, {len(self.js_files)} JS assets, {len(self.api_specs)} API specs.")

        return CrawlResult(
            target_url=self.config.target_url,
            endpoints=list(self.discovered_endpoints.values()),
            discovered_urls=list(self.visited_urls),
            forms=self.forms,
            js_files=list(self.js_files),
            api_specs=self.api_specs,
            secrets_leaked=self.secrets,
        )

    def _add_endpoint(
        self,
        url: str,
        method: str = "GET",
        status_code: Optional[int] = None,
        content_type: Optional[str] = None,
        params: Optional[List[str]] = None,
        source: str = "crawler",
    ):
        key = f"{method.upper()}:{url.split('?')[0]}"
        if key in self.discovered_endpoints:
            # Merge parameters
            existing = self.discovered_endpoints[key]
            if params:
                merged = list(set(existing.parameters + params))
                existing.parameters = merged
            if status_code and not existing.status_code:
                existing.status_code = status_code
        else:
            self.discovered_endpoints[key] = EndpointItem(
                url=url,
                method=method.upper(),
                status_code=status_code,
                content_type=content_type,
                parameters=params or [],
                source=source,
            )

    async def _probe_standard_paths(self, client: httpx.AsyncClient):
        """Probes OpenAPI, Swagger, robots, sitemap, and actuator endpoints."""
        # 1. OpenAPI / Swagger Specs
        for path in self.API_SPEC_PATHS:
            target_spec = urllib.parse.urljoin(self.base_url, path)
            try:
                resp = await client.get(target_spec)
                if resp.status_code == 200:
                    try:
                        spec_json = resp.json()
                        if "paths" in spec_json or "openapi" in spec_json or "swagger" in spec_json:
                            self._log(f"Discovered OpenAPI / Swagger specification at: {target_spec}")
                            self.api_specs.append({"url": target_spec, "spec": spec_json})
                            self._parse_openapi_spec(spec_json)
                    except Exception:
                        pass
            except Exception:
                pass

        # 2. GraphQL Discovery
        for path in self.GRAPHQL_PATHS:
            gql_url = urllib.parse.urljoin(self.base_url, path)
            try:
                # Test with simple schema introspection query
                query = {"query": "{ __schema { types { name } } }"}
                resp = await client.post(gql_url, json=query)
                if resp.status_code in [200, 400] and ("data" in resp.text or "__schema" in resp.text or "GraphQL" in resp.text or "errors" in resp.text):
                    self._log(f"Discovered GraphQL Endpoint at: {gql_url}")
                    self._add_endpoint(
                        url=gql_url,
                        method="POST",
                        status_code=resp.status_code,
                        content_type="application/json",
                        params=["query", "variables"],
                        source="graphql",
                    )
            except Exception:
                pass

        # 3. Robots.txt & Sitemap
        try:
            robots_url = urllib.parse.urljoin(self.base_url, "/robots.txt")
            resp = await client.get(robots_url)
            if resp.status_code == 200 and "User-agent:" in resp.text:
                self._log(f"Found robots.txt at {robots_url}")
                for line in resp.text.splitlines():
                    if line.strip().lower().startswith(("disallow:", "allow:")):
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            rpath = parts[1].strip()
                            if rpath and not rpath.startswith("*"):
                                full_url = urllib.parse.urljoin(self.base_url, rpath)
                                self._add_endpoint(full_url, "GET", source="robots.txt")
        except Exception:
            pass

    def _parse_openapi_spec(self, spec: Dict[str, Any]):
        """Extracts REST API routes, HTTP methods, and parameters from OpenAPI/Swagger JSON."""
        paths = spec.get("paths", {})
        base_path = spec.get("basePath", "")
        for route_path, methods in paths.items():
            full_path = f"{base_path.rstrip('/')}/{route_path.lstrip('/')}"
            full_url = urllib.parse.urljoin(self.base_url, full_path)
            for method, details in methods.items():
                if method.lower() in ["get", "post", "put", "delete", "patch", "options"]:
                    params = []
                    # Path/Query parameters
                    for p in details.get("parameters", []):
                        if isinstance(p, dict) and "name" in p:
                            params.append(p["name"])
                    # Request Body parameters
                    if "requestBody" in details:
                        content = details["requestBody"].get("content", {})
                        for _, schema_data in content.items():
                            schema = schema_data.get("schema", {})
                            props = schema.get("properties", {})
                            params.extend(props.keys())

                    self._add_endpoint(
                        url=full_url,
                        method=method.upper(),
                        params=params,
                        source="openapi",
                    )

    async def _analyze_js_files(self, client: httpx.AsyncClient):
        """Fetches discovered JavaScript files and scans for hidden endpoints & API tokens."""
        for js_url in list(self.js_files)[:15]:  # limit to top 15 JS files
            try:
                resp = await client.get(js_url)
                if resp.status_code == 200:
                    text = resp.text
                    # Check for secrets
                    self._scan_for_secrets(text, js_url)

                    # Check for embedded API routes
                    matches = self.API_ROUTE_REGEX.findall(text)
                    for match in set(matches):
                        full_route = urllib.parse.urljoin(self.base_url, match)
                        self._add_endpoint(url=full_route, method="GET", source="js_scraper")
            except Exception:
                pass

    def _scan_for_secrets(self, content: str, source_url: str):
        """Scans response or script content for leaked API tokens, keys, and credentials."""
        for secret_name, pattern in self.SECRET_PATTERNS:
            matches = pattern.findall(content)
            for match in matches:
                secret_str = match if isinstance(match, str) else match[0]
                # Filter out obvious false positives
                if len(secret_str) > 8 and not secret_str.startswith("http"):
                    self.secrets.append({
                        "type": secret_name,
                        "value": f"{secret_str[:6]}...{secret_str[-4:]}",
                        "raw_snippet": secret_str[:50],
                        "source": source_url,
                    })
