/**
 * Antigravity Vulnerability Scanner - Single Page Application Core
 */

class ScannerApp {
    constructor() {
        this.activeScanId = null;
        this.activeFindingId = null;
        this.pollInterval = null;
        this.statsInterval = null;
        this.templates = [];

        this.init();
    }

    init() {
        this.bindEvents();
        this.loadDashboardStats();
        this.loadRecentScans();
        this.loadTemplates();
        this.loadEndpoints();

        // Background polling for real-time stats
        this.statsInterval = setInterval(() => {
            this.loadDashboardStats();
            if (this.activeScanId) {
                this.pollActiveScan();
            }
        }, 2500);
    }

    bindEvents() {
        // Tab Navigation
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', (e) => {
                const tab = item.getAttribute('data-tab');
                this.switchTab(tab);
            });
        });

        // Quick Scan Launch
        const btnQuick = document.getElementById('btn-quick-scan');
        if (btnQuick) {
            btnQuick.addEventListener('click', () => this.handleQuickScan());
        }

        // Enter key on target input
        const inputTarget = document.getElementById('quick-target-url');
        if (inputTarget) {
            inputTarget.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') this.handleQuickScan();
            });
        }

        // Refresh dashboard button
        const btnRefresh = document.getElementById('btn-refresh-dashboard');
        if (btnRefresh) {
            btnRefresh.addEventListener('click', () => {
                this.loadDashboardStats();
                this.loadRecentScans();
                this.showToast('Dashboard data refreshed', 'info');
            });
        }

        // Stop active scan
        const btnStop = document.getElementById('btn-stop-active-scan');
        if (btnStop) {
            btnStop.addEventListener('click', () => this.stopActiveScan());
        }

        // Triage Filters
        const btnFilter = document.getElementById('btn-filter-triage');
        if (btnFilter) {
            btnFilter.addEventListener('click', () => this.loadVulnerabilities());
        }

        // Drawer Status Change
        const selectStatus = document.getElementById('drawer-status-select');
        if (selectStatus) {
            selectStatus.addEventListener('change', (e) => this.handleUpdateFindingStatus(e.target.value));
        }

        // Retest Finding Button
        const btnRetest = document.getElementById('btn-retest-finding');
        if (btnRetest) {
            btnRetest.addEventListener('click', () => this.handleRetestFinding());
        }

        // Template Test Runner
        const btnTmplTest = document.getElementById('btn-run-template-test');
        if (btnTmplTest) {
            btnTmplTest.addEventListener('click', () => this.handleRunTemplateTest());
        }

        // Reports Viewers & Downloads
        const scanSelector = document.getElementById('report-scan-selector');
        if (scanSelector) {
            scanSelector.addEventListener('change', (e) => this.handleReportScanSelect(e.target.value));
        }

        document.getElementById('btn-view-html-report')?.addEventListener('click', () => {
            const sid = document.getElementById('report-scan-selector').value;
            if (sid) window.open(`/api/reports/${sid}/html`, '_blank');
        });

        document.getElementById('btn-download-json-report')?.addEventListener('click', () => {
            const sid = document.getElementById('report-scan-selector').value;
            if (sid) window.open(`/api/reports/${sid}/json`, '_blank');
        });

        document.getElementById('btn-download-md-report')?.addEventListener('click', () => {
            const sid = document.getElementById('report-scan-selector').value;
            if (sid) window.open(`/api/reports/${sid}/markdown`, '_blank');
        });

        document.getElementById('btn-download-csv-report')?.addEventListener('click', () => {
            const sid = document.getElementById('report-scan-selector').value;
            if (sid) window.open(`/api/reports/${sid}/csv`, '_blank');
        });
    }

    switchTab(tabName) {
        document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
        document.querySelectorAll('.tab-view').forEach(el => el.classList.remove('active'));

        const targetNav = document.querySelector(`.nav-item[data-tab="${tabName}"]`);
        const targetView = document.getElementById(`view-${tabName}`);

        if (targetNav) targetNav.classList.add('active');
        if (targetView) targetView.classList.add('active');

        // Refresh tab-specific data
        if (tabName === 'triage') this.loadVulnerabilities();
        if (tabName === 'scans') this.loadScansHistory();
        if (tabName === 'endpoints') this.loadEndpoints();
        if (tabName === 'reports') this.loadReportsDropdown();
    }

    async fetchJson(url, options = {}) {
        try {
            const resp = await fetch(url, options);
            if (!resp.ok) {
                const err = await resp.json().catch(() => ({ detail: resp.statusText }));
                throw new Error(err.detail || `HTTP Error ${resp.status}`);
            }
            return await resp.json();
        } catch (e) {
            console.error(`Fetch error on ${url}:`, e);
            throw e;
        }
    }

    // ==========================================
    // Dashboard & Metrics
    // ==========================================

    async loadDashboardStats() {
        try {
            const stats = await this.fetchJson('/api/system/stats');
            document.getElementById('stat-critical').textContent = stats.critical_count;
            document.getElementById('stat-high').textContent = stats.high_count;
            document.getElementById('stat-medium').textContent = stats.medium_count;
            document.getElementById('stat-low-info').textContent = stats.low_count + stats.info_count;
            document.getElementById('stat-total-scans').textContent = stats.total_scans;

            // Nav badges
            const openBadge = document.getElementById('open-findings-badge');
            if (openBadge) openBadge.textContent = stats.total_findings;

            const activeBadge = document.getElementById('active-scans-badge');
            if (activeBadge) {
                if (stats.active_scans_count > 0) {
                    activeBadge.textContent = stats.active_scans_count;
                    activeBadge.style.display = 'inline-block';
                } else {
                    activeBadge.style.display = 'none';
                }
            }

            // Check if there is an active running scan to monitor
            const runningScan = stats.recent_scans.find(s => s.status === 'RUNNING');
            if (runningScan) {
                this.activeScanId = runningScan.id;
                this.showActiveScanMonitor(runningScan);
            }
        } catch (e) {
            console.error('Failed to load stats:', e);
        }
    }

    async loadRecentScans() {
        try {
            const scans = await this.fetchJson('/api/scans?limit=5');
            const tbody = document.getElementById('dashboard-recent-scans-body');
            if (!tbody) return;

            if (scans.length === 0) {
                tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 30px;">No scans executed yet.</td></tr>`;
                return;
            }

            tbody.innerHTML = scans.map(s => `
                <tr onclick="app.viewScan('${s.id}')">
                    <td><code class="table-code">${this.escapeHtml(s.target_url)}</code></td>
                    <td><span style="font-size: 11px; font-weight: 600; color: var(--accent-cyan);">${s.profile}</span></td>
                    <td><span class="badge-status status-${s.status}">${s.status}</span></td>
                    <td>
                        <span class="badge-sev badge-CRITICAL" style="font-size: 10px; padding: 1px 5px;">${s.critical_count}</span>
                        <span class="badge-sev badge-HIGH" style="font-size: 10px; padding: 1px 5px;">${s.high_count}</span>
                        <span class="badge-sev badge-MEDIUM" style="font-size: 10px; padding: 1px 5px;">${s.medium_count}</span>
                    </td>
                    <td><strong>${s.risk_score}</strong>/100</td>
                    <td>
                        <button class="btn btn-secondary btn-sm" onclick="event.stopPropagation(); app.viewScan('${s.id}')">View</button>
                    </td>
                </tr>
            `).join('');
        } catch (e) {
            console.error(e);
        }
    }

    // ==========================================
    // Scan Operations & Live Console
    // ==========================================

    async handleQuickScan() {
        const input = document.getElementById('quick-target-url');
        const profile = document.getElementById('quick-profile').value;
        const targetUrl = input.value.trim();

        if (!targetUrl) {
            this.showToast('Please enter a target URL (e.g. http://localhost:8888)', 'error');
            return;
        }

        try {
            const payload = {
                target_url: targetUrl,
                profile: profile,
                max_depth: 3,
                max_endpoints: 60,
                enable_nuclei: true,
            };

            const job = await this.fetchJson('/api/scans', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });

            this.activeScanId = job.id;
            this.showToast(`Scan launched for ${targetUrl}`, 'success');
            this.switchTab('scans');
            this.showActiveScanMonitor(job);
            this.loadDashboardStats();
        } catch (e) {
            this.showToast(`Failed to launch scan: ${e.message}`, 'error');
        }
    }

    launchDemoTargetScan() {
        document.getElementById('quick-target-url').value = 'http://127.0.0.1:8888';
        document.getElementById('quick-profile').value = 'FULL';
        this.handleQuickScan();
    }

    showActiveScanMonitor(job) {
        const monitor = document.getElementById('active-scan-monitor');
        if (!monitor) return;
        monitor.style.display = 'block';

        document.getElementById('active-monitor-target').textContent = job.target_url;
        document.getElementById('active-monitor-phase').textContent = job.current_phase || 'RUNNING';
        document.getElementById('active-monitor-pct').textContent = `${job.progress}%`;
        document.getElementById('active-monitor-progress-bar').style.width = `${job.progress}%`;
    }

    async pollActiveScan() {
        if (!this.activeScanId) return;

        try {
            const details = await this.fetchJson(`/api/scans/${this.activeScanId}`);
            this.showActiveScanMonitor(details);

            // Update terminal logs
            const terminal = document.getElementById('active-terminal-logs');
            if (terminal && details.log_text) {
                const lines = details.log_text.split('\n');
                terminal.innerHTML = lines.map(line => {
                    let cls = 'log-entry';
                    if (line.includes('[Crawler]')) cls += ' info';
                    else if (line.includes('CRITICAL') || line.includes('Error')) cls += ' crit';
                    else if (line.includes('Nuclei Match') || line.includes('confirmed')) cls += ' crit';
                    else if (line.includes('warning') || line.includes('HIGH')) cls += ' warn';
                    else if (line.includes('complete') || line.includes('finished')) cls += ' success';
                    return `<div class="${cls}">${this.escapeHtml(line)}</div>`;
                }).join('');
                terminal.scrollTop = terminal.scrollHeight;
            }

            if (details.status !== 'RUNNING' && details.status !== 'PENDING') {
                this.activeScanId = null;
                this.showToast(`Scan ${details.status}: Found ${details.critical_count + details.high_count + details.medium_count} vulnerabilities!`, 'success');
                this.loadScansHistory();
                this.loadDashboardStats();
            }
        } catch (e) {
            console.error('Poll error:', e);
        }
    }

    async stopActiveScan() {
        if (!this.activeScanId) return;
        try {
            await this.fetchJson(`/api/scans/${this.activeScanId}/stop`, { method: 'POST' });
            this.showToast('Scan abort signal sent', 'info');
        } catch (e) {
            this.showToast(`Failed to stop scan: ${e.message}`, 'error');
        }
    }

    async loadScansHistory() {
        try {
            const scans = await this.fetchJson('/api/scans?limit=50');
            const tbody = document.getElementById('scans-history-body');
            if (!tbody) return;

            if (scans.length === 0) {
                tbody.innerHTML = `<tr><td colspan="10" style="text-align: center; color: var(--text-muted); padding: 30px;">No scan history.</td></tr>`;
                return;
            }

            tbody.innerHTML = scans.map(s => `
                <tr onclick="app.viewScan('${s.id}')">
                    <td><code class="table-code">${s.id.substring(0, 8)}</code></td>
                    <td><code class="table-code">${this.escapeHtml(s.target_url)}</code></td>
                    <td><span style="font-size: 11px; font-weight: 600; color: var(--accent-cyan);">${s.profile}</span></td>
                    <td><span class="badge-status status-${s.status}">${s.status}</span></td>
                    <td>${s.total_endpoints}</td>
                    <td>
                        <span class="badge-sev badge-CRITICAL" style="font-size: 10px;">${s.critical_count}</span>
                        <span class="badge-sev badge-HIGH" style="font-size: 10px;">${s.high_count}</span>
                        <span class="badge-sev badge-MEDIUM" style="font-size: 10px;">${s.medium_count}</span>
                    </td>
                    <td><strong>${s.risk_score}</strong>/100</td>
                    <td>${s.duration_seconds}s</td>
                    <td style="font-size: 12px; color: var(--text-muted);">${new Date(s.start_time).toLocaleTimeString()}</td>
                    <td>
                        <button class="btn btn-secondary btn-sm" onclick="event.stopPropagation(); app.viewScan('${s.id}')">View</button>
                    </td>
                </tr>
            `).join('');
        } catch (e) {
            console.error(e);
        }
    }

    viewScan(scanId) {
        this.switchTab('triage');
        this.loadVulnerabilities(scanId);
    }

    // ==========================================
    // Vulnerability Triage & Retesting
    // ==========================================

    async loadVulnerabilities(scanId = null) {
        try {
            const search = document.getElementById('triage-search')?.value || '';
            const sev = document.getElementById('triage-filter-severity')?.value || '';
            const status = document.getElementById('triage-filter-status')?.value || '';

            let queryParams = new URLSearchParams();
            if (scanId) queryParams.append('scan_id', scanId);
            if (search) queryParams.append('search', search);
            if (sev) queryParams.append('severity', sev);
            if (status) queryParams.append('status', status);

            const findings = await this.fetchJson(`/api/vulnerabilities?${queryParams.toString()}`);
            const tbody = document.getElementById('triage-findings-body');
            if (!tbody) return;

            if (findings.length === 0) {
                tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 40px;">No vulnerabilities found matching filters.</td></tr>`;
                return;
            }

            tbody.innerHTML = findings.map(f => `
                <tr onclick="app.openFindingDetail('${f.id}')">
                    <td><span class="badge-sev badge-${f.severity}">${f.severity}</span></td>
                    <td style="font-weight: 600;">${this.escapeHtml(f.title)}</td>
                    <td style="font-size: 12px; color: var(--text-muted);">${this.escapeHtml(f.category)}</td>
                    <td>
                        <span class="method-badge method-${f.method}">${f.method}</span>
                        <code class="table-code">${this.escapeHtml(f.endpoint)}</code>
                    </td>
                    <td><strong>${f.cvss_score}</strong></td>
                    <td><span class="badge-status status-${f.status}">${f.status}</span></td>
                    <td><span style="font-size: 11px; text-transform: uppercase; color: var(--accent-cyan); font-family: 'JetBrains Mono', monospace;">${f.check_source}</span></td>
                    <td>
                        <button class="btn btn-secondary btn-sm" onclick="event.stopPropagation(); app.openFindingDetail('${f.id}')">Inspect</button>
                    </td>
                </tr>
            `).join('');
        } catch (e) {
            console.error(e);
        }
    }

    async openFindingDetail(findingId) {
        this.activeFindingId = findingId;
        try {
            const f = await this.fetchJson(`/api/vulnerabilities/${findingId}`);
            
            // Populate Drawer Fields
            const badge = document.getElementById('drawer-severity-badge');
            badge.className = `badge-sev badge-${f.severity}`;
            badge.textContent = f.severity;

            document.getElementById('drawer-cwe').textContent = f.cwe_id || 'CWE-Unknown';
            document.getElementById('drawer-cvss').textContent = `CVSS v3.1: ${f.cvss_score}`;
            document.getElementById('drawer-title').textContent = f.title;

            const methodBadge = document.getElementById('drawer-method');
            methodBadge.className = `method-badge method-${f.method}`;
            methodBadge.textContent = f.method;

            document.getElementById('drawer-endpoint').textContent = f.endpoint + (f.parameter ? ` [Param: ${f.parameter}]` : '');
            document.getElementById('drawer-description').textContent = f.description;
            document.getElementById('drawer-evidence').textContent = f.evidence;
            document.getElementById('drawer-remediation').textContent = f.remediation;

            document.getElementById('drawer-status-select').value = f.status;

            // Reset Retest Banner
            const retestBanner = document.getElementById('retest-result-banner');
            retestBanner.style.display = 'none';

            // Show Drawer
            document.getElementById('finding-drawer').classList.add('active');
        } catch (e) {
            this.showToast(`Failed to load finding: ${e.message}`, 'error');
        }
    }

    closeDrawer() {
        document.getElementById('finding-drawer').classList.remove('active');
        this.activeFindingId = null;
    }

    async handleUpdateFindingStatus(newStatus) {
        if (!this.activeFindingId) return;
        try {
            await this.fetchJson(`/api/vulnerabilities/${this.activeFindingId}/status`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ status: newStatus }),
            });
            this.showToast(`Status updated to ${newStatus}`, 'success');
            this.loadVulnerabilities();
            this.loadDashboardStats();
        } catch (e) {
            this.showToast(`Failed to update status: ${e.message}`, 'error');
        }
    }

    async handleRetestFinding() {
        if (!this.activeFindingId) return;
        const btn = document.getElementById('btn-retest-finding');
        const banner = document.getElementById('retest-result-banner');
        
        btn.disabled = true;
        btn.innerHTML = `<span>⏳</span> Retesting Target...`;
        banner.style.display = 'none';

        try {
            const res = await this.fetchJson(`/api/vulnerabilities/${this.activeFindingId}/retest`, {
                method: 'POST',
            });

            banner.style.display = 'block';
            if (res.still_vulnerable) {
                banner.style.background = 'rgba(239, 68, 68, 0.15)';
                banner.style.border = '1px solid #EF4444';
                banner.style.color = '#FCA5A5';
                banner.innerHTML = `<strong>⚠️ Verification Result: Still Vulnerable</strong><div style="margin-top: 4px;">${this.escapeHtml(res.evidence)}</div>`;
                this.showToast('Retest complete: Target is still vulnerable.', 'error');
            } else {
                banner.style.background = 'rgba(16, 185, 129, 0.15)';
                banner.style.border = '1px solid #10B981';
                banner.style.color = '#6EE7B7';
                banner.innerHTML = `<strong>🎉 Verification Result: Remediated!</strong><div style="margin-top: 4px;">${this.escapeHtml(res.evidence)}</div>`;
                this.showToast('Retest verified: Vulnerability resolved!', 'success');
                document.getElementById('drawer-status-select').value = 'RESOLVED';
            }

            this.loadVulnerabilities();
            this.loadDashboardStats();
        } catch (e) {
            this.showToast(`Retest failed: ${e.message}`, 'error');
        } finally {
            btn.disabled = false;
            btn.innerHTML = `<span>🔄</span> Retest Vulnerability`;
        }
    }

    // ==========================================
    // Endpoints & API Explorer
    // ==========================================

    async loadEndpoints() {
        try {
            const endpoints = await this.fetchJson('/api/endpoints?limit=200');
            const tbody = document.getElementById('endpoints-inventory-body');
            if (!tbody) return;

            if (endpoints.length === 0) {
                tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 30px;">No endpoints discovered yet.</td></tr>`;
                return;
            }

            tbody.innerHTML = endpoints.map(ep => `
                <tr>
                    <td><span class="method-badge method-${ep.method}">${ep.method}</span></td>
                    <td><code class="table-code">${this.escapeHtml(ep.url)}</code></td>
                    <td><span style="font-family: 'JetBrains Mono', monospace; font-size: 12px; color: ${ep.status_code === 200 ? '#34D399' : '#94A3B8'};">${ep.status_code || '---'}</span></td>
                    <td>${ep.parameters && ep.parameters.length > 0 ? ep.parameters.map(p => `<code class="table-code" style="margin-right: 4px;">${this.escapeHtml(p)}</code>`).join('') : '<span style="color: var(--text-muted);">None</span>'}</td>
                    <td><span style="font-size: 11px; text-transform: uppercase; color: var(--accent-cyan); font-family: 'JetBrains Mono', monospace;">${ep.source}</span></td>
                </tr>
            `).join('');
        } catch (e) {
            console.error(e);
        }
    }

    // ==========================================
    // Nuclei Template Studio
    // ==========================================

    async loadTemplates() {
        try {
            const res = await this.fetchJson('/api/templates');
            this.templates = res.templates || [];
            const container = document.getElementById('templates-list-container');
            if (!container) return;

            container.innerHTML = this.templates.map(t => `
                <div style="background: rgba(255,255,255,0.02); border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); padding: 12px; margin-bottom: 8px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                        <span style="font-weight: 700; font-size: 13.5px; color: #FFF;">${this.escapeHtml(t.name)}</span>
                        <span class="badge-sev badge-${t.severity}">${t.severity}</span>
                    </div>
                    <div style="font-size: 12px; color: var(--text-secondary); margin-bottom: 6px;">${this.escapeHtml(t.description)}</div>
                    <div style="font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--accent-cyan);">ID: ${t.id} &bull; Tags: ${t.tags}</div>
                </div>
            `).join('');

            // Sample template into tester
            const sampleYaml = `id: custom-header-disclosure-check
info:
  name: Custom Header Information Disclosure Check
  author: security-researcher
  severity: medium
  description: Checks if sensitive server banner or debug headers are disclosed.
  tags: headers,disclosure

http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers-condition: or
    matchers:
      - type: word
        part: header
        words:
          - "X-Powered-By"
          - "Server"
`;
            const yamlBox = document.getElementById('template-test-yaml');
            if (yamlBox && !yamlBox.value) yamlBox.value = sampleYaml;
        } catch (e) {
            console.error(e);
        }
    }

    async handleRunTemplateTest() {
        const targetUrl = document.getElementById('template-test-target').value.trim();
        const yamlContent = document.getElementById('template-test-yaml').value.trim();
        const resultsDiv = document.getElementById('template-test-results');

        if (!targetUrl || !yamlContent) {
            this.showToast('Please provide both Target URL and YAML content.', 'error');
            return;
        }

        resultsDiv.innerHTML = `<div style="color: var(--accent-cyan);">⏳ Executing Nuclei template against ${this.escapeHtml(targetUrl)}...</div>`;

        try {
            const res = await this.fetchJson('/api/templates/test', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target_url: targetUrl, yaml_content: yamlContent }),
            });

            if (res.matched) {
                resultsDiv.innerHTML = `
                    <div style="background: rgba(239, 68, 68, 0.15); border: 1px solid #EF4444; color: #FCA5A5; padding: 12px; border-radius: var(--radius-sm);">
                        <strong>🔥 MATCH CONFIRMED (${res.findings_count} finding(s))</strong>
                        <div style="font-family: 'JetBrains Mono', monospace; font-size: 11px; margin-top: 8px; white-space: pre-wrap;">${this.escapeHtml(res.findings[0]?.evidence || 'Match detected')}</div>
                    </div>
                `;
            } else {
                resultsDiv.innerHTML = `
                    <div style="background: rgba(16, 185, 129, 0.15); border: 1px solid #10B981; color: #6EE7B7; padding: 12px; border-radius: var(--radius-sm);">
                        <strong>✅ No Match</strong> - Target is not vulnerable to this template rule.
                    </div>
                `;
            }
        } catch (e) {
            resultsDiv.innerHTML = `<div style="color: #F87171;">Error: ${this.escapeHtml(e.message)}</div>`;
        }
    }

    // ==========================================
    // Executive Reports
    // ==========================================

    async loadReportsDropdown() {
        try {
            const scans = await this.fetchJson('/api/scans?limit=50');
            const selector = document.getElementById('report-scan-selector');
            if (!selector) return;

            selector.innerHTML = `<option value="">Select a completed scan...</option>` + scans.map(s => `
                <option value="${s.id}">${s.target_url} (${s.profile}) - ${new Date(s.start_time).toLocaleDateString()}</option>
            `).join('');

            if (scans.length > 0) {
                selector.value = scans[0].id;
                this.handleReportScanSelect(scans[0].id);
            }
        } catch (e) {
            console.error(e);
        }
    }

    handleReportScanSelect(scanId) {
        const frame = document.getElementById('report-preview-frame');
        if (frame && scanId) {
            frame.src = `/api/reports/${scanId}/html`;
        }
    }

    // ==========================================
    // Helpers & Utilities
    // ==========================================

    showToast(message, type = 'info') {
        const container = document.getElementById('toast-container');
        if (!container) return;

        const toast = document.createElement('div');
        toast.className = 'toast';
        const icon = type === 'error' ? '❌' : (type === 'success' ? '✅' : 'ℹ️');
        toast.innerHTML = `<span>${icon}</span> <span>${this.escapeHtml(message)}</span>`;
        container.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateY(10px)';
            setTimeout(() => toast.remove(), 250);
        }, 3500);
    }

    escapeHtml(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }
}

// Global instance
const app = new ScannerApp();
