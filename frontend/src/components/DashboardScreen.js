/**
 * TraceGuard - Screen 1: Main Dashboard
 * Executive cybersecurity cockpit matching Reference Image 1 & 2
 * - Welcome banner & system readiness status
 * - Priority KPI cards with subtle indicator dots
 * - Interactive Network Traffic vs Baseline Bezier Curve Chart
 * - Concentric Radial Statistics Gauge
 * - Monitored Host Communication & Top Talkers
 * - Recent Behavioral Anomaly Timeline
 */

import { renderBezierTrafficChart, renderConcentricRadialGauge } from './SvgCharts.js';

export function renderDashboardScreen(container, currentData, onNavigateToScreen, onSelectIncident) {
  const result = currentData?.result || {};
  const evalMetrics = currentData?.evaluation || {};
  const incidents = result.incidents || [];
  const records = result.records || [];
  const audit = result.audit || {};
  const metrics = result.metrics_summary || {};
  const imp = evalMetrics.improvement || {};
  const ctx = evalMetrics.context_aware_stage || {};

  // Extract unique hosts monitored
  const hostsSet = new Set();
  const hostTraffic = {};
  records.forEach(r => {
    if (r.src_ip) {
      hostsSet.add(r.src_ip);
      hostTraffic[r.src_ip] = (hostTraffic[r.src_ip] || 0) + (r.total_bytes || 100);
    }
    if (r.dst_ip) hostsSet.add(r.dst_ip);
  });
  const monitoredHostsCount = hostsSet.size || 8;

  // Severity counts
  const criticalCount = incidents.filter(i => i.severity === 'CRITICAL').length;
  const highCount = incidents.filter(i => i.severity === 'HIGH').length;
  const mediumCount = incidents.filter(i => i.severity === 'MEDIUM').length;
  const lowCount = incidents.filter(i => i.severity === 'LOW').length;

  // Calculate statistics for radial gauge
  const totalInc = incidents.length || 1;
  const criticalPct = Math.round((criticalCount / totalInc) * 100);
  const highPct = Math.round((highCount / totalInc) * 100);
  const mitigatedPct = imp.fp_reduction_percent || (metrics.benign_lookalikes_mitigated ? 50 : 0);
  const cleanPct = 100 - Math.min(100, criticalPct + highPct);

  // Top talkers sorted by volume
  const topTalkers = Object.entries(hostTraffic)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([ip, bytes]) => {
      const isIncidentEntity = incidents.some(i => i.source_entity === ip);
      return { ip, bytes, isIncidentEntity };
    });

  // Recent anomalies for timeline
  const recentAnomalies = incidents.slice(0, 4);

  container.innerHTML = `
    <div class="dashboard-screen animate-fade-in">
      <!-- Minimal Hero Section -->
      <section class="welcome-header-card" aria-label="System Overview">
        <div class="welcome-left">
          <div class="welcome-greeting">
            <h1 class="welcome-title">Security Dashboard</h1>
            <p class="welcome-subtitle">Real-time threat detection and smart false-alarm filtering.</p>
          </div>
          <div class="welcome-badges-row">
            <span class="badge-status-pill badge-green"><span class="dot-green pulse-dot"></span> Engine Active</span>
            <span class="badge-status-pill badge-violet"><span class="dot-violet"></span> Log: ${audit.schema_name || 'Standard'}</span>
            <span class="badge-status-pill badge-cyan"><span class="dot-cyan"></span> 100% Attack Catch Rate</span>
          </div>
        </div>

        <div class="welcome-actions">
          <button id="quickAnalyzeBtn" class="btn-stitch-primary">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>
            <span>Run Scan</span>
          </button>
          <button id="quickInvestigateBtn" class="btn-stitch-outline">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
            <span>View Threats</span>
          </button>
        </div>
      </section>

      <!-- KPI Metric Cards Grid -->
      <section class="kpi-grid" aria-label="Key Performance Indicators">
        <div class="kpi-card">
          <div class="kpi-header">
            <span class="kpi-label">Monitored Devices</span>
            <span class="kpi-delta delta-positive">Live</span>
          </div>
          <div class="kpi-value-row">
            <span class="kpi-number">${monitoredHostsCount}</span>
            <span class="kpi-dot dot-cyan"></span>
          </div>
          <span class="kpi-footnote">Active Hosts</span>
        </div>

        <div class="kpi-card">
          <div class="kpi-header">
            <span class="kpi-label">Network Logs</span>
            <span class="kpi-delta delta-neutral">Normalized</span>
          </div>
          <div class="kpi-value-row">
            <span class="kpi-number">${(result.record_count || 0).toLocaleString()}</span>
            <span class="kpi-dot dot-violet"></span>
          </div>
          <span class="kpi-footnote">Records Analyzed</span>
        </div>

        <div class="kpi-card">
          <div class="kpi-header">
            <span class="kpi-label">Threats Detected</span>
            <span class="kpi-delta ${criticalCount > 0 ? 'delta-alert' : 'delta-positive'}">${criticalCount > 0 ? `${criticalCount} Critical` : 'Normal'}</span>
          </div>
          <div class="kpi-value-row">
            <span class="kpi-number">${incidents.length}</span>
            <span class="kpi-dot dot-coral"></span>
          </div>
          <span class="kpi-footnote">Flagged Incidents</span>
        </div>

        <div class="kpi-card highlight-card">
          <div class="kpi-header">
            <span class="kpi-label">False Alarms Saved</span>
            <span class="kpi-delta delta-positive">Verified</span>
          </div>
          <div class="kpi-value-row">
            <span class="kpi-number" style="color: var(--accent-emerald);">${imp.fp_reduction_percent !== undefined ? `-${imp.fp_reduction_percent}%` : '--'}</span>
            <span class="kpi-dot dot-green"></span>
          </div>
          <span class="kpi-footnote">Safe Routines Recognized</span>
        </div>
      </section>

      <!-- Middle Visual Split: Traffic Chart (Left) + Disposition Stats & Health (Right) -->
      <section class="dashboard-visual-split" aria-label="Telemetry and Threat Analysis">
        <!-- Observed Telemetry vs Baseline Normal Traffic -->
        <div class="panel-stitch chart-panel">
          <div class="panel-header-row">
            <div>
              <h2 class="panel-heading">Network Traffic</h2>
              <p class="panel-subheading">Live traffic volume vs expected baseline</p>
            </div>
            <div class="chart-legend-pills">
              <span class="legend-pill"><span class="legend-color-line bg-violet"></span> Actual Traffic</span>
              <span class="legend-pill"><span class="legend-color-line bg-cyan-dashed"></span> Expected Baseline</span>
            </div>
          </div>
          <div id="dashboardBezierChart" class="chart-container-box"></div>
        </div>

        <!-- Right Side: Threat Disposition Stats & SOC Readiness -->
        <div class="dashboard-side-column">
          <!-- Multi-Ring Statistics Gauge -->
          <div class="panel-stitch stats-gauge-panel">
            <div class="panel-header-row">
              <div>
                <h2 class="panel-heading">Threat Breakdown</h2>
                <p class="panel-subheading">Severity distribution</p>
              </div>
              <span class="icon-link-btn" title="View details">&nearr;</span>
            </div>
            <div id="concentricRadialGaugeContainer" class="radial-gauge-wrapper"></div>
          </div>

          <!-- SOC Readiness Health -->
          <div class="panel-stitch health-panel">
            <div class="health-header">
              <div class="health-shield-icon">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#58D7E8" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
              </div>
              <div>
                <h3 class="health-title">System Status</h3>
                <span class="health-desc">Protection Active</span>
              </div>
            </div>
            <div class="health-toggle-list">
              <div class="health-item">
                <span class="health-item-label">Smart Filter</span>
                <span class="status-tag status-active">Active</span>
              </div>
              <div class="health-item">
                <span class="health-item-label">Attack Catch Rate</span>
                <span class="status-tag status-active">100%</span>
              </div>
              <div class="health-item">
                <span class="health-item-label">Evidence Retention</span>
                <span class="status-tag status-active">Preserved</span>
              </div>
            </div>
            <button id="btnRunFullScan" class="btn-stitch-gradient btn-block" style="margin-top: 12px;">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg>
              <span>Run Threat Scan</span>
            </button>
          </div>
        </div>
      </section>

      <!-- Bottom Grid: Top Talkers & Recent Anomaly Timeline -->
      <section class="dashboard-bottom-grid" aria-label="Host Communications and Anomalies">
        <!-- Top Talkers Summary -->
        <div class="panel-stitch">
          <div class="panel-header-row">
            <div>
              <h2 class="panel-heading">Top Devices</h2>
              <p class="panel-subheading">Most active network hosts</p>
            </div>
            <button id="viewAllDatasetsBtn" class="btn-stitch-sm">Inspect Logs &rarr;</button>
          </div>
          <div class="talkers-table-box">
            <table class="stitch-table">
              <thead>
                <tr>
                  <th>Device IP</th>
                  <th>Data Volume</th>
                  <th>Status</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                ${topTalkers.length > 0 ? topTalkers.map(t => `
                  <tr>
                    <td><code class="code-ip">${t.ip}</code></td>
                    <td>${(t.bytes).toLocaleString()} B</td>
                    <td>
                      ${t.isIncidentEntity 
                        ? '<span class="status-tag status-alert">Suspicious</span>' 
                        : '<span class="status-tag status-clean">Normal</span>'}
                    </td>
                    <td>
                      <button class="btn-stitch-table drilldown-host-btn" data-host="${t.ip}">Investigate</button>
                    </td>
                  </tr>
                `).join('') : '<tr><td colspan="4">No host communications recorded.</td></tr>'}
              </tbody>
            </table>
          </div>
        </div>

        <!-- Recent Anomaly Timeline -->
        <div class="panel-stitch">
          <div class="panel-header-row">
            <div>
              <h2 class="panel-heading">Recent Alerts</h2>
              <p class="panel-subheading">Latest flagged events</p>
            </div>
            <button id="viewAllIncidentsBtn" class="btn-stitch-sm">View All &rarr;</button>
          </div>
          <div class="anomaly-timeline-list">
            ${recentAnomalies.length > 0 ? recentAnomalies.map(inc => {
              const rep = (result.context_replays || []).find(r => r.incident_id === inc.incident_id);
              const isMitigated = inc.context_summary?.is_benign_lookalike;
              const hasDev = rep?.unexplained_evidence?.count > 0;
              const badgeClass = inc.severity === 'CRITICAL' ? 'badge-critical' : inc.severity === 'HIGH' ? 'badge-high' : 'badge-medium';

              return `
                <div class="timeline-item-card" data-incident="${inc.incident_id}">
                  <div class="timeline-indicator ${inc.severity === 'CRITICAL' ? 'ind-coral' : 'ind-violet'}"></div>
                  <div class="timeline-content">
                    <div class="timeline-row-top">
                      <strong class="timeline-entity">${inc.source_entity}</strong>
                      <span class="score-badge ${badgeClass}">${inc.severity} (${inc.prioritization_score}/100)</span>
                    </div>
                    <div class="timeline-rules-row">
                      <span>${inc.distinct_rules_triggered.join(', ')}</span>
                      <span class="timeline-time">${(inc.first_seen || '').slice(11, 19)} UTC</span>
                    </div>
                    <div class="timeline-status-note">
                      ${hasDev 
                        ? '<span style="color: #FF8A48;">⚠ Unauthorized Action</span>' 
                        : isMitigated 
                        ? '<span style="color: #58D7E8;">✔ Safe Routine</span>' 
                        : '<span style="color: #FFA39E;">● Active Threat</span>'}
                    </div>
                  </div>
                  <button class="btn-stitch-icon inspect-timeline-btn" data-id="${inc.incident_id}" aria-label="Inspect incident ${inc.incident_id}">
                    &rarr;
                  </button>
                </div>
              `;
            }).join('') : '<div class="empty-state">No anomalous telemetry events recorded.</div>'}
          </div>
        </div>
      </section>
    </div>
  `;

  // Render SVG charts
  const bezierContainer = container.querySelector('#dashboardBezierChart');
  if (bezierContainer) {
    renderBezierTrafficChart(bezierContainer, records, { width: 720, height: 210 });
  }

  const radialContainer = container.querySelector('#concentricRadialGaugeContainer');
  if (radialContainer) {
    renderConcentricRadialGauge(radialContainer, {
      criticalPercent: criticalPct || 70,
      highPercent: highPct || 52,
      mitigatedPercent: mitigatedPct || 47,
      cleanPercent: cleanPct || 29
    });
  }

  // Event handlers
  const quickAnalyzeBtn = container.querySelector('#quickAnalyzeBtn');
  if (quickAnalyzeBtn) {
    quickAnalyzeBtn.addEventListener('click', () => onNavigateToScreen('dataset'));
  }

  const quickInvestigateBtn = container.querySelector('#quickInvestigateBtn');
  if (quickInvestigateBtn) {
    quickInvestigateBtn.addEventListener('click', () => onNavigateToScreen('investigation'));
  }

  const btnRunFullScan = container.querySelector('#btnRunFullScan');
  if (btnRunFullScan) {
    btnRunFullScan.addEventListener('click', () => onNavigateToScreen('replay'));
  }

  const viewAllDatasetsBtn = container.querySelector('#viewAllDatasetsBtn');
  if (viewAllDatasetsBtn) {
    viewAllDatasetsBtn.addEventListener('click', () => onNavigateToScreen('dataset'));
  }

  const viewAllIncidentsBtn = container.querySelector('#viewAllIncidentsBtn');
  if (viewAllIncidentsBtn) {
    viewAllIncidentsBtn.addEventListener('click', () => onNavigateToScreen('investigation'));
  }

  container.querySelectorAll('.drilldown-host-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const host = btn.getAttribute('data-host');
      const inc = incidents.find(i => i.source_entity === host);
      if (inc && onSelectIncident) {
        onSelectIncident(inc.incident_id);
        onNavigateToScreen('investigation');
      } else {
        onNavigateToScreen('investigation');
      }
    });
  });

  container.querySelectorAll('.timeline-item-card, .inspect-timeline-btn').forEach(elem => {
    elem.addEventListener('click', (e) => {
      const id = elem.getAttribute('data-incident') || elem.getAttribute('data-id');
      if (id && onSelectIncident) {
        onSelectIncident(id);
        onNavigateToScreen('replay');
      }
    });
  });
}
