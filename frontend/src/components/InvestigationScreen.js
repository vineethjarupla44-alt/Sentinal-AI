/**
 * Sentinel AI - Screen 3: Incident Investigation
 * Detailed SOC triage interface with filters, circular risk score gauge,
 * triggered rules inspector (observed vs expected), actionable playbooks, and preserved flow evidence table.
 */

import { renderCircularScore } from './SvgCharts.js';

export function renderInvestigationScreen(container, currentData, selectedIncidentId, onSelectIncident) {
  const result = currentData?.result || {};
  const incidents = result.incidents || [];
  const records = result.records || [];
  const replays = result.context_replays || [];

  // Default selection if none selected
  if (!selectedIncidentId && incidents.length > 0) {
    selectedIncidentId = incidents[0].incident_id;
  }

  const activeIncident = incidents.find(i => i.incident_id === selectedIncidentId) || incidents[0] || null;
  const activeReplay = activeIncident ? replays.find(r => r.incident_id === activeIncident.incident_id) : null;

  // Filter state (local)
  let filterSearch = '';
  let filterSeverity = 'ALL';
  let filterRule = 'ALL';

  function filterIncidents() {
    return incidents.filter(inc => {
      const matchSearch = !filterSearch || inc.source_entity.toLowerCase().includes(filterSearch.toLowerCase()) || inc.incident_id.toLowerCase().includes(filterSearch.toLowerCase());
      const matchSeverity = filterSeverity === 'ALL' || inc.severity === filterSeverity;
      const matchRule = filterRule === 'ALL' || inc.distinct_rules_triggered.some(r => r.includes(filterRule));
      return matchSearch && matchSeverity && matchRule;
    });
  }

  function getBadgeClass(severity) {
    switch (severity) {
      case 'CRITICAL': return 'badge-critical';
      case 'HIGH': return 'badge-high';
      case 'MEDIUM': return 'badge-medium';
      case 'LOW': return 'badge-low';
      default: return 'badge-info';
    }
  }

  // Render investigation content
  function renderView() {
    const filteredList = filterIncidents();

    // Map evidence records for active incident
    const activeTargetIds = new Set(activeIncident ? activeIncident.record_ids : []);
    const matchingRecords = records.filter(r => activeTargetIds.has(r.record_id));

    // Observed vs Expected rule cards
    const triggeredRulesHtml = activeIncident ? (activeIncident.triggered_rules || []).map(r => {
      const obsText = r.observed ? JSON.stringify(r.observed).replace(/[{"}]/g, ' ') : 'Threshold breached';
      const expText = r.expected ? JSON.stringify(r.expected).replace(/[{"}]/g, ' ') : 'Standard baseline';

      return `
        <div class="rule-inspector-card">
          <div class="rule-top">
            <span class="rule-title">${r.rule_name}</span>
            <span class="rule-score-badge">+${r.score} pts</span>
          </div>
          <p class="rule-rationale">${r.rationale}</p>
          <div class="obs-vs-exp-grid">
            <div class="obs-box">
              <span class="obs-label">Observed Metrics</span>
              <span class="obs-val">${obsText}</span>
            </div>
            <div class="exp-box">
              <span class="exp-label">Configured Threshold</span>
              <span class="exp-val">${expText}</span>
            </div>
          </div>
        </div>
      `;
    }).join('') : '<p>No rules triggered.</p>';

    // Recommended SOC Investigation Steps
    let recommendedPlaybooks = [];
    if (activeIncident) {
      if (activeIncident.distinct_rules_triggered.some(r => r.includes('PORT-SCAN'))) {
        recommendedPlaybooks.push('1. Review local perimeter firewall logs for unsolicited SYN floods from ' + activeIncident.source_entity);
        recommendedPlaybooks.push('2. Verify whether source IP matches vulnerability scanner or asset discovery tool');
      }
      if (activeIncident.distinct_rules_triggered.some(r => r.includes('SWEEP'))) {
        recommendedPlaybooks.push('3. Inspect ARP / ICMP sweep telemetry across internal /24 subnets');
      }
      if (activeIncident.distinct_rules_triggered.some(r => r.includes('LATERAL') || r.includes('SPREAD'))) {
        recommendedPlaybooks.push('4. CRITICAL: Query Active Directory kerberos ticket requests and SMB/RDP session authentication');
        recommendedPlaybooks.push('5. Isolate affected host network segment via EDR endpoint isolation policy');
      }
      if (activeIncident.context_summary?.is_benign_lookalike) {
        recommendedPlaybooks.push('6. Verified against approved maintenance window or security scanner schedule — safe to assign routine audit status');
      }
    }

    container.innerHTML = `
      <div class="investigation-screen animate-fade-in">
        <!-- Filter Toolbar -->
        <div class="filters-toolbar-panel panel-stitch">
          <div class="filter-item">
            <label class="filter-label" for="filterSearchInput">Search:</label>
            <input type="text" id="filterSearchInput" class="stitch-input" placeholder="Search IP or Threat ID..." value="${filterSearch}">
          </div>

          <div class="filter-item">
            <label class="filter-label" for="filterSeveritySelect">Severity:</label>
            <select id="filterSeveritySelect" class="stitch-select">
              <option value="ALL" ${filterSeverity === 'ALL' ? 'selected' : ''}>All Levels</option>
              <option value="CRITICAL" ${filterSeverity === 'CRITICAL' ? 'selected' : ''}>Critical</option>
              <option value="HIGH" ${filterSeverity === 'HIGH' ? 'selected' : ''}>High</option>
              <option value="MEDIUM" ${filterSeverity === 'MEDIUM' ? 'selected' : ''}>Medium</option>
              <option value="LOW" ${filterSeverity === 'LOW' ? 'selected' : ''}>Low (Safe)</option>
            </select>
          </div>

          <div class="filter-item">
            <label class="filter-label" for="filterRuleSelect">Attack Type:</label>
            <select id="filterRuleSelect" class="stitch-select">
              <option value="ALL">All Types</option>
              <option value="PORT-SCAN">Port Scans</option>
              <option value="SWEEP">Network Sweeps</option>
              <option value="LATERAL">Lateral Spreading</option>
            </select>
          </div>

          <div class="filter-counter">
            <span class="counter-text">Showing <strong>${filteredList.length}</strong> of ${incidents.length} Threats</span>
          </div>
        </div>

        <!-- Master-Detail Investigation Split -->
        <div class="investigation-split-layout">
          <!-- Left: Prioritized Incident Queue -->
          <div class="incident-queue-column panel-stitch">
            <div class="queue-header">
              <h2 class="panel-heading">Threat Queue</h2>
              <span class="badge-status-pill badge-violet">${filteredList.length} Ranked</span>
            </div>

            <div class="incident-cards-scroll">
              ${filteredList.length > 0 ? filteredList.map(inc => {
                const isSelected = activeIncident && inc.incident_id === activeIncident.incident_id ? 'is-selected' : '';
                const badgeClass = getBadgeClass(inc.severity);
                const rulesSummary = inc.distinct_rules_triggered.map(r => r.replace('RULE-', '')).join(', ');

                return `
                  <div class="queue-item-card ${isSelected}" data-id="${inc.incident_id}">
                    <div class="queue-card-top">
                      <span class="queue-entity-ip">${inc.source_entity}</span>
                      <span class="score-badge ${badgeClass}">${inc.severity} (${inc.prioritization_score}/100)</span>
                    </div>
                    <div class="queue-rules-tag">${rulesSummary}</div>
                    <div class="queue-card-bottom">
                      <span>${inc.record_count} connections</span>
                      <span>${inc.duration_seconds}s span</span>
                      <span class="queue-id-tag">${inc.incident_id}</span>
                    </div>
                  </div>
                `;
              }).join('') : '<div class="empty-state">No incidents match the selected filters.</div>'}
            </div>
          </div>

          <!-- Right: Detailed Incident Inspector -->
          <div class="incident-detail-column">
            ${activeIncident ? `
              <!-- Incident Header Banner with Circular Score Gauge -->
              <div class="panel-stitch incident-hero-panel">
                <div class="hero-left">
                  <div class="hero-id-row">
                    <span class="badge-version">${activeIncident.incident_id}</span>
                    <span class="score-badge ${getBadgeClass(activeIncident.severity)}">${activeIncident.severity}</span>
                    ${activeIncident.context_summary?.is_benign_lookalike ? '<span class="status-tag status-clean">Safe Routine Recognized</span>' : ''}
                  </div>
                  <h2 class="hero-entity-title">Suspect Host: ${activeIncident.source_entity}</h2>
                  <div class="hero-meta-row">
                    <span><strong>First Seen:</strong> ${activeIncident.first_seen.replace('T', ' ')}</span>
                    <span><strong>Duration:</strong> ${activeIncident.duration_seconds}s</span>
                    <span><strong>Records:</strong> ${activeIncident.record_count}</span>
                  </div>
                </div>

                <div class="hero-right-gauge">
                  <div class="gauge-caption">Threat Score</div>
                  ${renderCircularScore(activeIncident.prioritization_score, 100, 76)}
                  <div class="gauge-sub">Raw: ${activeIncident.raw_score} &rarr; Final: ${activeIncident.prioritization_score}</div>
                </div>
              </div>

              <!-- Mathematical Prioritization Breakdown -->
              <div class="panel-stitch math-audit-card">
                <div class="math-title">
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#58D7E8" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>
                  Score Breakdown
                </div>
                <div class="math-formula-code">
                  ${activeIncident.scoring_breakdown?.formula_audit || 'Final Score = Raw Score - Safe Deductions'}
                </div>
              </div>

              <!-- Triggered Detection Rules (Observed vs Expected) -->
              <div class="panel-stitch">
                <div class="panel-header-row">
                  <div>
                    <h3 class="panel-heading">Triggered Rules</h3>
                    <p class="panel-subheading">Rules activated by observed telemetry</p>
                  </div>
                </div>
                <div class="rules-inspector-grid">
                  ${triggeredRulesHtml}
                </div>
              </div>

              <!-- Recommended SOC Playbook Investigation Steps -->
              <div class="panel-stitch">
                <div class="panel-header-row">
                  <div>
                    <h3 class="panel-heading">Recommended Actions</h3>
                    <p class="panel-subheading">Suggested investigation and response steps</p>
                  </div>
                  <span class="status-tag status-active">Actionable</span>
                </div>
                <ul class="playbook-steps-list">
                  ${recommendedPlaybooks.map(s => `<li>${s}</li>`).join('')}
                </ul>
              </div>

              <!-- Preserved Flow Evidence Table -->
              <div class="panel-stitch">
                <div class="panel-header-row">
                  <div>
                    <h3 class="panel-heading">Network Evidence (${matchingRecords.length} Records)</h3>
                    <p class="panel-subheading">Underlying network flows supporting this alert</p>
                  </div>
                  <button id="copyEvidenceBtn" class="btn-stitch-sm">Copy Record IDs</button>
                </div>

                <div class="evidence-table-container">
                  <table class="stitch-table">
                    <thead>
                      <tr>
                        <th>Record ID</th>
                        <th>Time (UTC)</th>
                        <th>Source</th>
                        <th>Target</th>
                        <th>Protocol</th>
                        <th>Data Size</th>
                        <th>Label</th>
                      </tr>
                    </thead>
                    <tbody>
                      ${matchingRecords.map(f => `
                        <tr>
                          <td><code class="code-id">${f.record_id}</code></td>
                          <td>${(f.timestamp || '').replace('T', ' ').replace('Z', '')}</td>
                          <td>${f.src_ip}:${f.src_port}</td>
                          <td>${f.dst_ip}:${f.dst_port}</td>
                          <td><span class="proto-tag">${f.protocol}</span></td>
                          <td>${(f.total_bytes || 0).toLocaleString()} B</td>
                          <td><span class="ground-truth-tag">${f.label || 'unlabeled'}</span></td>
                        </tr>
                      `).join('')}
                    </tbody>
                  </table>
                </div>
              </div>
            ` : `
              <div class="panel-stitch empty-inspector-state">
                <p>Select a threat from the queue on the left to see its investigation details.</p>
              </div>
            `}
          </div>
        </div>
      </div>
    `;

    // Bind event listeners
    const searchInput = container.querySelector('#filterSearchInput');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        filterSearch = e.target.value;
        renderView();
      });
    }

    const severitySelect = container.querySelector('#filterSeveritySelect');
    if (severitySelect) {
      severitySelect.addEventListener('change', (e) => {
        filterSeverity = e.target.value;
        renderView();
      });
    }

    const ruleSelect = container.querySelector('#filterRuleSelect');
    if (ruleSelect) {
      ruleSelect.addEventListener('change', (e) => {
        filterRule = e.target.value;
        renderView();
      });
    }

    container.querySelectorAll('.queue-item-card').forEach(card => {
      card.addEventListener('click', () => {
        const id = card.getAttribute('data-id');
        onSelectIncident(id);
      });
    });

    const copyBtn = container.querySelector('#copyEvidenceBtn');
    if (copyBtn && activeIncident) {
      copyBtn.addEventListener('click', () => {
        navigator.clipboard.writeText(activeIncident.record_ids.join(', '));
        copyBtn.textContent = 'Copied!';
        setTimeout(() => { copyBtn.textContent = 'Copy Flow IDs'; }, 2000);
      });
    }
  }

  renderView();
}
