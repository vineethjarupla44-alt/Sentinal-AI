/**
 * TraceGuard - Screen 3: Incident Investigation
 * Advanced SOC triage interface with 6 specialized analytical views:
 * 1. Overview & Rules (Risk Score Gauge, Mathematical Audit, Triggered Rules, Playbooks)
 * 2. Baseline & Deviation (Host traffic vs learned normal baseline envelope, Z-scores)
 * 3. Beaconing & Intervals (Pulse intervals, jitter CV, periodicity, C2 vs NTP disambiguation)
 * 4. Attack Timeline (Chronological timeline with evidence-backed attack-stage hypotheses)
 * 5. Network Graph (Interactive directed communication topology, nodes, volume-weighted edges)
 * 6. Flow Evidence (Underlying network records table with export/copy)
 */

import {
  renderCircularScore,
  renderHostDeviationChart,
  renderBeaconIntervalChart,
  renderNetworkCommunicationGraph
} from './SvgCharts.js';

let currentSubtab = 'overview';

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

  function getStageBadgeClass(stage) {
    switch (stage) {
      case 'Reconnaissance': return 'stage-badge-recon';
      case 'Lateral Movement': return 'stage-badge-lateral';
      case 'Command and Control (C2)': return 'stage-badge-c2';
      case 'Unusual Outbound Transfer': return 'stage-badge-transfer';
      default: return 'stage-badge-unclassified';
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
        recommendedPlaybooks.push('1. Review perimeter firewall and honeypot logs for unsolicited SYN probe bursts from ' + activeIncident.source_entity);
        recommendedPlaybooks.push('2. Cross-reference source IP against vulnerability scanner registrations and asset discovery agents');
      }
      if (activeIncident.distinct_rules_triggered.some(r => r.includes('SWEEP'))) {
        recommendedPlaybooks.push('3. Inspect ARP / ICMP subnet sweep telemetry across internal CIDR blocks');
      }
      if (activeIncident.distinct_rules_triggered.some(r => r.includes('LATERAL') || r.includes('SPREAD'))) {
        recommendedPlaybooks.push('4. Query Active Directory Kerberos ticket requests and SMB/RDP session authentication records');
        recommendedPlaybooks.push('5. Enforce immediate EDR endpoint isolation on host ' + activeIncident.source_entity);
      }
      if (activeIncident.beaconing_analysis && activeIncident.beaconing_analysis.some(b => b.is_suspicious)) {
        recommendedPlaybooks.push('6. Block C2 egress channels on perimeter gateway and capture full-packet payload for protocol inspection');
      }
      if (activeIncident.context_summary?.is_benign_lookalike) {
        recommendedPlaybooks.push('7. Verified against approved maintenance window or security scanner schedule — safe to assign routine audit status');
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

              <!-- Sub-tab Navigation Bar -->
              <div class="investigation-subtabs-bar">
                <button class="subtab-btn ${currentSubtab === 'overview' ? 'active' : ''}" data-tab="overview">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 6h16M4 12h16M4 18h7"/></svg>
                  Overview & Rules
                </button>
                <button class="subtab-btn ${currentSubtab === 'baseline' ? 'active' : ''}" data-tab="baseline">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 20V10M12 20V4M6 20v-6"/></svg>
                  Baseline & Deviation
                </button>
                <button class="subtab-btn ${currentSubtab === 'beaconing' ? 'active' : ''}" data-tab="beaconing">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M2 12h5l3-9 4 18 3-9h5"/></svg>
                  Beaconing & Intervals
                </button>
                <button class="subtab-btn ${currentSubtab === 'timeline' ? 'active' : ''}" data-tab="timeline">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg>
                  Attack Timeline
                </button>
                <button class="subtab-btn ${currentSubtab === 'graph' ? 'active' : ''}" data-tab="graph">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>
                  Network Graph
                </button>
                <button class="subtab-btn ${currentSubtab === 'evidence' ? 'active' : ''}" data-tab="evidence">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                  Flow Evidence (${matchingRecords.length})
                </button>
              </div>

              <!-- Sub-tab Content Panels -->
              <div class="investigation-tab-content">
                ${currentSubtab === 'overview' ? `
                  <!-- TAB 1: Overview & Rules -->
                  <div class="panel-stitch math-audit-card">
                    <div class="math-title">
                      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#65D9DF" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>
                      Mathematical Prioritization Audit
                    </div>
                    <div class="math-formula-code">
                      ${activeIncident.scoring_breakdown?.formula_audit || 'Final Score = Raw Score - Safe Deductions'}
                    </div>
                  </div>

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

                  <div class="panel-stitch">
                    <div class="panel-header-row">
                      <div>
                        <h3 class="panel-heading">Recommended Playbook Actions</h3>
                        <p class="panel-subheading">Step-by-step SOC triage procedure</p>
                      </div>
                      <span class="status-tag status-active">Actionable</span>
                    </div>
                    <ul class="playbook-steps-list">
                      ${recommendedPlaybooks.map(s => `<li>${s}</li>`).join('')}
                    </ul>
                  </div>
                ` : ''}

                ${currentSubtab === 'baseline' ? `
                  <!-- TAB 2: Baseline & Deviation -->
                  <div class="panel-stitch">
                    <div class="panel-header-row">
                      <div>
                        <h3 class="panel-heading">Host Baseline & Traffic Deviation</h3>
                        <p class="panel-subheading">Observed metrics evaluated against learned normal behaviour envelope (Z-scores)</p>
                      </div>
                      <span class="status-tag ${activeIncident.host_deviation?.has_anomaly ? 'status-alert' : 'status-clean'}">
                        ${activeIncident.host_deviation?.status || 'NORMAL'}
                      </span>
                    </div>

                    <!-- Baseline Methodology Banner -->
                    <div class="methodology-note-banner">
                      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#69E2C2" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
                      <span>
                        <strong>Methodology:</strong> Windowed temporal baselining across historical activity. Zero ground-truth label leakage. Insufficient history handled safely when observations &lt; 3.
                      </span>
                    </div>

                    <!-- Chart Container -->
                    <div id="hostDeviationChartHost" class="chart-embed-box"></div>

                    <!-- Baseline Metrics Grid -->
                    ${activeIncident.host_deviation?.deviations ? `
                      <div class="metrics-deviation-table-box">
                        <table class="stitch-table">
                          <thead>
                            <tr>
                              <th>Metric</th>
                              <th>Expected Baseline</th>
                              <th>Observed Value</th>
                              <th>Z-Score</th>
                              <th>Deviation %</th>
                              <th>Status</th>
                            </tr>
                          </thead>
                          <tbody>
                            ${activeIncident.host_deviation.deviations.map(d => `
                              <tr>
                                <td><strong>${d.metric}</strong></td>
                                <td>${typeof d.expected === 'number' ? d.expected.toLocaleString() : d.expected}</td>
                                <td>${typeof d.observed === 'number' ? d.observed.toLocaleString() : d.observed}</td>
                                <td><code class="code-id">${d.z_score !== null ? d.z_score.toFixed(2) : 'N/A'}</code></td>
                                <td style="font-weight: 700; color: ${d.is_anomalous ? (d.is_mitigated ? '#4ADE80' : '#FF8057') : '#69E2C2'};">
                                  ${d.deviation_percent >= 0 ? `+${d.deviation_percent}%` : `${d.deviation_percent}%`}
                                </td>
                                <td>
                                  <span class="status-tag ${d.is_anomalous ? (d.is_mitigated ? 'status-clean' : 'status-alert') : 'status-active'}">
                                    ${d.is_anomalous ? (d.is_mitigated ? 'Mitigated (Backup)' : 'Deviation Breach') : 'Within Baseline'}
                                  </span>
                                </td>
                              </tr>
                            `).join('')}
                          </tbody>
                        </table>
                      </div>
                    ` : ''}
                  </div>
                ` : ''}

                ${currentSubtab === 'beaconing' ? `
                  <!-- TAB 3: Candidate Beaconing & Intervals -->
                  <div class="panel-stitch">
                    <div class="panel-header-row">
                      <div>
                        <h3 class="panel-heading">Candidate Beaconing & Interval Pulse</h3>
                        <p class="panel-subheading">Periodic C2 communication analysis: &Delta;t intervals, regularity, and jitter (CV)</p>
                      </div>
                      <span class="status-tag ${activeIncident.beaconing_analysis && activeIncident.beaconing_analysis.some(b => b.is_suspicious) ? 'status-alert' : 'status-clean'}">
                        ${activeIncident.beaconing_analysis && activeIncident.beaconing_analysis.some(b => b.is_suspicious) ? 'Suspicious C2 Detected' : 'No Periodic Threat'}
                      </span>
                    </div>

                    <!-- Chart Container -->
                    <div id="beaconIntervalChartHost" class="chart-embed-box"></div>

                    <!-- Beaconing Channel Details -->
                    ${activeIncident.beaconing_analysis && activeIncident.beaconing_analysis.length > 0 ? `
                      <div class="beaconing-channels-list">
                        ${activeIncident.beaconing_analysis.map(b => `
                          <div class="beacon-card ${b.is_suspicious ? 'beacon-alert' : 'beacon-normal'}">
                            <div class="beacon-card-header">
                              <div>
                                <span class="beacon-channel-tag">${b.source_ip} &rarr; ${b.target_ip}:${b.target_port}</span>
                                <span class="proto-tag">${b.protocol}</span>
                              </div>
                              <span class="status-tag ${b.is_suspicious ? 'status-alert' : 'status-active'}">
                                ${b.classification}
                              </span>
                            </div>
                            <div class="beacon-metrics-row">
                              <div class="b-stat"><span class="b-label">Repetitions:</span> <strong>${b.metrics.repetitions}</strong></div>
                              <div class="b-stat"><span class="b-label">Mean Interval (&mu;):</span> <strong>${b.metrics.mean_interval_seconds}s</strong></div>
                              <div class="b-stat"><span class="b-label">Median Interval:</span> <strong>${b.metrics.median_interval_seconds}s</strong></div>
                              <div class="b-stat"><span class="b-label">Std Dev (&sigma;):</span> <strong>${b.metrics.std_deviation_seconds}s</strong></div>
                              <div class="b-stat"><span class="b-label">Jitter (CV):</span> <strong>${b.metrics.jitter_cv}</strong></div>
                              <div class="b-stat"><span class="b-label">Duration:</span> <strong>${b.metrics.observation_duration_seconds}s</strong></div>
                            </div>
                            <div class="beacon-rationale-text">
                              <strong>Analysis:</strong> ${b.rationale}
                            </div>
                          </div>
                        `).join('')}
                      </div>
                    ` : `
                      <div class="empty-state-notice">
                        <div style="font-size: 13px; font-weight: 700; color: var(--text-primary); margin-bottom: 4px;">No Candidate Beaconing Detected</div>
                        <div style="font-size: 12px; color: var(--text-secondary);">Connections for this host did not exhibit repetitive timing patterns meeting the 3-pulse threshold.</div>
                      </div>
                    `}
                  </div>
                ` : ''}

                ${currentSubtab === 'timeline' ? `
                  <!-- TAB 4: Attack Timeline -->
                  <div class="panel-stitch">
                    <div class="panel-header-row">
                      <div>
                        <h3 class="panel-heading">Evidence-Backed Attack Timeline</h3>
                        <p class="panel-subheading">Chronological telemetry progression with contextual stage hypotheses</p>
                      </div>
                      <span class="badge-status-pill badge-violet">${activeIncident.attack_timeline?.events?.length || 0} Milestones</span>
                    </div>

                    <!-- Hypothesis Disclaimer Banner -->
                    <div class="hypothesis-disclaimer-banner">
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#FF8057" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                      <div>
                        <strong style="color: #FF8057;">Hypothesis Disclaimer:</strong>
                        <span>Stage classifications (Reconnaissance, Lateral Movement, C2, Unusual Outbound Transfer) are analytical hypotheses inferred from traffic characteristics to accelerate SOC triage. They do not constitute forensically proven ground-truth.</span>
                      </div>
                    </div>

                    <!-- Timeline Track -->
                    <div class="chronological-timeline-track">
                      ${activeIncident.attack_timeline?.events && activeIncident.attack_timeline.events.length > 0 ? activeIncident.attack_timeline.events.map((ev, idx) => `
                        <div class="timeline-milestone-item">
                          <div class="timeline-bead ${ev.is_suspicious ? 'bead-alert' : 'bead-normal'}">
                            <span>${idx + 1}</span>
                          </div>
                          <div class="timeline-content-card">
                            <div class="timeline-card-header">
                              <span class="timeline-time">${(ev.timestamp || '').replace('T', ' ').replace('Z', '')}</span>
                              <span class="timeline-stage-tag ${getStageBadgeClass(ev.attack_stage_hypothesis)}">
                                ${ev.attack_stage_hypothesis}
                              </span>
                              ${ev.delta_t_seconds !== null ? `<span class="timeline-delta">+${ev.delta_t_seconds}s</span>` : '<span class="timeline-delta">T+0s</span>'}
                            </div>
                            <div class="timeline-channel">
                              <strong>${ev.source_ip}:${ev.source_port}</strong> &rarr; <strong>${ev.target_ip}:${ev.target_port}</strong>
                              <span class="proto-tag">${ev.protocol}</span>
                              <span class="vol-tag">${(ev.bytes || 0).toLocaleString()} B</span>
                            </div>
                            <p class="timeline-reasoning">${ev.hypothesis_reasoning}</p>
                            <div class="timeline-flow-ids">
                              Record: <code class="code-id">${ev.flow_id}</code>
                            </div>
                          </div>
                        </div>
                      `).join('') : '<div class="empty-state">No timeline events available for this incident.</div>'}
                    </div>
                  </div>
                ` : ''}

                ${currentSubtab === 'graph' ? `
                  <!-- TAB 5: Network Communication Graph -->
                  <div class="panel-stitch">
                    <div class="panel-header-row">
                      <div>
                        <h3 class="panel-heading">Directed Communication Topology</h3>
                        <p class="panel-subheading">Host nodes and directed traffic channels (edge thickness scaled to byte volume)</p>
                      </div>
                      <span class="status-tag status-active">Interactive</span>
                    </div>

                    <!-- Network Graph Canvas Host -->
                    <div id="networkGraphCanvasHost" class="chart-embed-box"></div>
                  </div>
                ` : ''}

                ${currentSubtab === 'evidence' ? `
                  <!-- TAB 6: Flow Evidence Table -->
                  <div class="panel-stitch">
                    <div class="panel-header-row">
                      <div>
                        <h3 class="panel-heading">Network Evidence (${matchingRecords.length} Records)</h3>
                        <p class="panel-subheading">Underlying telemetry records supporting this incident</p>
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
                ` : ''}
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

    // Render SVGs for currently active sub-tab if corresponding container exists
    if (activeIncident) {
      if (currentSubtab === 'baseline') {
        const baselineContainer = container.querySelector('#hostDeviationChartHost');
        if (baselineContainer) {
          renderHostDeviationChart(baselineContainer, activeIncident.host_deviation || { status: 'INSUFFICIENT_HISTORY' });
        }
      } else if (currentSubtab === 'beaconing') {
        const beaconContainer = container.querySelector('#beaconIntervalChartHost');
        if (beaconContainer) {
          renderBeaconIntervalChart(beaconContainer, activeIncident.beaconing_analysis || []);
        }
      } else if (currentSubtab === 'graph') {
        const graphContainer = container.querySelector('#networkGraphCanvasHost');
        if (graphContainer) {
          renderNetworkCommunicationGraph(graphContainer, activeIncident.network_graph || { nodes: [], edges: [] });
        }
      }
    }

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

    // Sub-tab switching
    container.querySelectorAll('.subtab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const tab = btn.getAttribute('data-tab');
        if (tab && tab !== currentSubtab) {
          currentSubtab = tab;
          renderView();
        }
      });
    });

    // Threat queue selection
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
        setTimeout(() => { copyBtn.textContent = 'Copy Record IDs'; }, 2000);
      });
    }
  }

  renderView();
}
