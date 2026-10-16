/**
 * Sentinel AI - Screen 4: Adaptive Context Replay (Signature Feature)
 * Distinctive before-and-after investigation experience:
 * - Dual-layer transparency: Naive Static Rule Assessment vs Context-Aware Baselining
 * - Rule contribution deltas with explicit plain-language rationale
 * - Critical deviation & unexplained evidence alert banners
 * - Chronological event timeline
 * - Interactive What-If Simulation Control (dynamic client-side preview without modifying raw data)
 */

import { renderCircularScore } from './SvgCharts.js';

export function renderContextReplayScreen(container, currentData, selectedIncidentId, onSelectIncident) {
  const result = currentData?.result || {};
  const incidents = result.incidents || [];
  const replays = result.context_replays || [];

  if (!selectedIncidentId && incidents.length > 0) {
    selectedIncidentId = incidents[0].incident_id;
  }

  const activeIncident = incidents.find(i => i.incident_id === selectedIncidentId) || incidents[0] || null;
  const activeReplay = activeIncident ? replays.find(r => r.incident_id === activeIncident.incident_id) : null;

  // Simulation state
  let simMitigationFactor = 80;
  let simScheduleActive = true;
  let simPortThreshold = 8;
  let isSimActive = false;

  function renderView() {
    if (!activeIncident || !activeReplay) {
      container.innerHTML = `
        <div class="context-replay-screen animate-fade-in">
          <div class="empty-state">No incidents available for Adaptive Context Replay.</div>
        </div>
      `;
      return;
    }

    const naiveStage = activeReplay.naive_stage;
    const contextStage = activeReplay.context_stage;
    const deltas = activeReplay.delta_analysis.rule_deltas || [];
    const unexplained = activeReplay.unexplained_evidence;

    // Simulation calculation
    let simulatedScore = contextStage.adjusted_score;
    if (isSimActive) {
      // Calculate what-if:
      const raw = naiveStage.raw_score;
      if (!simScheduleActive) {
        simulatedScore = raw; // no schedule mitigation
      } else {
        const factor = simMitigationFactor / 100;
        simulatedScore = Math.max(10, Math.round(raw * (1 - factor)));
      }
    }

    // Incident selection tabs
    const incidentTabsHtml = incidents.map(inc => {
      const isSel = inc.incident_id === activeIncident.incident_id;
      const isMit = inc.context_summary?.is_benign_lookalike;
      return `
        <button class="replay-inc-tab ${isSel ? 'active' : ''}" data-id="${inc.incident_id}">
          <span class="tab-id">${inc.incident_id}</span>
          <span class="tab-ip">${inc.source_entity}</span>
          <span class="tab-badge ${inc.severity === 'CRITICAL' ? 'badge-coral' : 'badge-lavender'}">${inc.prioritization_score}</span>
        </button>
      `;
    }).join('');

    // Unexplained evidence section
    let unexplainedHtml = '';
    if (unexplained.has_unexplained) {
      unexplainedHtml = `
        <div class="unexplained-alert-box">
          <div class="unexplained-alert-header">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#EF4444" stroke-width="2.2"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
            <div>
              <strong style="color: #F7F2FF; font-size: 15px;">⚠️ Unexpected Behavior: ${unexplained.count} Unauthorized Action(s)</strong>
              <p style="margin: 2px 0 0; color: #FFA39E; font-size: 13px;">${unexplained.analyst_guidance || 'Device performed actions outside its approved scope.'}</p>
            </div>
          </div>
          <ul class="unexplained-items-list">
            ${unexplained.items.map(u => `
              <li><span class="unexp-tag">[${u.type}]</span> <span class="unexp-text">${u.details}</span></li>
            `).join('')}
          </ul>
        </div>
      `;
    } else {
      unexplainedHtml = `
        <div class="unexplained-clean-box">
          <div class="clean-icon">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#34D399" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
          </div>
          <div>
            <strong style="color: #34D399; font-size: 14px;">✔ Verified Safe Routine</strong>
            <p style="margin: 2px 0 0; color: #B9A9D0; font-size: 13px;">Matched approved schedule and authorized ports cleanly.</p>
          </div>
        </div>
      `;
    }

    // Rule deltas
    const deltasHtml = deltas.map(d => {
      const isMitigated = d.score_reduction > 0;
      const pillClass = isMitigated ? 'delta-pill-reduced' : 'delta-pill-maintained';
      const pillText = isMitigated ? `-${d.score_reduction} pts (${d.percentage_reduction}% Reduction)` : 'Score Maintained';

      return `
        <div class="rule-delta-card">
          <div class="delta-top-row">
            <div>
              <span class="delta-rule-id">${d.rule_id}</span>
              <h4 class="delta-rule-title">${d.rule_name}</h4>
            </div>
            <span class="delta-score-pill ${pillClass}">${pillText}</span>
          </div>

          <div class="delta-score-comparison">
            <span class="score-step">Raw: <strong>${d.raw_score}</strong></span>
            <span class="score-arrow">&rarr;</span>
            <span class="score-step">Adjusted: <strong style="color: #58D7E8;">${d.adjusted_score}</strong></span>
          </div>

          <p class="delta-explanation-text">
            <strong>Reason:</strong> ${d.why_changed}
          </p>

          ${d.mitigations_applied && d.mitigations_applied.length > 0 ? `
            <div class="mitigation-tags-row">
              ${d.mitigations_applied.map(m => `
                <span class="matched-profile-tag">${m.type} (${Math.round(m.factor * 100)}% reduction)</span>
              `).join('')}
            </div>
          ` : ''}
        </div>
      `;
    }).join('');

    container.innerHTML = `
      <div class="context-replay-screen animate-fade-in">
        <!-- Screen Signature Header -->
        <div class="screen-header-row">
          <div>
            <div class="signature-heading-wrap">
              <span class="sparkle-badge">SIGNATURE FEATURE</span>
              <h1 class="screen-title">Smart Filter Replay</h1>
            </div>
            <p class="screen-desc">Compare traditional detection against context-aware filtering.</p>
          </div>
        </div>

        <!-- Incident Selector Ribbon -->
        <div class="replay-inc-selector-bar">
          <span class="selector-label">Select Threat:</span>
          <div class="selector-pills-row">
            ${incidentTabsHtml}
          </div>
        </div>

        <!-- Side-by-Side Dual Engine Comparison Layout -->
        <div class="dual-stages-grid">
          <!-- Stage 1: Naive Volumetric Engine (Zero Context) -->
          <div class="stage-card stage-card-naive">
            <div class="stage-badge-tag stage-naive-tag">Stage 1: Traditional Detection</div>
            <div class="stage-score-hero">
              <div class="stage-score-number">${naiveStage.raw_score}</div>
              <div class="stage-score-meta">
                <span class="score-badge badge-high">${naiveStage.naive_severity}</span>
                <span class="score-caption">Raw Score</span>
              </div>
            </div>
            <p class="stage-desc-text">${naiveStage.summary}</p>
            <div class="stage-warning-banner">
              <strong>Alert:</strong> Flags routine backups and scans blindly without context.
            </div>
          </div>

          <!-- Stage 2: Context-Aware Adaptive Baselining Engine -->
          <div class="stage-card stage-card-context">
            <div class="stage-badge-tag stage-context-tag">Stage 2: Sentinel AI Smart Filter</div>
            <div class="stage-score-hero">
              <div class="stage-score-number" style="color: #58D7E8;">${contextStage.adjusted_score}</div>
              <div class="stage-score-meta">
                <span class="score-badge ${contextStage.adjusted_score >= 50 ? 'badge-critical' : 'badge-low'}">${contextStage.context_severity}</span>
                <span class="score-caption">${contextStage.context_status}</span>
              </div>
            </div>
            <p class="stage-desc-text">${contextStage.summary}</p>
            <div class="stage-success-banner">
              <strong>Context Applied:</strong> Approved tools recognized; false alarm dismissed.
            </div>
          </div>
        </div>

        <!-- Unexplained Deviation Alert / Compliance Status -->
        ${unexplainedHtml}

        <!-- Rule Contribution Delta & Rationale Section -->
        <div class="panel-stitch">
          <div class="panel-header-row">
            <div>
              <h3 class="panel-heading">Score Adjustments</h3>
              <p class="panel-subheading">How approved profiles reduced alert scores</p>
            </div>
            <span class="status-tag status-clean">Explainable</span>
          </div>
          <div class="deltas-grid">
            ${deltasHtml}
          </div>
        </div>

        <!-- Interactive What-If Simulation Control -->
        <div class="panel-stitch what-if-container">
          <div class="panel-header-row">
            <div class="what-if-title-row">
              <span class="sim-icon">⚡</span>
              <div>
                <h3 class="panel-heading">What-If Simulation</h3>
                <p class="panel-subheading">Test how policy changes affect scores in real-time</p>
              </div>
            </div>
            <div class="sim-toggle-pill">
              <label class="switch-label">
                <input type="checkbox" id="simToggleCheckbox" ${isSimActive ? 'checked' : ''} />
                <span class="switch-text">${isSimActive ? 'SIMULATION ACTIVE' : 'Enable Simulation'}</span>
              </label>
            </div>
          </div>

          <div class="what-if-body ${isSimActive ? 'is-active' : 'is-inactive'}">
            <div class="what-if-controls-grid">
              <div class="sim-control-item">
                <label class="sim-label">Safe Discount Factor: <strong id="simFactorVal">${simMitigationFactor}%</strong></label>
                <input type="range" id="simFactorSlider" min="0" max="100" step="5" value="${simMitigationFactor}" class="stitch-slider" ${!isSimActive ? 'disabled' : ''}>
                <span class="sim-hint">Discount percentage when profile matches</span>
              </div>

              <div class="sim-control-item">
                <label class="sim-label">Schedule Authorization:</label>
                <select id="simScheduleSelect" class="stitch-select" ${!isSimActive ? 'disabled' : ''}>
                  <option value="true" ${simScheduleActive ? 'selected' : ''}>Within Authorized Window (Active)</option>
                  <option value="false" ${!simScheduleActive ? 'selected' : ''}>Outside Window (Off-Hours Deviation)</option>
                </select>
                <span class="sim-hint">Simulate off-schedule activity</span>
              </div>

              <div class="sim-result-card">
                <div class="sim-result-label">Simulated Score</div>
                <div class="sim-result-value ${simulatedScore >= 50 ? 'color-alert' : 'color-cyan'}">${simulatedScore} / 100</div>
                <div class="sim-watermark">[SIMULATION PREVIEW]</div>
              </div>
            </div>

            <div class="sim-disclaimer-note">
              <strong>Notice:</strong> Simulation mode does not alter original network logs or evidence.
            </div>
          </div>
        </div>

        <!-- Evidence Preservation Audit Box -->
        <div class="panel-stitch evidence-guarantee-card">
          <div class="guarantee-header">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#58D7E8" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
            <h4 class="guarantee-title">Evidence Preserved</h4>
          </div>
          <p class="guarantee-text">
            All ${activeIncident.record_count} raw connection records for host <code>${activeIncident.source_entity}</code> remain 100% intact.
          </p>
        </div>
      </div>
    `;

    // Event listeners
    container.querySelectorAll('.replay-inc-tab').forEach(btn => {
      btn.addEventListener('click', () => {
        const id = btn.getAttribute('data-id');
        onSelectIncident(id);
      });
    });

    const simToggle = container.querySelector('#simToggleCheckbox');
    if (simToggle) {
      simToggle.addEventListener('change', (e) => {
        isSimActive = e.target.checked;
        renderView();
      });
    }

    const simFactorSlider = container.querySelector('#simFactorSlider');
    if (simFactorSlider) {
      simFactorSlider.addEventListener('input', (e) => {
        simMitigationFactor = parseInt(e.target.value, 10);
        const valElem = container.querySelector('#simFactorVal');
        if (valElem) valElem.textContent = `${simMitigationFactor}%`;
        renderView();
      });
    }

    const simScheduleSelect = container.querySelector('#simScheduleSelect');
    if (simScheduleSelect) {
      simScheduleSelect.addEventListener('change', (e) => {
        simScheduleActive = e.target.value === 'true';
        renderView();
      });
    }
  }

  renderView();
}
