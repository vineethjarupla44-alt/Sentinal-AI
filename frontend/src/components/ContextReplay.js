/**
 * Component: ContextReplay
 * Distinctive Adaptive Context Replay Inspector showing Naive vs Context findings,
 * Rule contribution deltas, unexplained evidence, and mathematical audit.
 */

function getBadgeClass(severity) {
  switch (severity) {
    case 'CRITICAL': return 'badge-critical';
    case 'HIGH': return 'badge-high';
    case 'MEDIUM': return 'badge-medium';
    case 'LOW': return 'badge-low';
    default: return 'badge-info';
  }
}

export function renderContextReplay(container, incident, replay) {
  if (!incident || !replay) {
    container.innerHTML = `
      <div class="empty-selection-placeholder">
        <p>Select an incident from the queue to inspect its Adaptive Context Replay.</p>
      </div>
    `;
    return;
  }

  const naiveStage = replay.naive_stage;
  const contextStage = replay.context_stage;
  const deltas = replay.delta_analysis.rule_deltas || [];
  const unexplained = replay.unexplained_evidence;

  let unexplainedAlertHtml = '';
  if (unexplained.has_unexplained) {
    unexplainedAlertHtml = `
      <div class="unexplained-alert-box">
        <div class="unexplained-alert-title">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
          CRITICAL DEVIATION: ${unexplained.count} Unexplained Evidence Item(s)
        </div>
        <ul class="unexplained-list">
          ${unexplained.items.map(u => `<li>[${u.type}] ${u.details}</li>`).join('')}
        </ul>
      </div>
    `;
  }

  const deltaCardsHtml = deltas.map(d => {
    const isMitigated = d.score_reduction > 0;
    const pillClass = isMitigated ? 'delta-reduced' : 'delta-maintained';
    const pillText = isMitigated ? `-${d.score_reduction} pts (${d.percentage_reduction}% reduction)` : 'Score Maintained';

    return `
      <div class="delta-card">
        <div class="delta-header">
          <span class="delta-rule-name">${d.rule_name}</span>
          <span class="delta-score-pill ${pillClass}">${pillText}</span>
        </div>
        <div class="stage-score-display" style="font-size: 0.85rem; margin-bottom: 0.3rem;">
          <span>Raw Score: <strong>${d.raw_score}</strong></span> &rarr; 
          <span>Adjusted Score: <strong>${d.adjusted_score}</strong></span>
        </div>
        <p class="delta-rationale">${d.why_changed}</p>
      </div>
    `;
  }).join('');

  container.innerHTML = `
    <div class="replay-container">
      <div class="replay-stages-grid">
        <!-- Stage 1: Naive Rule Assessment -->
        <div class="stage-box stage-naive">
          <span class="stage-badge">Stage 1: Naive Volumetric Engine</span>
          <div class="stage-score-display">
            <span class="stage-score-num">${naiveStage.raw_score}</span>
            <span class="score-badge badge-high">${naiveStage.naive_severity}</span>
          </div>
          <p class="stage-summary-text">${naiveStage.summary}</p>
        </div>

        <!-- Stage 2: Context-Aware Baselining -->
        <div class="stage-box stage-context">
          <span class="stage-badge">Stage 2: Adaptive Context Engine</span>
          <div class="stage-score-display">
            <span class="stage-score-num">${contextStage.adjusted_score}</span>
            <span class="score-badge ${getBadgeClass(incident.severity)}">${contextStage.context_severity}</span>
          </div>
          <p class="stage-summary-text">${contextStage.summary}</p>
        </div>
      </div>

      ${unexplainedAlertHtml}

      <div class="delta-section">
        <h3 class="delta-section-title">Rule Contribution Delta & Justification</h3>
        ${deltaCardsHtml}
      </div>

      <div class="stage-box" style="font-size: 0.8rem; border-color: rgba(59, 130, 246, 0.3);">
        <strong style="color: #60a5fa;">Prioritization Mathematical Audit:</strong>
        <div style="font-family: var(--font-mono); margin-top: 4px; color: var(--text-secondary);">
          ${incident.scoring_breakdown.formula_audit} &rarr; <strong>Final Prioritization: ${incident.prioritization_score}/100</strong>
        </div>
      </div>
    </div>
  `;
}
