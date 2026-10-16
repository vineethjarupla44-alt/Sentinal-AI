/**
 * Component: IncidentQueue
 * Displays prioritized list of security incidents ranked 0-100.
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

export function renderIncidentQueue(container, incidents, selectedId, onSelect) {
  if (!incidents || incidents.length === 0) {
    container.innerHTML = '<div class="empty-state">No anomalous behavioral patterns detected.</div>';
    return;
  }

  container.innerHTML = incidents.map(inc => {
    const isSelected = inc.incident_id === selectedId ? 'selected' : '';
    const badgeClass = getBadgeClass(inc.severity);
    const ruleNames = inc.distinct_rules_triggered.map(r => r.replace('RULE-', '')).join(', ');

    return `
      <div class="incident-card ${isSelected}" id="inc_${inc.incident_id}" data-id="${inc.incident_id}">
        <div class="card-top">
          <span class="card-entity">${inc.source_entity}</span>
          <span class="score-badge ${badgeClass}">${inc.severity} (${inc.prioritization_score})</span>
        </div>
        <div class="card-rule-tag">${ruleNames}</div>
        <div class="card-meta">
          <span>Flows: ${inc.record_count}</span>
          <span>Duration: ${inc.duration_seconds}s</span>
        </div>
      </div>
    `;
  }).join('');

  container.querySelectorAll('.incident-card').forEach(card => {
    card.addEventListener('click', () => {
      const id = card.getAttribute('data-id');
      onSelect(id);
    });
  });
}
