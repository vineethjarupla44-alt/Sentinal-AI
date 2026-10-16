/**
 * Component: EvidenceTable
 * Renders preserved forensic flow records associated with an incident.
 */

export function renderEvidenceTable(tbody, records, incidentRecordIds) {
  const targetIds = new Set(incidentRecordIds || []);
  const matchingFlows = (records || []).filter(r => targetIds.has(r.record_id));

  if (matchingFlows.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7">No matching flow telemetry records found for this incident.</td></tr>';
    return;
  }

  tbody.innerHTML = matchingFlows.map(f => `
    <tr>
      <td><code>${f.record_id}</code></td>
      <td>${f.timestamp.replace('T', ' ').replace('Z', '')}</td>
      <td>${f.src_ip}:${f.src_port}</td>
      <td>${f.dst_ip}:${f.dst_port}</td>
      <td>${f.protocol}</td>
      <td>${(f.total_bytes || 0).toLocaleString()} B</td>
      <td><span class="card-rule-tag">${f.label}</span></td>
    </tr>
  `).join('');
}
