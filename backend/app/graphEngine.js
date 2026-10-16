/**
 * Sentinel AI - Incident Network Communication Graph Engine
 * Builds node-link topology representing communicating computers and external endpoints
 * for incident forensics and visual inspection.
 */

export function buildIncidentCommunicationGraph(incident, allRecords = [], contextualizedDetections = [], config = {}) {
  if (!incident) return { nodes: [], edges: [], summary: {} };

  const incidentRecordIds = new Set(incident.record_ids || []);
  const incidentFlows = allRecords.filter(r => incidentRecordIds.has(r.record_id));

  const nodesMap = new Map();
  const edgesMap = new Map();

  const trustedIps = new Set((config.trusted_activity || []).map(t => t.ip));
  const scannerIps = new Set((config.approved_security_scanners || []).map(s => s.ip));
  const backupIps = new Set((config.large_nightly_backups || []).map(b => b.src_ip));
  const patchIps = new Set((config.patch_servers || []).map(p => p.ip));

  const sourceIp = incident.source_entity;

  // Ensure source node exists
  nodesMap.set(sourceIp, {
    id: sourceIp,
    label: sourceIp,
    role: scannerIps.has(sourceIp) ? 'AUTHORIZED_SCANNER' : backupIps.has(sourceIp) ? 'BACKUP_SERVER' : patchIps.has(sourceIp) ? 'PATCH_SERVER' : 'SUSPECT_SOURCE',
    is_source: true,
    is_suspicious: !incident.context_summary?.is_benign_lookalike,
    flow_count: incidentFlows.length,
    byte_volume: incidentFlows.reduce((sum, f) => sum + (f.total_bytes || 0), 0)
  });

  // Extract edges and target nodes
  for (const flow of incidentFlows) {
    const dstIp = flow.dst_ip;
    if (!dstIp) continue;

    // Target node
    if (!nodesMap.has(dstIp)) {
      const isInternal = dstIp.startsWith('10.') || dstIp.startsWith('192.168.') || dstIp.startsWith('172.16.');
      let role = 'INTERNAL_TARGET';
      if (trustedIps.has(dstIp)) role = 'DOMAIN_CONTROLLER_CRITICAL';
      else if (!isInternal) role = 'EXTERNAL_DESTINATION';

      nodesMap.set(dstIp, {
        id: dstIp,
        label: dstIp,
        role,
        is_source: false,
        is_suspicious: !incident.context_summary?.is_benign_lookalike,
        flow_count: 0,
        byte_volume: 0
      });
    }

    const targetNode = nodesMap.get(dstIp);
    targetNode.flow_count++;
    targetNode.byte_volume += (flow.total_bytes || 0);

    // Edge key
    const edgeKey = `${flow.src_ip}->${dstIp}`;
    if (!edgesMap.has(edgeKey)) {
      edgesMap.set(edgeKey, {
        id: `edge_${flow.src_ip}_${dstIp}`,
        source: flow.src_ip,
        target: dstIp,
        flow_count: 0,
        byte_volume: 0,
        ports: new Set(),
        protocols: new Set(),
        is_suspicious: !incident.context_summary?.is_benign_lookalike,
        triggered_rules: incident.distinct_rules_triggered || []
      });
    }

    const edge = edgesMap.get(edgeKey);
    edge.flow_count++;
    edge.byte_volume += (flow.total_bytes || 0);
    if (flow.dst_port) edge.ports.add(flow.dst_port);
    if (flow.protocol) edge.protocols.add(flow.protocol);
  }

  // Format edges with weight
  const edges = Array.from(edgesMap.values()).map(e => {
    // Weight scaled 1.5 to 7.0 for visual stroke-width
    const weight = Math.min(7.0, Math.max(1.5, Math.round((Math.log10(e.flow_count + 1) * 2.5) * 10) / 10));
    return {
      ...e,
      ports: Array.from(e.ports).sort((a, b) => a - b),
      protocols: Array.from(e.protocols),
      weight
    };
  });

  const nodes = Array.from(nodesMap.values());

  return {
    nodes,
    edges,
    summary: {
      total_nodes: nodes.length,
      total_edges: edges.length,
      suspicious_edges: edges.filter(e => e.is_suspicious).length,
      source_entity: sourceIp
    }
  };
}
