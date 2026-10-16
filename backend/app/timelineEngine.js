/**
 * TraceGuard - Chronological Incident Timeline Engine
 * Reconstructs the end-to-end temporal attack sequence and assigns defensible
 * attack-stage hypotheses (Reconnaissance, Lateral Movement, C2, Unusual Outbound Transfer, Unclassified).
 */

export const AttackStage = {
  RECONNAISSANCE: 'Reconnaissance',
  LATERAL_MOVEMENT: 'Lateral Movement',
  COMMAND_AND_CONTROL: 'Command and Control (C2)',
  UNUSUAL_OUTBOUND: 'Unusual Outbound Transfer',
  UNCLASSIFIED: 'Unclassified'
};

export function buildIncidentTimeline(incident, allRecords = [], contextualizedDetections = [], beaconingFindings = []) {
  if (!incident) return [];

  const incidentRecordIds = new Set(incident.record_ids || []);
  const incidentFlows = allRecords.filter(r => incidentRecordIds.has(r.record_id));
  
  // Sort chronologically by epoch
  incidentFlows.sort((a, b) => (a.epoch_ms || 0) - (b.epoch_ms || 0));

  // Index detections by record ID
  const ruleByRecordId = new Map();
  for (const det of contextualizedDetections) {
    if (det.source_ip === incident.source_entity || det.pivot_host === incident.source_entity) {
      for (const rid of (det.evidence_records || [])) {
        if (!ruleByRecordId.has(rid)) {
          ruleByRecordId.set(rid, []);
        }
        ruleByRecordId.get(rid).push(det);
      }
    }
  }

  // Index beaconing by destination IP
  const beaconingByDest = new Map();
  for (const bf of beaconingFindings) {
    if (bf.source_ip === incident.source_entity && bf.is_suspicious) {
      beaconingByDest.set(bf.destination_ip, bf);
    }
  }

  const timelineEvents = [];
  let eventSeq = 1;

  for (const flow of incidentFlows) {
    const matchedDetections = ruleByRecordId.get(flow.record_id) || [];
    const matchedBeaconing = beaconingByDest.get(flow.dst_ip);

    let stage = AttackStage.UNCLASSIFIED;
    let stageReason = 'General network communication recorded during incident window.';
    let triggeredRuleName = null;
    let severity = 'INFORMATIONAL';
    let riskContribution = 5;

    // Evaluate primary attack stage from triggered rules
    const hasPortScan = matchedDetections.some(d => d.rule_id.includes('PORT-SCAN'));
    const hasSweep = matchedDetections.some(d => d.rule_id.includes('NET-SWEEP') || d.rule_id.includes('SWEEP'));
    const hasLateral = matchedDetections.some(d => d.rule_id.includes('LAT-MOVE') || d.rule_id.includes('LATERAL'));

    if (hasPortScan) {
      stage = AttackStage.RECONNAISSANCE;
      stageReason = `Port probing observed on destination ${flow.dst_ip}:${flow.dst_port}`;
      triggeredRuleName = 'Vertical Port Scan';
      severity = 'HIGH';
      riskContribution = 25;
    } else if (hasSweep) {
      stage = AttackStage.RECONNAISSANCE;
      stageReason = `Host sweep discovery targeting port ${flow.dst_port} across host ${flow.dst_ip}`;
      triggeredRuleName = 'Horizontal Network Sweep';
      severity = 'HIGH';
      riskContribution = 30;
    } else if (hasLateral) {
      stage = AttackStage.LATERAL_MOVEMENT;
      stageReason = `Internal propagation fan-out to host ${flow.dst_ip} via administrative port ${flow.dst_port} (${flow.protocol})`;
      triggeredRuleName = 'Spreading & Lateral Movement';
      severity = 'CRITICAL';
      riskContribution = 45;
    } else if (matchedBeaconing) {
      stage = AttackStage.COMMAND_AND_CONTROL;
      stageReason = `Periodic outbound keepalive to external target ${flow.dst_ip}:${flow.dst_port} (~${Math.round(matchedBeaconing.metrics.mean_interval_seconds)}s interval, CV=${matchedBeaconing.metrics.coefficient_of_variation})`;
      triggeredRuleName = 'Candidate C2 Beaconing';
      severity = 'HIGH';
      riskContribution = 35;
    } else if (flow.bytes_out > 500000 && !flow.dst_ip.startsWith('10.') && !flow.dst_ip.startsWith('192.168.')) {
      stage = AttackStage.UNUSUAL_OUTBOUND;
      stageReason = `Substantial outbound payload (${(flow.bytes_out).toLocaleString()} bytes) egress to external host ${flow.dst_ip}`;
      triggeredRuleName = 'Unusual Outbound Volume';
      severity = 'MEDIUM';
      riskContribution = 20;
    }

    timelineEvents.push({
      sequence_number: eventSeq++,
      record_id: flow.record_id,
      timestamp: flow.timestamp,
      epoch_ms: flow.epoch_ms,
      source: `${flow.src_ip}:${flow.src_port}`,
      destination: `${flow.dst_ip}:${flow.dst_port}`,
      protocol: flow.protocol,
      bytes: flow.total_bytes || 0,
      stage_hypothesis: stage,
      stage_reason: stageReason,
      triggered_rule: triggeredRuleName,
      severity,
      risk_contribution: riskContribution,
      hypothesis_disclaimer: 'Investigation hypothesis based on observable telemetry patterns, not conclusive proof.'
    });
  }

  return timelineEvents;
}
