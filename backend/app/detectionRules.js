import { RuleId } from './types.js';

/**
 * Evaluates records against Vertical Port Scan Detection Rule
 * Identifies a single source probing multiple distinct ports on target(s) within sliding window.
 */
export function detectPortScans(records, config) {
  const thresholdCfg = config.detection_thresholds?.port_scan || {
    window_seconds: 60,
    min_distinct_ports: 8,
    high_severity_port_count: 20,
    base_severity_score: 35
  };

  const windowMs = thresholdCfg.window_seconds * 1000;
  const detections = [];

  const bySource = new Map();
  for (const record of records) {
    if (!bySource.has(record.src_ip)) {
      bySource.set(record.src_ip, []);
    }
    bySource.get(record.src_ip).push(record);
  }

  for (const [srcIp, srcRecords] of bySource.entries()) {
    for (let i = 0; i < srcRecords.length; i++) {
      const startRecord = srcRecords[i];
      const windowEndMs = startRecord.epoch_ms + windowMs;
      
      const windowRecords = [];
      const distinctPorts = new Set();
      const targetIps = new Set();

      for (let j = i; j < srcRecords.length; j++) {
        const candidate = srcRecords[j];
        if (candidate.epoch_ms > windowEndMs) break;

        windowRecords.push(candidate);
        distinctPorts.add(candidate.dst_port);
        targetIps.add(candidate.dst_ip);
      }

      if (distinctPorts.size >= thresholdCfg.min_distinct_ports) {
        const portRatio = Math.min(
          1,
          (distinctPorts.size - thresholdCfg.min_distinct_ports) /
          Math.max(1, (thresholdCfg.high_severity_port_count - thresholdCfg.min_distinct_ports))
        );
        const rawScore = Math.min(
          95,
          Math.round(thresholdCfg.base_severity_score + portRatio * 45)
        );

        const targetList = Array.from(targetIps);
        const portList = Array.from(distinctPorts).sort((a, b) => a - b);
        const recordIds = windowRecords.map(r => r.record_id);

        detections.push({
          rule_id: RuleId.PORT_SCAN,
          rule_name: 'Vertical Port Scan Detection',
          source_ip: srcIp,
          target_ips: targetList,
          distinct_count: portList.length,
          observed_ports: portList,
          start_time: windowRecords[0].timestamp,
          end_time: windowRecords[windowRecords.length - 1].timestamp,
          start_epoch_ms: windowRecords[0].epoch_ms,
          end_epoch_ms: windowRecords[windowRecords.length - 1].epoch_ms,
          evidence_records: recordIds,
          evidence_flows: windowRecords,
          raw_score: rawScore,
          explanation: `Source IP ${srcIp} probed ${portList.length} distinct destination ports across target host(s) [${targetList.slice(0, 3).join(', ')}${targetList.length > 3 ? '...' : ''}] within ${thresholdCfg.window_seconds}s (Threshold: ${thresholdCfg.min_distinct_ports} ports).`
        });

        i += Math.max(0, windowRecords.length - 1);
      }
    }
  }

  return detections;
}

/**
 * Evaluates records against Horizontal Network Sweep Detection Rule
 * Identifies a single source querying the same port(s) across many destination hosts.
 */
export function detectNetworkSweeps(records, config) {
  const thresholdCfg = config.detection_thresholds?.network_sweep || {
    window_seconds: 60,
    min_distinct_hosts: 6,
    high_severity_host_count: 15,
    base_severity_score: 40
  };

  const windowMs = thresholdCfg.window_seconds * 1000;
  const detections = [];

  const bySource = new Map();
  for (const record of records) {
    if (!bySource.has(record.src_ip)) {
      bySource.set(record.src_ip, []);
    }
    bySource.get(record.src_ip).push(record);
  }

  for (const [srcIp, srcRecords] of bySource.entries()) {
    for (let i = 0; i < srcRecords.length; i++) {
      const startRecord = srcRecords[i];
      const windowEndMs = startRecord.epoch_ms + windowMs;

      const windowRecords = [];
      const distinctDstIps = new Set();
      const targetedPorts = new Set();

      for (let j = i; j < srcRecords.length; j++) {
        const candidate = srcRecords[j];
        if (candidate.epoch_ms > windowEndMs) break;

        windowRecords.push(candidate);
        distinctDstIps.add(candidate.dst_ip);
        targetedPorts.add(candidate.dst_port);
      }

      if (distinctDstIps.size >= thresholdCfg.min_distinct_hosts) {
        const hostRatio = Math.min(
          1,
          (distinctDstIps.size - thresholdCfg.min_distinct_hosts) /
          Math.max(1, (thresholdCfg.high_severity_host_count - thresholdCfg.min_distinct_hosts))
        );
        const rawScore = Math.min(
          95,
          Math.round(thresholdCfg.base_severity_score + hostRatio * 45)
        );

        const hostList = Array.from(distinctDstIps);
        const portList = Array.from(targetedPorts).sort((a, b) => a - b);
        const recordIds = windowRecords.map(r => r.record_id);

        detections.push({
          rule_id: RuleId.NETWORK_SWEEP,
          rule_name: 'Horizontal Network Sweep Detection',
          source_ip: srcIp,
          distinct_count: hostList.length,
          observed_hosts: hostList,
          targeted_ports: portList,
          start_time: windowRecords[0].timestamp,
          end_time: windowRecords[windowRecords.length - 1].timestamp,
          start_epoch_ms: windowRecords[0].epoch_ms,
          end_epoch_ms: windowRecords[windowRecords.length - 1].epoch_ms,
          evidence_records: recordIds,
          evidence_flows: windowRecords,
          raw_score: rawScore,
          explanation: `Source IP ${srcIp} initiated connection attempts to ${hostList.length} distinct destination hosts targeting ports [${portList.join(', ')}] within ${thresholdCfg.window_seconds}s (Threshold: ${thresholdCfg.min_distinct_hosts} hosts).`
        });

        i += Math.max(0, windowRecords.length - 1);
      }
    }
  }

  return detections;
}

/**
 * Evaluates records against Spreading & Lateral Movement Indicators
 * Detects hosts that receive administrative connections and subsequently fan out
 * to multiple other internal hosts on admin/remote service ports (SMB, RDP, SSH, WinRM, RPC).
 */
export function detectLateralMovement(records, config) {
  const thresholdCfg = config.detection_thresholds?.lateral_movement || {
    window_seconds: 180,
    fanout_threshold: 3,
    admin_ports: [22, 135, 445, 3389, 5985, 5986],
    base_severity_score: 50
  };

  const adminPortsSet = new Set(thresholdCfg.admin_ports || [22, 135, 445, 3389, 5985, 5986]);
  const windowMs = thresholdCfg.window_seconds * 1000;
  const detections = [];

  const outboundByHost = new Map();
  const inboundByHost = new Map();

  for (const record of records) {
    if (!outboundByHost.has(record.src_ip)) outboundByHost.set(record.src_ip, []);
    outboundByHost.get(record.src_ip).push(record);

    if (!inboundByHost.has(record.dst_ip)) inboundByHost.set(record.dst_ip, []);
    inboundByHost.get(record.dst_ip).push(record);
  }

  for (const [hostIp, outboundFlows] of outboundByHost.entries()) {
    const adminOutbounds = outboundFlows.filter(r => adminPortsSet.has(r.dst_port));
    if (adminOutbounds.length === 0) continue;

    for (let i = 0; i < adminOutbounds.length; i++) {
      const startRecord = adminOutbounds[i];
      const windowEndMs = startRecord.epoch_ms + windowMs;

      const windowFlows = [];
      const distinctTargets = new Set();
      const adminPortsUsed = new Set();

      for (let j = i; j < adminOutbounds.length; j++) {
        const candidate = adminOutbounds[j];
        if (candidate.epoch_ms > windowEndMs) break;

        windowFlows.push(candidate);
        distinctTargets.add(candidate.dst_ip);
        adminPortsUsed.add(candidate.dst_port);
      }

      if (distinctTargets.size >= thresholdCfg.fanout_threshold) {
        const inboundFlows = inboundByHost.get(hostIp) || [];
        const possibleVectors = inboundFlows.filter(
          r => adminPortsSet.has(r.dst_port) &&
               r.epoch_ms <= startRecord.epoch_ms &&
               r.epoch_ms >= (startRecord.epoch_ms - 300000)
        );

        const targetList = Array.from(distinctTargets);
        const portList = Array.from(adminPortsUsed).sort((a, b) => a - b);
        
        let rawScore = thresholdCfg.base_severity_score + (targetList.length * 8);
        if (possibleVectors.length > 0) {
          rawScore += 15;
        }
        rawScore = Math.min(98, rawScore);

        const allEvidenceFlows = [...windowFlows];
        if (possibleVectors.length > 0) {
          allEvidenceFlows.unshift(possibleVectors[possibleVectors.length - 1]);
        }

        const evidenceIds = allEvidenceFlows.map(r => r.record_id);

        detections.push({
          rule_id: RuleId.LATERAL_MOVEMENT,
          rule_name: 'Spreading & Lateral Movement Indicator',
          pivot_host: hostIp,
          source_ip: hostIp,
          distinct_count: targetList.length,
          fanout_targets: targetList,
          admin_ports: portList,
          has_ingress_vector: possibleVectors.length > 0,
          ingress_source: possibleVectors.length > 0 ? possibleVectors[possibleVectors.length - 1].src_ip : null,
          start_time: allEvidenceFlows[0].timestamp,
          end_time: allEvidenceFlows[allEvidenceFlows.length - 1].timestamp,
          start_epoch_ms: allEvidenceFlows[0].epoch_ms,
          end_epoch_ms: allEvidenceFlows[allEvidenceFlows.length - 1].epoch_ms,
          evidence_records: evidenceIds,
          evidence_flows: allEvidenceFlows,
          raw_score: rawScore,
          explanation: `Host ${hostIp} exhibited spreading/lateral fan-out to ${targetList.length} distinct targets [${targetList.join(', ')}] on administrative ports [${portList.join(', ')}] within ${thresholdCfg.window_seconds}s.${possibleVectors.length > 0 ? ` Prior ingress connection from ${possibleVectors[possibleVectors.length - 1].src_ip} observed.` : ''}`
        });

        i += Math.max(0, windowFlows.length - 1);
      }
    }
  }

  return detections;
}

export function runAllDetectionRules(records, config) {
  const portScans = detectPortScans(records, config);
  const sweeps = detectNetworkSweeps(records, config);
  const lateral = detectLateralMovement(records, config);

  return [...portScans, ...sweeps, ...lateral];
}
