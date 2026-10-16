import { MitigationTag } from './types.js';

/**
 * Checks if a given timestamp falls within an hourly UTC schedule window.
 * Supports overnight windows (e.g., start 22:00, end 04:00).
 */
export function isWithinSchedule(timestampIso, schedule) {
  if (!schedule) return true;
  const date = new Date(timestampIso);
  const hour = date.getUTCHours();
  const start = schedule.start_hour;
  const end = schedule.end_hour;

  if (start <= end) {
    return hour >= start && hour <= end;
  } else {
    return hour >= start || hour <= end;
  }
}

/**
 * Checks if a given timestamp falls within any configured maintenance window.
 */
export function matchMaintenanceWindow(timestampIso, maintenanceWindows = []) {
  const date = new Date(timestampIso);
  const day = date.getUTCDay();
  const hour = date.getUTCHours();

  for (const mw of maintenanceWindows) {
    if (mw.days_of_week && !mw.days_of_week.includes(day)) {
      continue;
    }
    const start = mw.start_hour_utc;
    const end = mw.end_hour_utc;
    const inHour = start <= end ? (hour >= start && hour <= end) : (hour >= start || hour <= end);

    if (inHour) {
      return mw;
    }
  }
  return null;
}

/**
 * Applies evidence-preserving context evaluations against a raw detection
 * Handles approved scanners, scheduled backups, patch servers, and maintenance windows.
 */
export function applyContextToDetection(detection, config) {
  const mitigations = [];
  const unexplainedEvidence = [];
  let cumulativeMitigation = 0;

  const srcIp = detection.source_ip || detection.pivot_host;
  const startTime = detection.start_time;

  // 1. Check Approved Security Scanners
  const matchedScanner = (config.approved_security_scanners || []).find(s => s.ip === srcIp);
  if (matchedScanner) {
    const inSchedule = isWithinSchedule(startTime, matchedScanner.active_schedule_utc);
    const authorizedPorts = matchedScanner.authorized_ports;
    
    let unauthorizedPortsFound = [];
    if (authorizedPorts !== 'ALL' && Array.isArray(authorizedPorts) && detection.observed_ports) {
      unauthorizedPortsFound = detection.observed_ports.filter(p => !authorizedPorts.includes(p));
    }

    if (unauthorizedPortsFound.length > 0) {
      unexplainedEvidence.push({
        type: 'UNAUTHORIZED_SCAN_PORTS',
        details: `Scanner ${srcIp} probed ports [${unauthorizedPortsFound.join(', ')}] not declared in authorized port profile.`,
        ports: unauthorizedPortsFound
      });
    }

    let factor = matchedScanner.max_mitigation_factor || 0.80;
    let rationale = `Source ${srcIp} matches verified security scanner (${matchedScanner.hostname || matchedScanner.vendor}).`;

    if (!inSchedule) {
      factor *= 0.5;
      unexplainedEvidence.push({
        type: 'OFF_HOURS_SCANNER_ACTIVITY',
        details: `Security scanner ${srcIp} active at ${startTime} (outside scheduled window ${matchedScanner.active_schedule_utc?.start_hour}:00-${matchedScanner.active_schedule_utc?.end_hour}:00 UTC).`
      });
      rationale += ` Warning: Activity occurred outside designated audit window.`;
    }

    mitigations.push({
      type: 'APPROVED_SCANNER',
      tag: MitigationTag.AUTH_SEC_SCANNER,
      discount_factor: factor,
      rationale,
      matched_asset: matchedScanner
    });
    cumulativeMitigation = Math.max(cumulativeMitigation, factor);
  }

  // 2. Check Large Nightly Backups
  const matchedBackup = (config.large_nightly_backups || []).find(b => b.src_ip === srcIp);
  if (matchedBackup) {
    const inSchedule = isWithinSchedule(startTime, matchedBackup.scheduled_window_utc);
    const flows = detection.evidence_flows || [];
    
    const validTargets = flows.filter(f => f.dst_ip === matchedBackup.dst_ip && f.dst_port === matchedBackup.port);
    const unexpectedFlows = flows.filter(f => f.dst_ip !== matchedBackup.dst_ip || f.dst_port !== matchedBackup.port);

    if (unexpectedFlows.length > 0) {
      unexplainedEvidence.push({
        type: 'UNEXPECTED_BACKUP_TARGET_OR_PORT',
        details: `Backup host ${srcIp} initiated connections to unexpected targets/ports: [${unexpectedFlows.map(f => `${f.dst_ip}:${f.dst_port}`).slice(0, 3).join(', ')}].`,
        count: unexpectedFlows.length
      });
    }

    let factor = matchedBackup.max_mitigation_factor || 0.80;
    let rationale = `Traffic originates from authorized backup source ${srcIp} for task '${matchedBackup.name}'.`;

    if (!inSchedule) {
      factor *= 0.4;
      unexplainedEvidence.push({
        type: 'OFF_HOURS_BACKUP_EXECUTION',
        details: `Backup job ran at ${startTime} outside expected window (${matchedBackup.scheduled_window_utc?.start_hour}:00-${matchedBackup.scheduled_window_utc?.end_hour}:00 UTC).`
      });
      rationale += ` Warning: Backup executed outside scheduled window.`;
    }

    mitigations.push({
      type: 'AUTHORIZED_BACKUP',
      tag: MitigationTag.AUTH_NIGHTLY_BACKUP,
      discount_factor: factor,
      rationale,
      matched_asset: matchedBackup
    });
    cumulativeMitigation = Math.max(cumulativeMitigation, factor);
  }

  // 3. Check Patch Servers
  const matchedPatch = (config.patch_servers || []).find(p => p.ip === srcIp);
  if (matchedPatch) {
    const allowedPorts = matchedPatch.ports || [80, 443, 8530, 8531];
    const targets = detection.observed_hosts || detection.fanout_targets || [];
    const ports = detection.targeted_ports || detection.admin_ports || [];

    const nonPatchPorts = ports.filter(p => !allowedPorts.includes(p));
    if (nonPatchPorts.length > 0) {
      unexplainedEvidence.push({
        type: 'NON_PATCH_PORTS_ACCESSED',
        details: `Patch server ${srcIp} communicated on non-update ports [${nonPatchPorts.join(', ')}].`
      });
    }

    let factor = matchedPatch.max_mitigation_factor || 0.75;
    if (nonPatchPorts.length > 0) factor *= 0.5;

    mitigations.push({
      type: 'PATCH_DISTRIBUTION',
      tag: MitigationTag.AUTH_PATCH_DISTRIBUTION,
      discount_factor: factor,
      rationale: `Source ${srcIp} matches verified patch distribution system (${matchedPatch.hostname || matchedPatch.service}).`,
      matched_asset: matchedPatch
    });
    cumulativeMitigation = Math.max(cumulativeMitigation, factor);
  }

  // 4. Check Global Maintenance Windows
  const isKnownAsset = (config.approved_security_scanners || []).some(s => s.ip === srcIp) ||
                       (config.large_nightly_backups || []).some(b => b.src_ip === srcIp) ||
                       (config.patch_servers || []).some(p => p.ip === srcIp) ||
                       (config.trusted_activity || []).some(t => t.ip === srcIp);

  const activeMw = matchMaintenanceWindow(startTime, config.maintenance_windows);
  if (activeMw && isKnownAsset) {
    mitigations.push({
      type: 'MAINTENANCE_WINDOW',
      tag: MitigationTag.MAINTENANCE_WINDOW,
      discount_factor: activeMw.mitigation_factor || 0.40,
      rationale: `Activity from known asset ${srcIp} coincided with scheduled maintenance window '${activeMw.name}' (${activeMw.id}).`,
      matched_asset: activeMw
    });
    cumulativeMitigation = Math.max(cumulativeMitigation, (activeMw.mitigation_factor || 0.40) * 0.75);
  }

  let adjustedScore = Math.round(detection.raw_score * (1 - Math.min(0.85, cumulativeMitigation)));

  if (unexplainedEvidence.length > 0) {
    const penalty = (config.prioritization_weights?.unexplained_evidence_penalty || 20);
    adjustedScore = Math.min(100, adjustedScore + penalty);
  }

  let contextStatus = 'ESCALATED_HIGH_RISK';
  if (mitigations.length > 0 && unexplainedEvidence.length === 0 && adjustedScore < 30) {
    contextStatus = 'DEPRIORITIZED_BENIGN_LOOKALIKE';
  } else if (mitigations.length > 0 && unexplainedEvidence.length > 0) {
    contextStatus = 'REVIEW_REQUIRED_DEVIATION';
  } else if (adjustedScore < 50) {
    contextStatus = 'MEDIUM_RISK';
  }

  return {
    detection_id: `DET_${Math.random().toString(36).substring(2, 9).toUpperCase()}`,
    rule_id: detection.rule_id,
    rule_name: detection.rule_name,
    source_ip: srcIp,
    raw_score: detection.raw_score,
    adjusted_score: Math.max(5, Math.min(100, adjustedScore)),
    cumulative_mitigation: Math.round(cumulativeMitigation * 100),
    context_mitigations: mitigations,
    unexplained_evidence: unexplainedEvidence,
    context_status: contextStatus,
    start_time: detection.start_time,
    end_time: detection.end_time,
    evidence_records: detection.evidence_records,
    evidence_flows: detection.evidence_flows,
    original_detection: detection
  };
}
