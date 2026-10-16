/**
 * Sentinel AI - Beaconing & Periodic Activity Detection Engine
 * Identifies automated C2 keepalives, periodic heartbeats, and irregular connection patterns.
 *
 * Calculates:
 * - Connection time gaps (delta t)
 * - Repetition counts
 * - Mean and median intervals
 * - Interval variability (Standard deviation and Coefficient of Variation CV = sigma / mu)
 * - Observation duration
 *
 * Disambiguates legitimate recurring services (NTP, DNS, internal monitoring, WSUS)
 * from suspicious external Command and Control (C2) beaconing.
 */

export function detectBeaconing(records = [], config = {}) {
  const groups = new Map();

  // Filter for valid flows with timestamps and group by (src_ip, dst_ip, dst_port)
  for (const record of records) {
    if (!record.src_ip || !record.dst_ip) continue;
    const key = `${record.src_ip}->${record.dst_ip}:${record.dst_port || 0}/${record.protocol || 'TCP'}`;
    if (!groups.has(key)) {
      groups.set(key, {
        src_ip: record.src_ip,
        dst_ip: record.dst_ip,
        dst_port: record.dst_port || 0,
        protocol: record.protocol || 'TCP',
        flows: []
      });
    }
    groups.get(key).flows.push(record);
  }

  const findings = [];

  // Minimum repetitions required to evaluate periodicity (default: 4)
  const minRepetitions = config.detection_thresholds?.beaconing?.min_repetitions || 4;

  for (const [channelKey, group] of groups.entries()) {
    if (group.flows.length < minRepetitions) continue;

    // Sort flows chronologically
    const sortedFlows = [...group.flows].sort((a, b) => (a.epoch_ms || 0) - (b.epoch_ms || 0));
    const firstEpoch = sortedFlows[0].epoch_ms || 0;
    const lastEpoch = sortedFlows[sortedFlows.length - 1].epoch_ms || firstEpoch;
    const durationSec = Math.max(1, Math.round((lastEpoch - firstEpoch) / 1000));

    // Calculate inter-arrival time gaps (intervals in seconds)
    const intervals = [];
    const intervalDataPoints = [];

    for (let i = 1; i < sortedFlows.length; i++) {
      const deltaMs = (sortedFlows[i].epoch_ms || 0) - (sortedFlows[i - 1].epoch_ms || 0);
      const deltaSec = Math.max(0, Math.round((deltaMs / 1000) * 10) / 10);
      intervals.push(deltaSec);
      intervalDataPoints.push({
        timestamp: sortedFlows[i].timestamp,
        epoch_ms: sortedFlows[i].epoch_ms,
        interval_seconds: deltaSec,
        bytes: sortedFlows[i].total_bytes || 0
      });
    }

    if (intervals.length === 0) continue;

    // Statistical intervals
    const meanInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    const sortedIntervals = [...intervals].sort((a, b) => a - b);
    const medianInterval = sortedIntervals[Math.floor(sortedIntervals.length / 2)];
    const variance = intervals.reduce((acc, val) => acc + Math.pow(val - meanInterval, 2), 0) / intervals.length;
    const stdDev = Math.sqrt(variance);
    // Coefficient of Variation (Jitter Metric): CV = sigma / mu
    const cv = meanInterval > 0 ? stdDev / meanInterval : 1.0;

    // Evaluate Legitimacy & Context
    // 1. Is NTP (port 123)?
    const isNtp = group.dst_port === 123 || group.protocol === 'NTP';
    // 2. Is standard internal DNS (port 53)?
    const isDns = group.dst_port === 53;
    // 3. Matches trusted activity IP or hostname?
    const isTrustedDest = (config.trusted_activity || []).some(t => t.ip === group.dst_ip);
    // 4. Matches approved scanner or patch server?
    const isApprovedScanner = (config.approved_security_scanners || []).some(s => s.ip === group.src_ip);
    const isPatchServer = (config.patch_servers || []).some(p => p.ip === group.src_ip);

    // Is destination internal RFC1918?
    const isInternalDest = group.dst_ip.startsWith('10.') || group.dst_ip.startsWith('192.168.') || group.dst_ip.startsWith('172.16.');

    let verdict = 'IRREGULAR_CONNECTIONS';
    let isSuspicious = false;
    let rationale = '';

    if (isNtp) {
      verdict = 'LEGITIMATE_NTP_SYNC';
      isSuspicious = false;
      rationale = `Periodic time synchronization against NTP server (${group.dst_ip}:123). Standard network operational protocol (RFC 5905).`;
    } else if (isTrustedDest) {
      verdict = 'TRUSTED_INFRASTRUCTURE_HEARTBEAT';
      isSuspicious = false;
      rationale = `Periodic telemetry exchanged with approved corporate infrastructure (${group.dst_ip}). Regularity is expected.`;
    } else if (isApprovedScanner || isPatchServer) {
      verdict = 'AUTHORIZED_ADMIN_SERVICE';
      isSuspicious = false;
      rationale = `Periodic connections originate from approved administrative infrastructure (${group.src_ip}).`;
    } else if (cv <= 0.20 && meanInterval >= 10 && meanInterval <= 600) {
      // Highly regular interval with jitter <= 20%
      if (!isInternalDest) {
        verdict = 'SUSPICIOUS_C2_BEACONING';
        isSuspicious = true;
        rationale = `High-confidence C2 beaconing detected: Host ${group.src_ip} made ${sortedFlows.length} repeated connections to external target ${group.dst_ip}:${group.dst_port} at ultra-regular intervals of ~${Math.round(meanInterval)}s (CV=${cv.toFixed(2)}, jitter < 20%).`;
      } else {
        verdict = 'PERIODIC_INTERNAL_POLL';
        isSuspicious = false;
        rationale = `Regular internal polling (~${Math.round(meanInterval)}s interval, CV=${cv.toFixed(2)}) between internal hosts.`;
      }
    } else if (cv <= 0.35 && meanInterval >= 5) {
      // Moderately periodic
      if (!isInternalDest) {
        verdict = 'SUSPICIOUS_PERIODIC_OUTBOUND';
        isSuspicious = true;
        rationale = `Moderately periodic outbound connections (~${Math.round(meanInterval)}s interval, CV=${cv.toFixed(2)}) to external endpoint ${group.dst_ip}. Candidate beaconing with jitter.`;
      } else {
        verdict = 'BENIGN_SERVICE_HEARTBEAT';
        isSuspicious = false;
        rationale = `Internal service heartbeat with moderate jitter (CV=${cv.toFixed(2)}).`;
      }
    } else {
      verdict = 'IRREGULAR_TRAFFIC';
      isSuspicious = false;
      rationale = `Repeated connections exhibit high timing jitter (CV=${cv.toFixed(2)}), typical of human interactive traffic or sporadic requests.`;
    }

    findings.push({
      channel_id: channelKey,
      source_ip: group.src_ip,
      destination_ip: group.dst_ip,
      destination_port: group.dst_port,
      protocol: group.protocol,
      repetition_count: sortedFlows.length,
      observation_duration_seconds: durationSec,
      metrics: {
        mean_interval_seconds: Math.round(meanInterval * 10) / 10,
        median_interval_seconds: Math.round(medianInterval * 10) / 10,
        std_dev_seconds: Math.round(stdDev * 10) / 10,
        coefficient_of_variation: Math.round(cv * 100) / 100,
        jitter_pct: Math.round(cv * 100),
        min_interval_seconds: sortedIntervals[0],
        max_interval_seconds: sortedIntervals[sortedIntervals.length - 1]
      },
      intervals,
      interval_datapoints: intervalDataPoints,
      is_suspicious: isSuspicious,
      verdict,
      rationale,
      evidence_record_ids: sortedFlows.map(f => f.record_id)
    });
  }

  // Sort: Suspicious beaconing candidates first
  findings.sort((a, b) => (b.is_suspicious ? 1 : 0) - (a.is_suspicious ? 1 : 0));

  return findings;
}
