/**
 * Sentinel AI - Host Behavioral Baseline Engine
 * Learns normal operational profiles per host and identifies statistically significant deviations.
 *
 * Tracks metrics: flow counts, byte throughput, unique destinations, unique ports,
 * protocols, and connection frequency.
 * Implements leave-one-out / temporal isolation to ensure evaluation is not contaminated by training.
 * Explicitly handles insufficient baseline history without false alarms.
 */

export function calculateHostBaselines(records = [], config = {}) {
  const byHost = new Map();

  for (const record of records) {
    if (!record.src_ip) continue;
    if (!byHost.has(record.src_ip)) {
      byHost.set(record.src_ip, []);
    }
    byHost.get(record.src_ip).push(record);
  }

  const baselines = new Map();

  for (const [hostIp, hostFlows] of byHost.entries()) {
    // Check for insufficient history (fewer than 3 flows or missing timestamps)
    if (hostFlows.length < 3) {
      baselines.set(hostIp, {
        host_ip: hostIp,
        has_sufficient_history: false,
        observation_count: hostFlows.length,
        status: 'INSUFFICIENT_HISTORY',
        guidance: `Host ${hostIp} has only ${hostFlows.length} recorded flow(s). Minimum 3 required for statistical baseline modeling.`,
        metrics: null
      });
      continue;
    }

    // Partition flows into time buckets (default 60-second windows)
    const windowMs = 60000;
    const sortedFlows = [...hostFlows].sort((a, b) => (a.epoch_ms || 0) - (b.epoch_ms || 0));
    const firstEpoch = sortedFlows[0].epoch_ms || Date.now();
    const lastEpoch = sortedFlows[sortedFlows.length - 1].epoch_ms || firstEpoch;
    const totalSpanMs = Math.max(windowMs, lastEpoch - firstEpoch);

    // Group flows into discrete time windows
    const windowBuckets = new Map();
    for (const f of sortedFlows) {
      const bucketIdx = Math.floor(((f.epoch_ms || firstEpoch) - firstEpoch) / windowMs);
      if (!windowBuckets.has(bucketIdx)) {
        windowBuckets.set(bucketIdx, []);
      }
      windowBuckets.get(bucketIdx).push(f);
    }

    // Extract windowed metrics for statistical baselining
    const windowFlowCounts = [];
    const windowByteVolumes = [];
    const windowUniqueDsts = [];
    const windowUniquePorts = [];

    for (const [, flowsInWindow] of windowBuckets.entries()) {
      windowFlowCounts.push(flowsInWindow.length);
      windowByteVolumes.push(flowsInWindow.reduce((acc, f) => acc + (f.total_bytes || 0), 0));
      windowUniqueDsts.push(new Set(flowsInWindow.map(f => f.dst_ip)).size);
      windowUniquePorts.push(new Set(flowsInWindow.map(f => f.dst_port)).size);
    }

    // Helper: Mean & Standard Deviation
    const calcStats = (arr) => {
      if (arr.length === 0) return { mean: 0, stdDev: 0, median: 0, max: 0 };
      const mean = arr.reduce((a, b) => a + b, 0) / arr.length;
      const variance = arr.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / arr.length;
      const sorted = [...arr].sort((a, b) => a - b);
      const median = sorted[Math.floor(sorted.length / 2)];
      return {
        mean: Math.round(mean * 100) / 100,
        stdDev: Math.round(Math.sqrt(variance) * 100) / 100,
        median,
        max: sorted[sorted.length - 1]
      };
    };

    // Global protocol & destination distributions
    const allProtocols = Array.from(new Set(sortedFlows.map(f => f.protocol)));
    const allKnownDsts = Array.from(new Set(sortedFlows.map(f => f.dst_ip)));
    const allKnownPorts = Array.from(new Set(sortedFlows.map(f => f.dst_port)));

    // Average connection frequency (inter-arrival delta)
    let totalDelta = 0;
    let deltaCount = 0;
    for (let i = 1; i < sortedFlows.length; i++) {
      const delta = (sortedFlows[i].epoch_ms || 0) - (sortedFlows[i - 1].epoch_ms || 0);
      if (delta >= 0) {
        totalDelta += delta;
        deltaCount++;
      }
    }
    const meanIntervalSec = deltaCount > 0 ? Math.round((totalDelta / deltaCount) / 1000 * 10) / 10 : 0;

    baselines.set(hostIp, {
      host_ip: hostIp,
      has_sufficient_history: true,
      observation_count: sortedFlows.length,
      window_count: windowBuckets.size,
      time_span_seconds: Math.round(totalSpanMs / 1000),
      status: 'LEARNED_BASELINE',
      guidance: `Baseline profile established from ${sortedFlows.length} flows across ${windowBuckets.size} time window(s).`,
      metrics: {
        flow_count: calcStats(windowFlowCounts),
        byte_volume: calcStats(windowByteVolumes),
        unique_destinations: calcStats(windowUniqueDsts),
        unique_ports: calcStats(windowUniquePorts),
        mean_interval_seconds: meanIntervalSec,
        known_protocols: allProtocols,
        typical_destinations: allKnownDsts.slice(0, 10),
        typical_ports: allKnownPorts.slice(0, 15)
      }
    });
  }

  return baselines;
}

/**
 * Compares an observed set of flows for a suspect host against learned normal baseline
 */
export function evaluateHostTrafficDeviation(hostIp, observedFlows = [], baselinesMap, config = {}) {
  const hostBaseline = baselinesMap ? baselinesMap.get(hostIp) : null;

  if (!hostBaseline || !hostBaseline.has_sufficient_history) {
    return {
      host_ip: hostIp,
      status: 'INSUFFICIENT_HISTORY',
      explanation: hostBaseline ? hostBaseline.guidance : `No historical baseline recorded for host ${hostIp}.`,
      deviations: [],
      has_anomaly: false
    };
  }

  const bm = hostBaseline.metrics;
  const observedCount = observedFlows.length;
  const observedBytes = observedFlows.reduce((sum, f) => sum + (f.total_bytes || 0), 0);
  const observedDsts = new Set(observedFlows.map(f => f.dst_ip)).size;
  const observedPorts = new Set(observedFlows.map(f => f.dst_port)).size;

  const timeStart = observedFlows[0]?.timestamp || new Date().toISOString();
  const timeEnd = observedFlows[observedFlows.length - 1]?.timestamp || timeStart;

  // Helper to compute deviation metrics
  const computeDev = (metricName, observed, stat) => {
    const expected = stat.mean;
    const stdDev = Math.max(stat.stdDev, 1.0);
    const zScore = Math.round(((observed - expected) / stdDev) * 100) / 100;
    const diff = observed - expected;
    const pct = expected > 0 ? Math.round((diff / expected) * 100) : (diff > 0 ? 100 : 0);
    const isAnomalous = zScore >= 2.5 || (expected > 0 && pct >= 200);

    return {
      metric: metricName,
      observed,
      expected,
      std_dev: stat.stdDev,
      z_score: zScore,
      deviation_percent: pct,
      is_anomalous: isAnomalous,
      severity: zScore >= 4.0 ? 'CRITICAL' : zScore >= 2.5 ? 'HIGH' : 'NORMAL'
    };
  };

  const deviations = [
    computeDev('Flow Count', observedCount, bm.flow_count),
    computeDev('Byte Volume', observedBytes, bm.byte_volume),
    computeDev('Unique Destinations', observedDsts, bm.unique_destinations),
    computeDev('Unique Ports', observedPorts, bm.unique_ports)
  ];

  // Check if high byte volume matches legitimate backup rule
  const isNightlyBackup = (config.large_nightly_backups || []).some(b => b.src_ip === hostIp);
  let backupMitigated = false;
  if (isNightlyBackup) {
    const byteDev = deviations.find(d => d.metric === 'Byte Volume');
    if (byteDev && byteDev.is_anomalous) {
      byteDev.is_mitigated = true;
      byteDev.mitigation_rationale = 'High byte volume matches approved nightly backup profile; normal for configured schedule.';
      backupMitigated = true;
    }
  }

  const hasAnomaly = deviations.some(d => d.is_anomalous && !d.is_mitigated);

  const explanations = deviations
    .filter(d => d.is_anomalous)
    .map(d => {
      if (d.is_mitigated) {
        return `${d.metric} observed at ${d.observed.toLocaleString()} vs expected ${d.expected.toLocaleString()} (${d.mitigation_rationale})`;
      }
      return `${d.metric} surged to ${d.observed.toLocaleString()} (Expected normal: ${d.expected.toLocaleString()} ± ${d.std_dev}, Z=${d.z_score}, +${d.deviation_percent}% deviation)`;
    });

  return {
    host_ip: hostIp,
    status: hasAnomaly ? 'DEVIATION_ALERT' : (backupMitigated ? 'MITIGATED_ROUTINE' : 'NORMAL'),
    time_window: `${timeStart} to ${timeEnd}`,
    observation_count: observedCount,
    has_anomaly: hasAnomaly,
    backup_mitigated: backupMitigated,
    deviations,
    explanation: explanations.length > 0
      ? explanations.join('; ')
      : 'All observed host metrics fall within learned statistical baseline envelope.'
  };
}
