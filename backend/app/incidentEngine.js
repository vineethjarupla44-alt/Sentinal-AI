import { SeverityLevel } from './types.js';

/**
 * Maps numeric 0-100 score to standardized SOC Severity Level
 */
export function calculateSeverityLevel(score) {
  if (score >= 85) return SeverityLevel.CRITICAL;
  if (score >= 65) return SeverityLevel.HIGH;
  if (score >= 40) return SeverityLevel.MEDIUM;
  if (score >= 20) return SeverityLevel.LOW;
  return SeverityLevel.INFORMATIONAL;
}

/**
 * Checks if any destination host in records is a high-value asset
 */
export function checkHighValueAssetTargeting(detections, config) {
  const trustedIps = new Set((config.trusted_activity || []).map(t => t.ip));
  for (const det of detections) {
    const flows = det.evidence_flows || [];
    for (const f of flows) {
      if (trustedIps.has(f.dst_ip)) {
        return true;
      }
    }
  }
  return false;
}

/**
 * Groups contextualized detections into cohesive Incidents and calculates
 * a transparent 0-100 prioritization score.
 */
export function groupAndScoreIncidents(contextualizedDetections, config) {
  if (!contextualizedDetections || contextualizedDetections.length === 0) {
    return [];
  }

  const bySource = new Map();
  for (const det of contextualizedDetections) {
    const src = det.source_ip;
    if (!bySource.has(src)) {
      bySource.set(src, []);
    }
    bySource.get(src).push(det);
  }

  const incidents = [];
  let incidentCounter = 1;

  for (const [sourceIp, detections] of bySource.entries()) {
    let minEpoch = Infinity;
    let maxEpoch = -Infinity;
    let firstSeen = '';
    let lastSeen = '';

    const allRecordIds = new Set();
    const distinctRules = new Set();
    const allMitigations = [];
    const allUnexplained = [];

    let maxRawScore = 0;
    let maxAdjustedScore = 0;

    for (const det of detections) {
      distinctRules.add(det.rule_id);
      if (det.raw_score > maxRawScore) maxRawScore = det.raw_score;
      if (det.adjusted_score > maxAdjustedScore) maxAdjustedScore = det.adjusted_score;

      for (const rid of (det.evidence_records || [])) {
        allRecordIds.add(rid);
      }
      for (const m of (det.context_mitigations || [])) {
        allMitigations.push(m);
      }
      for (const u of (det.unexplained_evidence || [])) {
        allUnexplained.push(u);
      }

      const orig = det.original_detection;
      if (orig.start_epoch_ms && orig.start_epoch_ms < minEpoch) {
        minEpoch = orig.start_epoch_ms;
        firstSeen = orig.start_time;
      }
      if (orig.end_epoch_ms && orig.end_epoch_ms > maxEpoch) {
        maxEpoch = orig.end_epoch_ms;
        lastSeen = orig.end_time;
      }
    }

    const durationSec = minEpoch !== Infinity && maxEpoch !== -Infinity
      ? Math.max(1, Math.round((maxEpoch - minEpoch) / 1000))
      : 1;

    let baseScore = maxAdjustedScore;
    let formulaSteps = [`Base Adjusted Score: ${baseScore}`];

    let correlationBonus = 0;
    if (distinctRules.size >= 2) {
      correlationBonus = 15 * (distinctRules.size - 1);
      formulaSteps.push(`Multi-Rule Correlation (+${correlationBonus} pts for ${distinctRules.size} distinct attack behaviors)`);
    }

    const targetsHva = checkHighValueAssetTargeting(detections, config);
    let hvaBonus = 0;
    if (targetsHva) {
      hvaBonus = config.prioritization_weights?.high_value_asset_bonus || 15;
      formulaSteps.push(`Critical Asset Proximity (+${hvaBonus} pts targeting Domain Controller/Key Asset)`);
    }

    let unexplainedPenalty = 0;
    if (allUnexplained.length > 0 && maxAdjustedScore < 50) {
      unexplainedPenalty = 15;
      formulaSteps.push(`Unexplained Profile Deviation (+${unexplainedPenalty} pts)`);
    }

    let finalScore = Math.min(100, Math.max(5, baseScore + correlationBonus + hvaBonus + unexplainedPenalty));

    if (allMitigations.length > 0 && allUnexplained.length === 0 && distinctRules.size === 1) {
      finalScore = Math.min(finalScore, maxAdjustedScore);
    }

    const severity = calculateSeverityLevel(finalScore);

    const ruleExplanations = detections.map(d => ({
      rule_id: d.rule_id,
      rule_name: d.rule_name,
      raw_score: d.raw_score,
      adjusted_score: d.adjusted_score,
      explanation: d.original_detection.explanation,
      mitigations_applied: d.context_mitigations.map(m => m.rationale),
      unexplained_evidence: d.unexplained_evidence
    }));

    incidents.push({
      incident_id: `INC-2026-${String(incidentCounter++).padStart(3, '0')}`,
      title: `${severity} Alert: Anomalous activity detected from ${sourceIp}`,
      source_entity: sourceIp,
      severity,
      prioritization_score: finalScore,
      raw_score: maxRawScore,
      first_seen: firstSeen,
      last_seen: lastSeen,
      duration_seconds: durationSec,
      record_count: allRecordIds.size,
      record_ids: Array.from(allRecordIds),
      distinct_rules_triggered: Array.from(distinctRules),
      triggered_rules: ruleExplanations,
      scoring_breakdown: {
        raw_score: maxRawScore,
        base_adjusted_score: baseScore,
        multi_rule_correlation_bonus: correlationBonus,
        high_value_asset_bonus: hvaBonus,
        unexplained_deviation_penalty: unexplainedPenalty,
        final_score: finalScore,
        formula_audit: formulaSteps.join(' -> ')
      },
      context_summary: {
        is_mitigated: allMitigations.length > 0,
        mitigations: allMitigations,
        unexplained_evidence: allUnexplained,
        is_benign_lookalike: finalScore < 30 && allMitigations.length > 0 && allUnexplained.length === 0
      }
    });
  }

  incidents.sort((a, b) => b.prioritization_score - a.prioritization_score);

  return incidents;
}
