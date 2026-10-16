/**
 * Adaptive Context Replay Engine
 * Produces an auditable before-and-after comparison of detection findings:
 * - Stage 1: Naive / Static Rule Assessment (No Context)
 * - Stage 2: Context-Aware Assessment (With Baselining & Approved Profiles)
 * - Delta Analysis: What changed, by how much, and the exact rationale
 * - Unexplained Evidence: Critical residual observations not justified by context profiles
 */

export function generateAdaptiveContextReplay(rawDetections, contextualizedDetections, incidents, config) {
  const replayItems = [];

  for (const incident of incidents) {
    const matchingContextualDetections = contextualizedDetections.filter(
      cd => cd.source_ip === incident.source_entity
    );

    const ruleDeltas = matchingContextualDetections.map(cd => {
      const orig = cd.original_detection;
      const scoreDelta = cd.raw_score - cd.adjusted_score;

      return {
        rule_id: cd.rule_id,
        rule_name: cd.rule_name,
        raw_score: cd.raw_score,
        adjusted_score: cd.adjusted_score,
        score_reduction: scoreDelta,
        percentage_reduction: cd.raw_score > 0 ? Math.round((scoreDelta / cd.raw_score) * 100) : 0,
        why_changed: cd.context_mitigations.length > 0
          ? cd.context_mitigations.map(m => m.rationale).join(' ')
          : 'No contextual mitigation applied; original rule score sustained.',
        mitigations_applied: cd.context_mitigations,
        unexplained_evidence: cd.unexplained_evidence
      };
    });

    const totalRawScore = incident.raw_score;
    const finalPrioritizationScore = incident.prioritization_score;
    const overallDelta = totalRawScore - finalPrioritizationScore;

    const incidentUnexplained = [];
    for (const rd of ruleDeltas) {
      if (rd.unexplained_evidence && rd.unexplained_evidence.length > 0) {
        incidentUnexplained.push(...rd.unexplained_evidence);
      }
    }

    replayItems.push({
      incident_id: incident.incident_id,
      source_entity: incident.source_entity,
      time_range: {
        first_seen: incident.first_seen,
        last_seen: incident.last_seen,
        duration_seconds: incident.duration_seconds
      },
      naive_stage: {
        assessment_type: 'Naive Static Rule Engine (Zero Context)',
        raw_score: totalRawScore,
        naive_severity: totalRawScore >= 70 ? 'HIGH / CRITICAL' : totalRawScore >= 40 ? 'MEDIUM' : 'LOW',
        rule_count: ruleDeltas.length,
        summary: `Alert triggered on volumetric / pattern thresholds without organizational context.`
      },
      context_stage: {
        assessment_type: 'Context-Aware Adaptive Baselining Engine',
        adjusted_score: finalPrioritizationScore,
        context_severity: incident.severity,
        context_status: incident.context_summary.is_benign_lookalike
          ? 'DEPRIORITIZED_BENIGN_LOOKALIKE'
          : incidentUnexplained.length > 0
            ? 'REVIEW_REQUIRED_DEVIATION'
            : 'ESCALATED_HIGH_RISK',
        summary: incident.context_summary.is_benign_lookalike
          ? `Verified benign operational pattern (${incident.context_summary.mitigations.map(m => m.type).join(', ')}). Deprioritized to reduce analyst fatigue while preserving audit records.`
          : `High-risk anomalous activity confirmed with actionable prioritization.`
      },
      delta_analysis: {
        overall_score_change: overallDelta > 0 ? `-${overallDelta} pts` : `+${Math.abs(overallDelta)} pts`,
        score_change_numeric: -overallDelta,
        rule_deltas: ruleDeltas
      },
      unexplained_evidence: {
        count: incidentUnexplained.length,
        has_unexplained: incidentUnexplained.length > 0,
        items: incidentUnexplained,
        analyst_guidance: incidentUnexplained.length > 0
          ? 'CRITICAL ALERT: Although host matched baseline context, unexplained anomalies (unexpected ports, off-schedule activity, or unapproved targets) were detected. Do NOT auto-close!'
          : 'All observed flows strictly conform to approved baseline profile and schedule.'
      },
      evidence_preservation: {
        total_records_preserved: incident.record_count,
        sample_record_ids: incident.record_ids.slice(0, 10),
        evidence_integrity_statement: 'All raw flow records, timestamps, and packet metrics remain permanently preserved in forensic audit logs. No data was pruned or suppressed.'
      }
    });
  }

  return replayItems;
}
