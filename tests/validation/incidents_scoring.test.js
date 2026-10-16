import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { groupAndScoreIncidents } from '../../backend/app/incidentEngine.js';
import { generateAdaptiveContextReplay } from '../../backend/app/contextReplay.js';
import { calculateHostBaselines, evaluateHostTrafficDeviation } from '../../backend/app/hostBaseline.js';
import { normalizeCSV } from '../../backend/app/dataLoader.js';
import { RuleId, MitigationTag, SeverityLevel, createFlowRecord } from '../../backend/app/types.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function getPath(rel) {
  const c1 = path.resolve(rel);
  const c2 = path.resolve(__dirname, '..', '..', rel);
  return fs.existsSync(c1) ? c1 : c2;
}

const config = JSON.parse(fs.readFileSync(getPath('config/config.json'), 'utf8'));

/**
 * TC-INC-GROUP-001: Incident Grouping by Source Entity
 * Feature: Multi-Detection Incident Aggregation
 * Expected: Detections sharing the same source entity are merged into one incident.
 */
test('TC-INC-GROUP-001: Aggregates multiple detection rules from the same source into a single prioritized incident', () => {
  const mockDetections = [
    {
      detection_id: 'DET_01',
      rule_id: RuleId.PORT_SCAN,
      rule_name: 'Vertical Port Scan Detection',
      source_ip: '10.0.1.77',
      raw_score: 55,
      adjusted_score: 55,
      context_mitigations: [],
      unexplained_evidence: [],
      start_time: '2026-10-15T02:00:00Z',
      end_time: '2026-10-15T02:01:00Z',
      evidence_records: ['r1', 'r2', 'r3'],
      original_detection: {
        start_epoch_ms: 1760500000000,
        end_epoch_ms: 1760500060000,
        start_time: '2026-10-15T02:00:00Z',
        end_time: '2026-10-15T02:01:00Z',
        explanation: 'Observed port scan'
      }
    },
    {
      detection_id: 'DET_02',
      rule_id: RuleId.NETWORK_SWEEP,
      rule_name: 'Horizontal Network Sweep Detection',
      source_ip: '10.0.1.77',
      raw_score: 65,
      adjusted_score: 65,
      context_mitigations: [],
      unexplained_evidence: [],
      start_time: '2026-10-15T02:01:30Z',
      end_time: '2026-10-15T02:02:30Z',
      evidence_records: ['r4', 'r5'],
      original_detection: {
        start_epoch_ms: 1760500090000,
        end_epoch_ms: 1760500150000,
        start_time: '2026-10-15T02:01:30Z',
        end_time: '2026-10-15T02:02:30Z',
        explanation: 'Observed network sweep'
      }
    }
  ];

  const incidents = groupAndScoreIncidents(mockDetections, config);
  assert.equal(incidents.length, 1, 'Must merge into a single incident');
  assert.equal(incidents[0].source_entity, '10.0.1.77');
  assert.equal(incidents[0].record_count, 5);
  assert.equal(incidents[0].distinct_rules_triggered.length, 2);
  assert.ok(incidents[0].prioritization_score > 65, 'Multi-rule correlation bonus must elevate score');
});

/**
 * TC-INC-DEDUP-001: Evidence Deduplication
 * Feature: Deduplication Invariance
 * Expected: Ingesting duplicate records ignores identical re-transmissions.
 */
test('TC-INC-DEDUP-001: Deduplicates identical telemetry records without double-counting flow evidence', () => {
  const schemaConfigs = JSON.parse(fs.readFileSync(getPath('config/dataset_mapping.json'), 'utf8'));
  const csvWithDups = `ts,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,proto
2026-10-15T02:00:00Z,DUP_1,10.0.1.1,5000,10.0.2.2,80,tcp
2026-10-15T02:00:00Z,DUP_1,10.0.1.1,5000,10.0.2.2,80,tcp
2026-10-15T02:00:05Z,UNIQ_2,10.0.1.1,5001,10.0.2.2,80,tcp`;

  const result = normalizeCSV(csvWithDups, schemaConfigs, 'zeek_conn_log');
  assert.equal(result.records.length, 2, 'Must only retain 2 unique records');
  assert.equal(result.audit.duplicates_suppressed, 1);
});

/**
 * TC-INC-SCORE-001: Transparent 0-100 Prioritization Scoring
 * Feature: Mathematical Scoring Formula Audit
 * Expected: Score integrates base adjusted score + multi-rule bonus + high-value asset bonus.
 */
test('TC-INC-SCORE-001: Audits mathematical prioritization score breakdown and bounds', () => {
  const highRiskDetection = {
    detection_id: 'DET_DC',
    rule_id: RuleId.LATERAL_MOVEMENT,
    rule_name: 'Spreading & Lateral Movement Indicator',
    source_ip: '10.0.1.20',
    raw_score: 70,
    adjusted_score: 70,
    context_mitigations: [],
    unexplained_evidence: [],
    evidence_records: ['e1', 'e2'],
    evidence_flows: [
      { src_ip: '10.0.1.20', dst_ip: '10.0.0.10', dst_port: 445 } // 10.0.0.10 is DC in config.trusted_activity
    ],
    original_detection: {
      start_epoch_ms: 1760500000000,
      end_epoch_ms: 1760500030000,
      start_time: '2026-10-15T02:00:00Z',
      end_time: '2026-10-15T02:00:30Z',
      explanation: 'Lateral movement towards DC'
    }
  };

  const incidents = groupAndScoreIncidents([highRiskDetection], config);
  assert.equal(incidents.length, 1);
  const inc = incidents[0];
  assert.ok(inc.prioritization_score <= 100);
  assert.ok(inc.prioritization_score >= 85, 'Targeting DC must elevate to CRITICAL');
  assert.equal(inc.severity, SeverityLevel.CRITICAL);
  assert.ok(inc.scoring_breakdown.formula_audit.includes('Critical Asset Proximity'));
});

/**
 * TC-INC-REPLAY-001: Adaptive Context Replay Preservation
 * Feature: Transparent Before-and-After Audit
 * Expected: Raw naive assessment and context-aware assessment side-by-side; raw records preserved.
 */
test('TC-INC-REPLAY-001: Adaptive Context Replay maintains 100% of raw evidence while detailing score deltas', () => {
  const rawDet = {
    rule_id: RuleId.PORT_SCAN,
    rule_name: 'Vertical Port Scan Detection',
    source_ip: '10.0.50.5',
    target_ips: ['10.0.1.10'],
    observed_ports: [80, 443],
    raw_score: 75,
    evidence_records: ['r_rep1']
  };

  const ctxDet = {
    detection_id: 'DET_REP_01',
    rule_id: RuleId.PORT_SCAN,
    rule_name: 'Vertical Port Scan Detection',
    source_ip: '10.0.50.5',
    raw_score: 75,
    adjusted_score: 15,
    context_mitigations: [{ type: 'APPROVED_SCANNER', rationale: 'Verified Nessus scanner' }],
    unexplained_evidence: [],
    start_time: '2026-10-15T03:00:00Z',
    end_time: '2026-10-15T03:01:00Z',
    evidence_records: ['r_rep1'],
    original_detection: rawDet
  };

  const incident = {
    incident_id: 'INC-2026-001',
    source_entity: '10.0.50.5',
    severity: SeverityLevel.INFORMATIONAL,
    prioritization_score: 15,
    raw_score: 75,
    record_count: 1,
    record_ids: ['r_rep1'],
    distinct_rules_triggered: [RuleId.PORT_SCAN],
    context_summary: { is_benign_lookalike: true, mitigations: [{ type: 'APPROVED_SCANNER' }], unexplained_evidence: [] }
  };

  const replays = generateAdaptiveContextReplay([rawDet], [ctxDet], [incident], config);
  assert.equal(replays.length, 1);
  const rep = replays[0];

  assert.equal(rep.naive_stage.raw_score, 75);
  assert.equal(rep.context_stage.adjusted_score, 15);
  assert.equal(rep.delta_analysis.overall_score_change, '-60 pts');
  assert.equal(rep.evidence_preservation.total_records_preserved, 1);
  assert.ok(rep.evidence_preservation.evidence_integrity_statement.includes('No data was pruned'));
});

/**
 * TC-INC-INSUFFICIENT-001: Insufficient History Handling
 * Feature: Sparse Observation Defense
 * Expected: Hosts with fewer than 3 flows are tagged INSUFFICIENT_HISTORY without false alerts.
 */
test('TC-INC-INSUFFICIENT-001: Hosts with insufficient observation history (<3 flows) tagged honestly without false alarms', () => {
  const sparseRecords = [
    createFlowRecord({
      record_id: 'sparse_01',
      timestamp: new Date().toISOString(),
      src_ip: '10.0.1.250',
      dst_ip: '10.0.0.1',
      dst_port: 80,
      protocol: 'TCP',
      total_bytes: 400
    }),
    createFlowRecord({
      record_id: 'sparse_02',
      timestamp: new Date().toISOString(),
      src_ip: '10.0.1.250',
      dst_ip: '10.0.0.1',
      dst_port: 80,
      protocol: 'TCP',
      total_bytes: 450
    })
  ];

  const baselines = calculateHostBaselines(sparseRecords, config);
  const bm = baselines.get('10.0.1.250');

  assert.ok(bm);
  assert.equal(bm.has_sufficient_history, false);
  assert.equal(bm.status, 'INSUFFICIENT_HISTORY');
  assert.ok(bm.guidance.includes('Minimum 3 required'));

  const evalResult = evaluateHostTrafficDeviation('10.0.1.250', sparseRecords, baselines, config);
  assert.equal(evalResult.status, 'INSUFFICIENT_HISTORY');
  assert.equal(evalResult.has_anomaly, false);
});
