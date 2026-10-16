import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { applyContextToDetection } from '../../backend/app/trustedActivity.js';
import { calculateHostBaselines, evaluateHostTrafficDeviation } from '../../backend/app/hostBaseline.js';
import { detectBeaconing } from '../../backend/app/beaconingDetector.js';
import { runAllDetectionRules } from '../../backend/app/detectionRules.js';
import { TraceGuardPipeline } from '../../backend/app/pipeline.js';
import { evaluateDetectionPerformance } from '../../backend/app/evaluation.js';
import { createFlowRecord, RuleId, MitigationTag } from '../../backend/app/types.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function getPath(rel) {
  const c1 = path.resolve(rel);
  const c2 = path.resolve(__dirname, '..', '..', rel);
  return fs.existsSync(c1) ? c1 : c2;
}

const config = JSON.parse(fs.readFileSync(getPath('config/config.json'), 'utf8'));

/**
 * TC-LEGIT-BACKUP-001: Scheduled Nightly Backup
 * Feature: Backup Context Mitigation
 * Preconditions: Scheduled backup window (01:00-04:00 UTC), correct destination and port.
 * Expected: Baseline deviation marked as backup_mitigated; status MITIGATED_ROUTINE.
 */
test('TC-LEGIT-BACKUP-001: Scheduled nightly backup with massive byte volume is mitigated without false positive attack alert', () => {
  const baseTime = Date.now() - 3600000;
  const history = [];

  for (let i = 0; i < 6; i++) {
    history.push(createFlowRecord({
      record_id: `b_hist_${i}`,
      timestamp: new Date(baseTime + i * 60000).toISOString(),
      src_ip: '10.0.20.15',
      dst_ip: '10.0.99.100',
      dst_port: 445,
      protocol: 'TCP',
      total_bytes: 50000
    }));
  }

  const baselines = calculateHostBaselines(history, config);

  const backupSurge = [
    createFlowRecord({
      record_id: 'b_surge_01',
      timestamp: '2026-10-15T02:30:00Z', // within 01:00 - 04:00 UTC schedule
      src_ip: '10.0.20.15',
      dst_ip: '10.0.99.100',
      dst_port: 445,
      protocol: 'TCP',
      total_bytes: 850000000 // 850 MB
    })
  ];

  const evalResult = evaluateHostTrafficDeviation('10.0.20.15', backupSurge, baselines, config);
  assert.equal(evalResult.backup_mitigated, true);
  assert.equal(evalResult.has_anomaly, false, 'Authorized backup must not trigger false positive attack alert');
  assert.equal(evalResult.status, 'MITIGATED_ROUTINE');
  assert.ok(evalResult.explanation.includes('approved nightly backup'));
});

/**
 * TC-LEGIT-SCANNER-001: Approved Security Scanner
 * Feature: Scanner Context Mitigation
 * Preconditions: Nessus scanner (10.0.50.5), within schedule (02:00-06:00 UTC), authorized ports.
 * Expected: Score mitigated by 80%, adjusted score < 30, DEPRIORITIZED_BENIGN_LOOKALIKE.
 */
test('TC-LEGIT-SCANNER-001: Approved security scanner within authorized window and ports deprioritizes alert score below 30', () => {
  const scannerDetection = {
    rule_id: RuleId.PORT_SCAN,
    rule_name: 'Vertical Port Scan Detection',
    source_ip: '10.0.50.5',
    target_ips: ['10.0.1.15'],
    observed_ports: [21, 22, 80, 443, 135, 139, 445], // all in authorized profile
    start_time: '2026-10-15T03:30:00Z', // within 02:00-06:00 UTC window
    raw_score: 75,
    evidence_records: ['s1', 's2']
  };

  const result = applyContextToDetection(scannerDetection, config);
  assert.ok(result.adjusted_score < 30, `Score (${result.adjusted_score}) must be deprioritized`);
  assert.equal(result.context_status, 'DEPRIORITIZED_BENIGN_LOOKALIKE');
  assert.equal(result.context_mitigations[0].tag, MitigationTag.AUTH_SEC_SCANNER);
  assert.equal(result.unexplained_evidence.length, 0);
});

/**
 * TC-LEGIT-PATCH-001: Trusted Patch Server
 * Feature: Patch Distribution Context Mitigation
 * Preconditions: WSUS server (10.0.10.20) connects to internal clients on port 8530.
 * Expected: Mitigated by 75%, tag AUTH_PATCH_DISTRIBUTION, score < 30.
 */
test('TC-LEGIT-PATCH-001: Trusted patch distribution server querying client hosts deprioritizes sweep alert', () => {
  const patchDetection = {
    rule_id: RuleId.NETWORK_SWEEP,
    rule_name: 'Horizontal Network Sweep Detection',
    source_ip: '10.0.10.20',
    observed_hosts: ['10.0.1.5', '10.0.1.6', '10.0.1.7', '10.0.1.8', '10.0.1.9', '10.0.1.10'],
    targeted_ports: [8530],
    start_time: '2026-10-15T03:00:00Z',
    raw_score: 65,
    evidence_records: ['p1', 'p2']
  };

  const result = applyContextToDetection(patchDetection, config);
  assert.ok(result.adjusted_score < 30);
  assert.equal(result.context_mitigations[0].tag, MitigationTag.AUTH_PATCH_DISTRIBUTION);
});

/**
 * TC-LEGIT-HEALTH-001: Normal Periodic Monitoring & Health Checks
 * Feature: Legitimate Recurring Protocol Disambiguation
 * Preconditions: Periodic connections to NTP server (10.0.0.5:123).
 * Expected: Verdict LEGITIMATE_NTP_SYNC, is_suspicious = false.
 */
test('TC-LEGIT-HEALTH-001: Periodic health checks and NTP time sync recognized as legitimate operational protocol', () => {
  const records = [];
  const baseEpoch = 1760500000000;

  for (let i = 0; i < 8; i++) {
    records.push(createFlowRecord({
      record_id: `ntp_h_${i}`,
      timestamp: new Date(baseEpoch + i * 15000).toISOString(),
      src_ip: '10.0.1.25',
      dst_ip: '10.0.0.5',
      dst_port: 123,
      protocol: 'UDP',
      total_bytes: 48
    }));
  }

  const findings = detectBeaconing(records, config);
  const ntpFinding = findings.find(f => f.destination_ip === '10.0.0.5');
  assert.ok(ntpFinding);
  assert.equal(ntpFinding.is_suspicious, false);
  assert.equal(ntpFinding.verdict, 'LEGITIMATE_NTP_SYNC');
});

/**
 * TC-LEGIT-HIGHVOL-001: Ordinary High-Volume Legitimate Traffic
 * Feature: Benign Traffic False-Positive Immunity
 * Preconditions: High-volume streaming/web downloads without scan/sweep characteristics.
 * Expected: 0 raw detections triggered.
 */
test('TC-LEGIT-HIGHVOL-001: Ordinary high-volume benign traffic does not trigger port scan, sweep, or lateral rules', () => {
  const benignFlows = [];
  const baseEpoch = 1760500000000;

  for (let i = 0; i < 20; i++) {
    benignFlows.push(createFlowRecord({
      record_id: `norm_dl_${i}`,
      timestamp: new Date(baseEpoch + i * 2000).toISOString(),
      src_ip: '10.0.1.55',
      dst_ip: '142.250.190.46', // Google CDN
      dst_port: 443,
      protocol: 'TCP',
      bytes_out: 5000,
      bytes_in: 500000, // 500 KB per flow
      total_bytes: 505000
    }));
  }

  const detections = runAllDetectionRules(benignFlows, config);
  assert.equal(detections.length, 0, 'Benign single-destination web traffic must not trigger any attack rule');
});

/**
 * TC-LEGIT-SUSP-001: Trusted Activity with Unrelated Suspicious Pattern
 * Feature: Non-suppression of anomalies in approved profiles
 * Preconditions: Scanner active off-hours and probing unauthorized port 31337.
 * Expected: Unexplained evidence flagged, score remains elevated, NOT auto-closed.
 */
test('TC-LEGIT-SUSP-001: Approved scanner exhibiting off-schedule and unapproved port activity preserves alert without suppression', () => {
  const suspiciousScannerDetection = {
    rule_id: RuleId.PORT_SCAN,
    rule_name: 'Vertical Port Scan Detection',
    source_ip: '10.0.50.5',
    target_ips: ['10.0.0.10'], // DC
    observed_ports: [80, 443, 31337],
    start_time: '2026-10-15T15:00:00Z', // 15:00 UTC is outside 02:00-06:00 window
    raw_score: 80,
    evidence_records: ['susp_sc_1', 'susp_sc_2']
  };

  const result = applyContextToDetection(suspiciousScannerDetection, config);
  assert.ok(result.adjusted_score >= 50, 'Score must remain high due to off-hours and unauthorized port');
  assert.equal(result.context_status, 'REVIEW_REQUIRED_DEVIATION');
  assert.ok(result.unexplained_evidence.length >= 2);
  assert.notEqual(result.context_status, 'DEPRIORITIZED_BENIGN_LOOKALIKE');
});

/**
 * TC-LEGIT-EVAL-001: Empirical False-Positive Reduction & Metrics Evaluation
 * Feature: Scientific Performance Metrics
 * Preconditions: Annotated dataset processed through full pipeline.
 * Expected: 100% recall preserved, FP reduction >= 50%, precision gain > 15%.
 */
test('TC-LEGIT-EVAL-001: Evaluates before/after confusion matrix, confirming 100% attack recall and >= 50% false-positive reduction', () => {
  const pipeline = new TraceGuardPipeline();
  const zeekPath = getPath('datasets/synthetic/zeek_sample_annotated.csv');
  const result = pipeline.processFile(zeekPath);

  const evalMetrics = evaluateDetectionPerformance(result);

  assert.equal(evalMetrics.naive_stage.recall, 1.0, 'Naive recall must be 100%');
  assert.equal(evalMetrics.context_aware_stage.recall, 1.0, 'Context-aware recall must be 100% (zero attacks suppressed)');
  assert.equal(evalMetrics.context_aware_stage.fn, 0, 'False negatives must be exactly 0');

  assert.ok(evalMetrics.improvement.fp_reduced_count > 0, 'False alarms must be reduced');
  assert.ok(evalMetrics.improvement.fp_reduction_percent >= 50, 'FP reduction must be >= 50%');
  assert.ok(evalMetrics.context_aware_stage.precision > evalMetrics.naive_stage.precision, 'Precision must improve');
});
