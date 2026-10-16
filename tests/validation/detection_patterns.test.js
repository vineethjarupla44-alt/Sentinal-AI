import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { detectPortScans, detectNetworkSweeps, detectLateralMovement, runAllDetectionRules } from '../../backend/app/detectionRules.js';
import { calculateHostBaselines, evaluateHostTrafficDeviation } from '../../backend/app/hostBaseline.js';
import { detectBeaconing } from '../../backend/app/beaconingDetector.js';
import { applyContextToDetection } from '../../backend/app/trustedActivity.js';
import { buildIncidentTimeline, AttackStage } from '../../backend/app/timelineEngine.js';
import { createFlowRecord, RuleId } from '../../backend/app/types.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function getPath(rel) {
  const c1 = path.resolve(rel);
  const c2 = path.resolve(__dirname, '..', '..', rel);
  return fs.existsSync(c1) ? c1 : c2;
}

const config = JSON.parse(fs.readFileSync(getPath('config/config.json'), 'utf8'));

/**
 * TC-DET-SPIKE-001: Traffic Volume Spikes
 * Feature: Host Traffic Baseline Deviation
 * Preconditions: Normal baseline envelope established with >= 3 historical flows.
 * Expected: Flag anomaly when observed bytes/flows deviate by Z >= 2.5 or > 200%.
 */
test('TC-DET-SPIKE-001: Traffic volume spike triggers statistical baseline deviation alert', () => {
  const baseTime = Date.now() - 360000;
  const baselineRecords = [];

  // 12 regular flows averaging ~1000 bytes each
  for (let i = 0; i < 12; i++) {
    baselineRecords.push(createFlowRecord({
      record_id: `spike_base_${i}`,
      timestamp: new Date(baseTime + i * 15000).toISOString(),
      src_ip: '10.0.1.44',
      dst_ip: '10.0.0.10',
      dst_port: 80,
      protocol: 'TCP',
      total_bytes: 900 + (i % 4) * 50
    }));
  }

  const baselines = calculateHostBaselines(baselineRecords, config);
  const hostBm = baselines.get('10.0.1.44');
  assert.ok(hostBm && hostBm.has_sufficient_history, 'Host must establish baseline');

  // Observed sudden volume spike: 2,500,000 bytes
  const spikeFlows = [
    createFlowRecord({
      record_id: 'spike_surge_1',
      timestamp: new Date().toISOString(),
      src_ip: '10.0.1.44',
      dst_ip: '198.51.100.22',
      dst_port: 443,
      protocol: 'TCP',
      total_bytes: 2500000
    })
  ];

  const evalResult = evaluateHostTrafficDeviation('10.0.1.44', spikeFlows, baselines, config);
  assert.equal(evalResult.has_anomaly, true, 'Surge must be flagged as anomaly');
  assert.equal(evalResult.status, 'DEVIATION_ALERT');

  const byteDev = evalResult.deviations.find(d => d.metric === 'Byte Volume');
  assert.ok(byteDev && byteDev.is_anomalous);
  assert.ok(byteDev.z_score >= 2.5, `Z-score (${byteDev.z_score}) must exceed 2.5`);
  assert.ok(evalResult.explanation.includes('surged to'));
});

/**
 * TC-DET-REPEAT-001: Repeated Connection Blocks
 * Feature: Repetition and Periodicity Evaluation
 * Preconditions: Repeated connections to the same target/port.
 * Expected: Detect repetition and evaluate periodicity without assuming repetition alone proves maliciousness.
 */
test('TC-DET-REPEAT-001: Repeated connection blocks evaluate periodicity and avoid treating repetition alone as malicious', () => {
  const baseTime = 1760500000000;
  const irregularRecords = [];
  const intervals = [5, 45, 12, 180, 20, 95]; // irregular intervals
  let curr = baseTime;

  for (let i = 0; i < intervals.length; i++) {
    irregularRecords.push(createFlowRecord({
      record_id: `rep_irr_${i}`,
      timestamp: new Date(curr).toISOString(),
      src_ip: '10.0.2.15',
      dst_ip: '198.51.100.77',
      dst_port: 443,
      protocol: 'TCP',
      total_bytes: 1500
    }));
    curr += intervals[i] * 1000;
  }

  const findings = detectBeaconing(irregularRecords, config);
  const targetFinding = findings.find(f => f.destination_ip === '198.51.100.77');
  assert.ok(targetFinding, 'Repeated block must be observed and grouped');
  assert.equal(targetFinding.repetition_count, intervals.length);
  assert.equal(targetFinding.is_suspicious, false, 'Irregular repetition alone must NOT be flagged as malicious');
  assert.equal(targetFinding.verdict, 'IRREGULAR_TRAFFIC');
});

/**
 * TC-DET-UNAUTHPORT-001: Unapproved Ports
 * Feature: Policy-driven port authorization enforcement
 * Preconditions: Scanner or patch server probes ports outside its authorized policy.
 * Expected: Flag unexplained evidence and apply penalty to final score.
 */
test('TC-DET-UNAUTHPORT-001: Probing ports unapproved by policy triggers unexplained evidence penalty', () => {
  const unapprovedPortDetection = {
    rule_id: RuleId.PORT_SCAN,
    rule_name: 'Vertical Port Scan Detection',
    source_ip: '10.0.50.5', // Nessus scanner (authorized ports: standard admin/web)
    target_ips: ['10.0.0.15'],
    observed_ports: [80, 443, 31337, 4444], // 31337 and 4444 are unauthorized
    start_time: '2026-10-15T03:00:00Z', // in scheduled window
    raw_score: 75,
    evidence_records: ['rec_u1', 'rec_u2']
  };

  const result = applyContextToDetection(unapprovedPortDetection, config);
  assert.ok(result.unexplained_evidence.length > 0, 'Must record unauthorized ports');
  const portEvidence = result.unexplained_evidence.find(u => u.type === 'UNAUTHORIZED_SCAN_PORTS');
  assert.ok(portEvidence, 'Must specifically flag UNAUTHORIZED_SCAN_PORTS');
  assert.deepEqual(portEvidence.ports, [31337, 4444]);
  assert.equal(result.context_status, 'REVIEW_REQUIRED_DEVIATION');
  assert.ok(result.adjusted_score >= 35, 'Score should reflect penalty for unapproved ports');
});

/**
 * TC-DET-PORTSCAN-001: Port Scans
 * Feature: Vertical Port Scan Rule (RULE-PORT-SCAN-001)
 * Preconditions: Source connects to >= 8 distinct ports within 60s window.
 * Expected: Trigger port scan rule with distinct port count, observed ports, and explanation.
 */
test('TC-DET-PORTSCAN-001: Single host connecting to >= 8 distinct ports triggers Vertical Port Scan rule', () => {
  const records = [];
  const baseEpoch = 1760500000000;
  const scannedPorts = [21, 22, 23, 25, 80, 110, 135, 443, 445, 1433, 3389]; // 11 distinct ports

  for (let i = 0; i < scannedPorts.length; i++) {
    records.push(createFlowRecord({
      record_id: `ps_${i}`,
      timestamp: new Date(baseEpoch + i * 1000).toISOString(),
      src_ip: '192.168.1.199',
      dst_ip: '10.0.1.10',
      dst_port: scannedPorts[i],
      protocol: 'TCP'
    }));
  }

  const detections = detectPortScans(records, config);
  assert.equal(detections.length, 1);
  assert.equal(detections[0].rule_id, RuleId.PORT_SCAN);
  assert.equal(detections[0].source_ip, '192.168.1.199');
  assert.equal(detections[0].distinct_count, 11);
  assert.deepEqual(detections[0].observed_ports, scannedPorts.sort((a, b) => a - b));
  assert.ok(detections[0].raw_score >= 35);
});

/**
 * TC-DET-NETSWEEP-001: Network Sweeps
 * Feature: Horizontal Network Sweep Rule (RULE-NET-SWEEP-001)
 * Preconditions: Source connects to >= 6 distinct hosts on same port within 60s window.
 * Expected: Trigger sweep rule with distinct host count and target host list.
 */
test('TC-DET-NETSWEEP-001: Single host connecting to >= 6 distinct hosts triggers Horizontal Network Sweep rule', () => {
  const records = [];
  const baseEpoch = 1760500000000;

  for (let i = 1; i <= 8; i++) {
    records.push(createFlowRecord({
      record_id: `ns_${i}`,
      timestamp: new Date(baseEpoch + i * 2000).toISOString(),
      src_ip: '192.168.1.200',
      dst_ip: `10.0.2.${i}`,
      dst_port: 445,
      protocol: 'TCP'
    }));
  }

  const detections = detectNetworkSweeps(records, config);
  assert.equal(detections.length, 1);
  assert.equal(detections[0].rule_id, RuleId.NETWORK_SWEEP);
  assert.equal(detections[0].source_ip, '192.168.1.200');
  assert.equal(detections[0].distinct_count, 8);
  assert.ok(detections[0].targeted_ports.includes(445));
});

/**
 * TC-DET-BEACON-001: Beaconing
 * Feature: Candidate C2 Beaconing Detector
 * Preconditions: Repeated connections to external IP with CV <= 0.20 and regular intervals.
 * Expected: Flag SUSPICIOUS_C2_BEACONING with interval timing and jitter CV.
 */
test('TC-DET-BEACON-001: Repeated outbound connections with low jitter CV <= 0.20 identified as C2 beaconing', () => {
  const records = [];
  const baseEpoch = 1760500000000;

  // 10 connections every 30 seconds with ±0.5s jitter
  for (let i = 0; i < 10; i++) {
    const jitterMs = (i % 2 === 0 ? 500 : -500);
    records.push(createFlowRecord({
      record_id: `bcn_${i}`,
      timestamp: new Date(baseEpoch + i * 30000 + jitterMs).toISOString(),
      src_ip: '10.0.1.75',
      dst_ip: '203.0.113.88',
      dst_port: 443,
      protocol: 'TCP',
      total_bytes: 350
    }));
  }

  const findings = detectBeaconing(records, config);
  const beacon = findings.find(f => f.destination_ip === '203.0.113.88');
  assert.ok(beacon);
  assert.equal(beacon.is_suspicious, true);
  assert.equal(beacon.verdict, 'SUSPICIOUS_C2_BEACONING');
  assert.ok(beacon.metrics.coefficient_of_variation <= 0.20);
  assert.ok(Math.abs(beacon.metrics.mean_interval_seconds - 30) <= 1);
});

/**
 * TC-DET-EXFIL-001: Possible Data Exfiltration
 * Feature: Attack Stage Hypothesis & Outbound Volume Inspection
 * Preconditions: High outbound byte transfer (>500KB) to external destination.
 * Expected: Assigns Unusual Outbound Transfer hypothesis with explicit analytical disclaimer.
 */
test('TC-DET-EXFIL-001: Large outbound data transfer to external destination flagged as Unusual Outbound Transfer hypothesis', () => {
  const incident = {
    incident_id: 'INC-EXFIL-001',
    source_entity: '10.0.1.90',
    record_ids: ['exfil_flow_1']
  };

  const records = [
    createFlowRecord({
      record_id: 'exfil_flow_1',
      timestamp: '2026-10-15T04:30:00Z',
      src_ip: '10.0.1.90',
      dst_ip: '198.51.100.55', // external
      dst_port: 443,
      protocol: 'TCP',
      bytes_out: 1200000, // 1.2 MB
      bytes_in: 500,
      total_bytes: 1200500
    })
  ];

  const timeline = buildIncidentTimeline(incident, records, [], []);
  assert.equal(timeline.length, 1);
  assert.equal(timeline[0].stage_hypothesis, AttackStage.UNUSUAL_OUTBOUND);
  assert.ok(timeline[0].stage_reason.includes('Substantial outbound payload'));
  assert.ok(timeline[0].hypothesis_disclaimer.includes('Investigation hypothesis'));
});

/**
 * TC-DET-LATERAL-001: Lateral Movement
 * Feature: Spreading & Lateral Movement Rule (RULE-LAT-MOVE-001)
 * Preconditions: Host fans out to >= 3 internal hosts on administrative ports.
 * Expected: Flag lateral movement with target list, admin ports, and ingress correlation if present.
 */
test('TC-DET-LATERAL-001: Fan-out across administrative ports (SMB/RDP/SSH) triggers Lateral Movement rule', () => {
  const records = [
    // Preceding ingress vector
    createFlowRecord({
      record_id: 'lat_in',
      timestamp: '2026-10-15T02:00:00Z',
      src_ip: '192.168.1.10',
      dst_ip: '10.0.1.30',
      dst_port: 445,
      protocol: 'TCP'
    }),
    // Outbound fan-out on admin ports
    createFlowRecord({
      record_id: 'lat_out_1',
      timestamp: '2026-10-15T02:02:00Z',
      src_ip: '10.0.1.30',
      dst_ip: '10.0.1.31',
      dst_port: 445,
      protocol: 'TCP'
    }),
    createFlowRecord({
      record_id: 'lat_out_2',
      timestamp: '2026-10-15T02:02:15Z',
      src_ip: '10.0.1.30',
      dst_ip: '10.0.1.32',
      dst_port: 3389,
      protocol: 'TCP'
    }),
    createFlowRecord({
      record_id: 'lat_out_3',
      timestamp: '2026-10-15T02:02:30Z',
      src_ip: '10.0.1.30',
      dst_ip: '10.0.1.33',
      dst_port: 22,
      protocol: 'TCP'
    })
  ];

  const detections = detectLateralMovement(records, config);
  assert.equal(detections.length, 1);
  assert.equal(detections[0].rule_id, RuleId.LATERAL_MOVEMENT);
  assert.equal(detections[0].pivot_host, '10.0.1.30');
  assert.equal(detections[0].distinct_count, 3);
  assert.equal(detections[0].has_ingress_vector, true);
  assert.equal(detections[0].ingress_source, '192.168.1.10');
  assert.ok(detections[0].raw_score >= 70);
});

/**
 * TC-DET-NEWDEST-001: New External Destinations
 * Feature: Host Baseline External Destination Tracking & Gap Disclosure
 * Preconditions: Baseline records established; new flow connects to unseen external IP.
 * Expected: Baseline tracks typical destinations; verifies absence of standalone new-dest detector rule honestly.
 */
test('TC-DET-NEWDEST-001: Host baseline tracks typical destinations and honestly records absence of standalone rule', () => {
  const baseRecords = [];
  const baseEpoch = Date.now() - 360000;

  for (let i = 0; i < 6; i++) {
    baseRecords.push(createFlowRecord({
      record_id: `nd_base_${i}`,
      timestamp: new Date(baseEpoch + i * 30000).toISOString(),
      src_ip: '10.0.1.88',
      dst_ip: '10.0.0.10', // known internal DC
      dst_port: 53,
      protocol: 'UDP',
      total_bytes: 100
    }));
  }

  const baselines = calculateHostBaselines(baseRecords, config);
  const bm = baselines.get('10.0.1.88');
  assert.ok(bm && bm.has_sufficient_history);
  assert.ok(bm.metrics.typical_destinations.includes('10.0.0.10'));

  // Evaluate new external destination
  const newDestFlow = [
    createFlowRecord({
      record_id: 'nd_new_1',
      timestamp: new Date().toISOString(),
      src_ip: '10.0.1.88',
      dst_ip: '198.51.100.200', // unseen external
      dst_port: 8080,
      protocol: 'TCP',
      total_bytes: 150
    })
  ];

  // Deviation engine observes unique destination count deviation
  const evalResult = evaluateHostTrafficDeviation('10.0.1.88', newDestFlow, baselines, config);
  assert.ok(evalResult.deviations.find(d => d.metric === 'Unique Destinations'));

  // Documented limitation: Standalone "New External Destination" alert rule is not implemented in detectionRules.js
  const allDetections = runAllDetectionRules(newDestFlow, config);
  assert.equal(allDetections.length, 0, 'Documented limitation: Standalone new external destination alert is not an active detection rule');
});
