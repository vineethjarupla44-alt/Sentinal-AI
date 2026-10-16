import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { calculateHostBaselines, evaluateHostTrafficDeviation } from '../../backend/app/hostBaseline.js';
import { detectBeaconing } from '../../backend/app/beaconingDetector.js';
import { buildIncidentTimeline, AttackStage } from '../../backend/app/timelineEngine.js';
import { buildIncidentCommunicationGraph } from '../../backend/app/graphEngine.js';
import { createFlowRecord } from '../../backend/app/types.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function getPath(rel) {
  const c1 = path.resolve(rel);
  const c2 = path.resolve(__dirname, '..', '..', rel);
  return fs.existsSync(c1) ? c1 : c2;
}

const config = JSON.parse(fs.readFileSync(getPath('config/config.json'), 'utf8'));

/**
 * TC-VIS-BASELINE-001: Traffic Deviation Data Structure & Empty State
 * Feature: Baseline Visualization Feed
 * Expected: Computes Z-scores, expected vs observed, and provides clean empty state when no history exists.
 */
test('TC-VIS-BASELINE-001: Generates accurate statistical deviation metrics and handles empty state gracefully', () => {
  // Empty state test
  const emptyResult = evaluateHostTrafficDeviation('10.0.99.99', [], new Map(), config);
  assert.equal(emptyResult.status, 'INSUFFICIENT_HISTORY');
  assert.equal(emptyResult.has_anomaly, false);
  assert.ok(emptyResult.explanation.includes('No historical baseline'));

  // Active deviation test
  const baselineRecords = [];
  const baseEpoch = Date.now() - 360000;
  for (let i = 0; i < 10; i++) {
    baselineRecords.push(createFlowRecord({
      record_id: `b_vis_${i}`,
      timestamp: new Date(baseEpoch + i * 15000).toISOString(),
      src_ip: '10.0.1.10',
      dst_ip: '10.0.0.1',
      dst_port: 80,
      protocol: 'TCP',
      total_bytes: 1000
    }));
  }

  const baselines = calculateHostBaselines(baselineRecords, config);
  const observedFlows = [
    createFlowRecord({
      record_id: 'obs_1',
      timestamp: new Date().toISOString(),
      src_ip: '10.0.1.10',
      dst_ip: '10.0.0.1',
      dst_port: 80,
      protocol: 'TCP',
      total_bytes: 50000
    })
  ];

  const evalResult = evaluateHostTrafficDeviation('10.0.1.10', observedFlows, baselines, config);
  assert.ok(evalResult.deviations.length === 4);
  const byteDev = evalResult.deviations.find(d => d.metric === 'Byte Volume');
  assert.equal(byteDev.observed, 50000);
  assert.equal(byteDev.expected, 3333.33);
  assert.ok(byteDev.is_anomalous);
});

/**
 * TC-VIS-BEACON-001: Beaconing Interval Pulse Visualization Data
 * Feature: Inter-arrival Time Series Generation
 * Expected: Ordered timestamps, delta gaps delta t match source intervals, CV and summaries computed.
 */
test('TC-VIS-BEACON-001: Computes accurate inter-arrival time gaps and jitter metrics for interval visualization', () => {
  const records = [];
  const baseEpoch = 1760500000000;
  const gaps = [30, 30, 31, 29, 30]; // ~30 second gaps

  let curr = baseEpoch;
  records.push(createFlowRecord({
    record_id: 'bcn_vis_0',
    timestamp: new Date(curr).toISOString(),
    src_ip: '10.0.1.80',
    dst_ip: '198.51.100.10',
    dst_port: 443,
    protocol: 'TCP'
  }));

  for (let i = 0; i < gaps.length; i++) {
    curr += gaps[i] * 1000;
    records.push(createFlowRecord({
      record_id: `bcn_vis_${i + 1}`,
      timestamp: new Date(curr).toISOString(),
      src_ip: '10.0.1.80',
      dst_ip: '198.51.100.10',
      dst_port: 443,
      protocol: 'TCP'
    }));
  }

  const findings = detectBeaconing(records, config);
  const finding = findings.find(f => f.destination_ip === '198.51.100.10');

  assert.ok(finding);
  assert.equal(finding.intervals.length, gaps.length);
  // Verify delta t values match source intervals
  for (let i = 0; i < gaps.length; i++) {
    assert.equal(finding.intervals[i], gaps[i]);
  }
  assert.ok(Math.abs(finding.metrics.mean_interval_seconds - 30) <= 0.5);
  assert.ok(finding.metrics.coefficient_of_variation < 0.10);
});

/**
 * TC-VIS-TIMELINE-001: Chronological Incident Timeline
 * Feature: Chronological Event Milestones & Stage Hypotheses
 * Expected: Strict ascending time order, appropriate attack stage hypothesis, and mandatory disclaimer.
 */
test('TC-VIS-TIMELINE-001: Sequences incident flows chronologically and assigns evidence-backed attack-stage hypotheses', () => {
  const incident = {
    incident_id: 'INC-VIS-001',
    source_entity: '10.0.1.77',
    record_ids: ['t_flow_3', 't_flow_1', 't_flow_2']
  };

  // Provide out-of-order flows to verify sorting
  const records = [
    createFlowRecord({
      record_id: 't_flow_3',
      timestamp: '2026-10-15T02:00:30Z',
      src_ip: '10.0.1.77',
      dst_ip: '10.0.1.3',
      dst_port: 445,
      protocol: 'TCP'
    }),
    createFlowRecord({
      record_id: 't_flow_1',
      timestamp: '2026-10-15T02:00:10Z',
      src_ip: '10.0.1.77',
      dst_ip: '10.0.1.1',
      dst_port: 445,
      protocol: 'TCP'
    }),
    createFlowRecord({
      record_id: 't_flow_2',
      timestamp: '2026-10-15T02:00:20Z',
      src_ip: '10.0.1.77',
      dst_ip: '10.0.1.2',
      dst_port: 445,
      protocol: 'TCP'
    })
  ];

  const detections = [
    {
      rule_id: 'RULE-NET-SWEEP-001',
      source_ip: '10.0.1.77',
      evidence_records: ['t_flow_1', 't_flow_2', 't_flow_3']
    }
  ];

  const timeline = buildIncidentTimeline(incident, records, detections, []);
  assert.equal(timeline.length, 3);
  // Must be sorted chronologically
  assert.equal(timeline[0].record_id, 't_flow_1');
  assert.equal(timeline[1].record_id, 't_flow_2');
  assert.equal(timeline[2].record_id, 't_flow_3');

  // Verify Reconnaissance hypothesis and disclaimer
  assert.equal(timeline[0].stage_hypothesis, AttackStage.RECONNAISSANCE);
  assert.ok(timeline[0].hypothesis_disclaimer.includes('Investigation hypothesis'));
});

/**
 * TC-VIS-GRAPH-001: Directed Network Communication Graph
 * Feature: Communication Topology Construction
 * Expected: Nodes correspond to actual hosts, edges match communications, stroke weight is scaled, zero fabricated hosts.
 */
test('TC-VIS-GRAPH-001: Builds directed topology graph with accurate host nodes, flow counts, and edge weights', () => {
  const incident = {
    incident_id: 'INC-VIS-002',
    source_entity: '10.0.1.20',
    record_ids: ['g_f1', 'g_f2'],
    distinct_rules_triggered: ['RULE-LAT-MOVE-001'],
    context_summary: { is_benign_lookalike: false }
  };

  const records = [
    createFlowRecord({
      record_id: 'g_f1',
      timestamp: '2026-10-15T03:00:00Z',
      src_ip: '10.0.1.20',
      dst_ip: '10.0.1.25',
      dst_port: 3389,
      protocol: 'TCP',
      total_bytes: 15000
    }),
    createFlowRecord({
      record_id: 'g_f2',
      timestamp: '2026-10-15T03:00:10Z',
      src_ip: '10.0.1.20',
      dst_ip: '10.0.0.10', // DC in trusted_activity
      dst_port: 445,
      protocol: 'TCP',
      total_bytes: 35000
    })
  ];

  const graph = buildIncidentCommunicationGraph(incident, records, [], config);

  // Nodes check: exactly 1 source + 2 targets = 3 nodes
  assert.equal(graph.nodes.length, 3);
  const srcNode = graph.nodes.find(n => n.id === '10.0.1.20');
  const dcNode = graph.nodes.find(n => n.id === '10.0.0.10');
  const tgtNode = graph.nodes.find(n => n.id === '10.0.1.25');

  assert.ok(srcNode && srcNode.is_source);
  assert.ok(dcNode && dcNode.role === 'DOMAIN_CONTROLLER_CRITICAL');
  assert.ok(tgtNode && tgtNode.role === 'INTERNAL_TARGET');

  // Edges check: exactly 2 edges
  assert.equal(graph.edges.length, 2);
  const edgeToDc = graph.edges.find(e => e.target === '10.0.0.10');
  assert.ok(edgeToDc);
  assert.equal(edgeToDc.is_suspicious, true);
  assert.ok(edgeToDc.weight >= 1.5 && edgeToDc.weight <= 7.0);
  assert.deepEqual(edgeToDc.ports, [445]);
});
