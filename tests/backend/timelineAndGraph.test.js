import test from 'node:test';
import assert from 'node:assert/strict';
import { buildIncidentTimeline, AttackStage } from '../../backend/app/timelineEngine.js';
import { buildIncidentCommunicationGraph } from '../../backend/app/graphEngine.js';
import { createFlowRecord } from '../../backend/app/types.js';

test('Timeline Engine: Orders events chronologically and assigns attack-stage hypotheses', () => {
  const incident = {
    incident_id: 'INC-TEST-001',
    source_entity: '10.0.1.77',
    record_ids: ['f1', 'f2', 'f3']
  };

  const records = [
    createFlowRecord({
      record_id: 'f1',
      timestamp: '2026-10-15T02:45:00Z',
      src_ip: '10.0.1.77',
      dst_ip: '10.0.1.1',
      dst_port: 445,
      protocol: 'TCP'
    }),
    createFlowRecord({
      record_id: 'f2',
      timestamp: '2026-10-15T02:45:05Z',
      src_ip: '10.0.1.77',
      dst_ip: '10.0.1.2',
      dst_port: 445,
      protocol: 'TCP'
    }),
    createFlowRecord({
      record_id: 'f3',
      timestamp: '2026-10-15T02:45:10Z',
      src_ip: '10.0.1.77',
      dst_ip: '10.0.1.3',
      dst_port: 445,
      protocol: 'TCP'
    })
  ];

  const mockDetections = [
    {
      rule_id: 'RULE-NET-SWEEP-002',
      source_ip: '10.0.1.77',
      evidence_records: ['f1', 'f2', 'f3']
    }
  ];

  const timeline = buildIncidentTimeline(incident, records, mockDetections, []);
  assert.equal(timeline.length, 3);
  assert.equal(timeline[0].record_id, 'f1');
  assert.equal(timeline[1].record_id, 'f2');
  assert.equal(timeline[2].record_id, 'f3');
  assert.equal(timeline[0].stage_hypothesis, AttackStage.RECONNAISSANCE);
  assert.ok(timeline[0].hypothesis_disclaimer.includes('Investigation hypothesis'));
});

test('Communication Graph: Builds node-link topology with directed edges and suspicious highlights', () => {
  const incident = {
    incident_id: 'INC-TEST-002',
    source_entity: '10.0.1.20',
    record_ids: ['f_lat_1', 'f_lat_2'],
    distinct_rules_triggered: ['RULE-LAT-MOVE-003'],
    context_summary: { is_benign_lookalike: false }
  };

  const records = [
    createFlowRecord({
      record_id: 'f_lat_1',
      timestamp: '2026-10-15T03:15:00Z',
      src_ip: '10.0.1.20',
      dst_ip: '10.0.1.21',
      dst_port: 3389,
      protocol: 'TCP',
      total_bytes: 28000
    }),
    createFlowRecord({
      record_id: 'f_lat_2',
      timestamp: '2026-10-15T03:15:30Z',
      src_ip: '10.0.1.20',
      dst_ip: '10.0.1.22',
      dst_port: 445,
      protocol: 'TCP',
      total_bytes: 18000
    })
  ];

  const graph = buildIncidentCommunicationGraph(incident, records, [], {});
  assert.ok(graph.nodes.length >= 3, 'Should have source and 2 targets');
  assert.ok(graph.edges.length >= 2, 'Should have 2 communication edges');

  const srcNode = graph.nodes.find(n => n.id === '10.0.1.20');
  assert.ok(srcNode);
  assert.equal(srcNode.is_source, true);

  const edge1 = graph.edges.find(e => e.source === '10.0.1.20' && e.target === '10.0.1.21');
  assert.ok(edge1);
  assert.equal(edge1.is_suspicious, true);
  assert.ok(edge1.weight >= 1.5);
  assert.deepEqual(edge1.ports, [3389]);
});
