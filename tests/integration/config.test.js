import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { TraceGuardPipeline } from '../../backend/app/pipeline.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function getPath(rel) {
  const c1 = path.resolve(rel);
  const c2 = path.resolve(__dirname, '..', '..', rel);
  return fs.existsSync(c1) ? c1 : c2;
}

test('Configuration Dynamics: Changing detection thresholds dynamically updates rule triggers', () => {
  const basePipeline = new TraceGuardPipeline();
  const zeekPath = getPath('datasets/synthetic/zeek_sample_annotated.csv');
  const initialResult = basePipeline.processFile(zeekPath);

  const initialPortScans = initialResult.raw_detections.filter(d => d.rule_id === 'RULE-PORT-SCAN-001');
  assert.ok(initialPortScans.length >= 2, 'Initially should detect at least 2 port scans (min 8 ports)');

  // Raise threshold to 25 ports dynamically
  const modifiedConfig = JSON.parse(JSON.stringify(basePipeline.config));
  modifiedConfig.detection_thresholds.port_scan.min_distinct_ports = 25;

  const dynamicPipeline = new TraceGuardPipeline(modifiedConfig);
  const updatedResult = dynamicPipeline.processFile(zeekPath);
  const updatedPortScans = updatedResult.raw_detections.filter(d => d.rule_id === 'RULE-PORT-SCAN-001');

  assert.equal(updatedPortScans.length, 0, 'No port scans should trigger with threshold raised to 25');
});

test('Configuration Dynamics: Adding a new approved scanner dynamically shifts incident status', () => {
  const basePipeline = new TraceGuardPipeline();
  const zeekPath = getPath('datasets/synthetic/zeek_sample_annotated.csv');
  const result1 = basePipeline.processFile(zeekPath);
  const inc1 = result1.incidents.find(i => i.source_entity === '192.168.1.105');
  assert.ok(inc1.prioritization_score >= 65, 'Unapproved source should be High/Critical');

  // Dynamically approve 192.168.1.105 as an internal pen-test scanner
  const modifiedConfig = JSON.parse(JSON.stringify(basePipeline.config));
  modifiedConfig.approved_security_scanners.push({
    ip: '192.168.1.105',
    hostname: 'pentest-authorized-box',
    authorized_ports: 'ALL',
    active_schedule_utc: { start_hour: 0, end_hour: 23 },
    max_mitigation_factor: 0.80
  });

  const dynamicPipeline = new TraceGuardPipeline(modifiedConfig);
  const result2 = dynamicPipeline.processFile(zeekPath);
  const inc2 = result2.incidents.find(i => i.source_entity === '192.168.1.105');

  assert.ok(inc2.prioritization_score < 30, 'Newly approved source should be deprioritized to benign lookalike');
  assert.equal(inc2.context_summary.is_benign_lookalike, true);
});
