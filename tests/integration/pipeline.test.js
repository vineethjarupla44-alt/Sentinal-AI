import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { SentinelPipeline } from '../../backend/app/pipeline.js';
import { evaluateDetectionPerformance } from '../../backend/app/evaluation.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function getPath(rel) {
  const c1 = path.resolve(rel);
  const c2 = path.resolve(__dirname, '..', '..', rel);
  return fs.existsSync(c1) ? c1 : c2;
}

test('Integration Pipeline: Processes Schema 1 (Zeek) and verifies replay + metrics', () => {
  const pipeline = new SentinelPipeline();
  const zeekPath = getPath('datasets/synthetic/zeek_sample_annotated.csv');
  const result = pipeline.processFile(zeekPath);

  assert.ok(result.record_count > 0);
  assert.ok(result.incidents.length > 0);
  assert.ok(result.context_replays.length > 0);

  // Validate Adaptive Context Replay for approved scanner
  const scannerReplay = result.context_replays.find(r => r.source_entity === '10.0.50.5');
  assert.ok(scannerReplay, 'Should produce replay for 10.0.50.5');
  assert.ok(scannerReplay.delta_analysis.rule_deltas.length > 0);
  assert.ok(scannerReplay.delta_analysis.rule_deltas[0].score_reduction > 0);

  // Evaluate performance metrics
  const evalMetrics = evaluateDetectionPerformance(result);
  assert.equal(evalMetrics.context_aware_stage.recall, 1, 'Recall must remain 100%');
  assert.ok(evalMetrics.improvement.fp_reduction_percent >= 50, 'FP reduction must be >= 50%');
});

test('Integration Pipeline: Processes Schema 2 (Firewall/VPC) through the same engine', () => {
  const pipeline = new SentinelPipeline();
  const fwPath = getPath('datasets/synthetic/firewall_sample_annotated.csv');
  const result = pipeline.processFile(fwPath);

  assert.ok(result.record_count > 0);
  assert.ok(result.incidents.length > 0);

  const evalMetrics = evaluateDetectionPerformance(result);
  assert.equal(evalMetrics.context_aware_stage.recall, 1);
  assert.ok(evalMetrics.improvement.fp_reduction_percent >= 70);
});
