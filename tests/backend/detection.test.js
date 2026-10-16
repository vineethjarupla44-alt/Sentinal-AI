import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { normalizeCSV } from '../../backend/app/dataLoader.js';
import { detectPortScans, detectNetworkSweeps, detectLateralMovement, runAllDetectionRules } from '../../backend/app/detectionRules.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function getPath(rel) {
  const c1 = path.resolve(rel);
  const c2 = path.resolve(__dirname, '..', '..', rel);
  return fs.existsSync(c1) ? c1 : c2;
}

const config = JSON.parse(fs.readFileSync(getPath('config/config.json'), 'utf8'));
const schemaConfigs = JSON.parse(fs.readFileSync(getPath('config/dataset_mapping.json'), 'utf8'));

test('Detection: Detects vertical port scans exceeding port threshold', () => {
  const zeekCsv = fs.readFileSync(getPath('datasets/synthetic/zeek_sample_annotated.csv'), 'utf8');
  const { records } = normalizeCSV(zeekCsv, schemaConfigs);

  const portScans = detectPortScans(records, config);
  assert.ok(portScans.length > 0, 'Port scans should be detected');

  const attackerScan = portScans.find(s => s.source_ip === '192.168.1.105');
  assert.ok(attackerScan, 'Attacker 192.168.1.105 should trigger vertical port scan');
  assert.ok(attackerScan.distinct_count >= 10, 'Should observe distinct ports >= 10');
  assert.ok(attackerScan.raw_score >= 50, 'Severity score should be elevated');
});

test('Detection: Detects horizontal network sweeps across multiple targets', () => {
  const zeekCsv = fs.readFileSync(getPath('datasets/synthetic/zeek_sample_annotated.csv'), 'utf8');
  const { records } = normalizeCSV(zeekCsv, schemaConfigs);

  const sweeps = detectNetworkSweeps(records, config);
  assert.ok(sweeps.length > 0, 'Network sweeps should be detected');

  const infectedSweep = sweeps.find(s => s.source_ip === '10.0.1.77');
  assert.ok(infectedSweep, 'Host 10.0.1.77 should trigger horizontal sweep');
  assert.ok(infectedSweep.distinct_count >= 6, 'Should observe at least 6 target hosts');
  assert.ok(infectedSweep.targeted_ports.includes(445), 'Targeted port should include 445');
});

test('Detection: Detects lateral movement and spreading across administrative ports', () => {
  const zeekCsv = fs.readFileSync(getPath('datasets/synthetic/zeek_sample_annotated.csv'), 'utf8');
  const { records } = normalizeCSV(zeekCsv, schemaConfigs);

  const lateral = detectLateralMovement(records, config);
  assert.ok(lateral.length > 0, 'Lateral movement should be detected');

  const pivotDet = lateral.find(l => l.pivot_host === '10.0.1.20');
  assert.ok(pivotDet, 'Pivot host 10.0.1.20 should be flagged');
  assert.ok(pivotDet.distinct_count >= 3, 'Should fan out to >= 3 targets');
  assert.ok(pivotDet.has_ingress_vector, 'Should correlate preceding ingress connection from 192.168.1.50');
});

test('Detection: Low-volume benign traffic does not trigger false alerts', () => {
  const benignRecords = [
    { record_id: 'b1', timestamp: '2026-10-15T02:00:00Z', epoch_ms: 1000, src_ip: '10.0.0.9', dst_ip: '10.0.0.10', dst_port: 53, protocol: 'UDP' },
    { record_id: 'b2', timestamp: '2026-10-15T02:00:05Z', epoch_ms: 6000, src_ip: '10.0.0.9', dst_ip: '10.0.0.5', dst_port: 123, protocol: 'UDP' },
    { record_id: 'b3', timestamp: '2026-10-15T02:00:10Z', epoch_ms: 11000, src_ip: '10.0.0.9', dst_ip: '142.250.190.46', dst_port: 443, protocol: 'TCP' }
  ];

  const detections = runAllDetectionRules(benignRecords, config);
  assert.equal(detections.length, 0, 'Normal benign web/DNS/NTP should not trigger any rule');
});
