import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { applyContextToDetection, isWithinSchedule } from '../../backend/app/trustedActivity.js';
import { RuleId, MitigationTag } from '../../backend/app/types.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function getPath(rel) {
  const c1 = path.resolve(rel);
  const c2 = path.resolve(__dirname, '..', '..', rel);
  return fs.existsSync(c1) ? c1 : c2;
}

const config = JSON.parse(fs.readFileSync(getPath('config/config.json'), 'utf8'));

test('Context Engine: Schedule checker handles normal and overnight windows', () => {
  const schedule = { start_hour: 2, end_hour: 6 };
  assert.equal(isWithinSchedule('2026-10-15T03:00:00Z', schedule), true);
  assert.equal(isWithinSchedule('2026-10-15T08:00:00Z', schedule), false);

  const overnight = { start_hour: 22, end_hour: 4 };
  assert.equal(isWithinSchedule('2026-10-15T23:30:00Z', overnight), true);
  assert.equal(isWithinSchedule('2026-10-15T02:30:00Z', overnight), true);
  assert.equal(isWithinSchedule('2026-10-15T12:00:00Z', overnight), false);
});

test('Context Engine: Mitigates approved security scanner within authorized window', () => {
  const scannerDetection = {
    rule_id: RuleId.PORT_SCAN,
    rule_name: 'Vertical Port Scan Detection',
    source_ip: '10.0.50.5',
    target_ips: ['10.0.0.15'],
    observed_ports: [21, 22, 80, 443, 135, 139, 445, 1433, 3306, 3389],
    start_time: '2026-10-15T03:00:00Z',
    end_time: '2026-10-15T03:00:10Z',
    raw_score: 75,
    evidence_records: ['rec1', 'rec2']
  };

  const result = applyContextToDetection(scannerDetection, config);
  assert.ok(result.adjusted_score < 30, `Adjusted score (${result.adjusted_score}) should be deprioritized`);
  assert.equal(result.context_status, 'DEPRIORITIZED_BENIGN_LOOKALIKE');
  assert.equal(result.context_mitigations[0].tag, MitigationTag.AUTH_SEC_SCANNER);
  assert.equal(result.unexplained_evidence.length, 0);
});

test('Context Engine: Retains high score and flags unexplained evidence if scanner probes unauthorized port or runs off-hours', () => {
  const anomalousScannerDetection = {
    rule_id: RuleId.PORT_SCAN,
    rule_name: 'Vertical Port Scan Detection',
    source_ip: '10.0.50.5',
    target_ips: ['10.0.0.15'],
    observed_ports: [80, 443, 31337],
    start_time: '2026-10-15T14:00:00Z',
    raw_score: 75,
    evidence_records: ['rec1', 'rec2']
  };

  const result = applyContextToDetection(anomalousScannerDetection, config);
  assert.ok(result.adjusted_score >= 50, 'Score should remain high due to off-schedule and unapproved port');
  assert.ok(result.unexplained_evidence.length >= 2, 'Should flag both unauthorized port and off-hours activity');
  assert.notEqual(result.context_status, 'DEPRIORITIZED_BENIGN_LOOKALIKE');
});

test('Context Engine: Deprioritizes authorized patch distribution during rollout', () => {
  const patchDetection = {
    rule_id: RuleId.NETWORK_SWEEP,
    rule_name: 'Horizontal Network Sweep Detection',
    source_ip: '10.0.10.20',
    observed_hosts: ['10.0.1.101', '10.0.1.102', '10.0.1.103', '10.0.1.104'],
    targeted_ports: [8530],
    start_time: '2026-10-15T03:00:00Z',
    end_time: '2026-10-15T03:00:30Z',
    raw_score: 65,
    evidence_records: ['p1', 'p2']
  };

  const result = applyContextToDetection(patchDetection, config);
  assert.ok(result.adjusted_score < 30);
  assert.equal(result.context_mitigations[0].tag, MitigationTag.AUTH_PATCH_DISTRIBUTION);
});
