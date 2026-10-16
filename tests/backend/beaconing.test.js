import test from 'node:test';
import assert from 'node:assert/strict';
import { detectBeaconing } from '../../backend/app/beaconingDetector.js';
import { createFlowRecord } from '../../backend/app/types.js';

test('Beaconing Detector: Identifies automated periodic C2 beaconing with low jitter', () => {
  const records = [];
  const baseTime = 1760500000000;
  const targetIp = '198.51.100.45';

  // 8 connections occurring precisely every 60 seconds with tiny 1-second jitter
  const jitters = [0, 1, -1, 0, 1, 0, -1, 1];
  for (let i = 0; i < 8; i++) {
    const epoch = baseTime + (i * 60000) + (jitters[i] * 1000);
    records.push(createFlowRecord({
      record_id: `beacon_${i}`,
      timestamp: new Date(epoch).toISOString(),
      src_ip: '10.0.1.80',
      dst_ip: targetIp,
      dst_port: 8443,
      protocol: 'TCP',
      total_bytes: 450
    }));
  }

  const findings = detectBeaconing(records, {});
  const c2Finding = findings.find(f => f.destination_ip === targetIp);

  assert.ok(c2Finding, 'Should detect candidate beaconing channel');
  assert.equal(c2Finding.is_suspicious, true);
  assert.equal(c2Finding.verdict, 'SUSPICIOUS_C2_BEACONING');
  assert.equal(c2Finding.repetition_count, 8);
  assert.ok(Math.abs(c2Finding.metrics.mean_interval_seconds - 60) <= 2);
  assert.ok(c2Finding.metrics.coefficient_of_variation <= 0.20, 'CV must be low (< 0.20) for periodic beacon');
});

test('Beaconing Detector: Classifies irregular repeated connections as non-malicious', () => {
  const records = [];
  const baseTime = 1760500000000;
  // Highly variable intervals: 10s, 120s, 15s, 300s, 45s, 180s
  const intervalsSec = [10, 120, 15, 300, 45, 180];
  let currTime = baseTime;

  for (let i = 0; i < intervalsSec.length; i++) {
    records.push(createFlowRecord({
      record_id: `browsing_${i}`,
      timestamp: new Date(currTime).toISOString(),
      src_ip: '10.0.1.80',
      dst_ip: '142.250.190.46',
      dst_port: 443,
      protocol: 'TCP',
      total_bytes: 12000
    }));
    currTime += intervalsSec[i] * 1000;
  }

  const findings = detectBeaconing(records, {});
  const webFinding = findings.find(f => f.destination_ip === '142.250.190.46');

  assert.ok(webFinding);
  assert.equal(webFinding.is_suspicious, false);
  assert.equal(webFinding.verdict, 'IRREGULAR_TRAFFIC');
  assert.ok(webFinding.metrics.coefficient_of_variation > 0.40, 'Irregular traffic must have high CV');
});

test('Beaconing Detector: Excludes legitimate NTP and trusted monitoring services', () => {
  const config = {
    trusted_activity: [
      { ip: '10.0.0.5', hostname: 'ntp-internal.corp.internal', role: 'NTP Time Server' }
    ]
  };

  const records = [];
  const baseTime = 1760500000000;

  // Regular NTP poll every 30 seconds
  for (let i = 0; i < 6; i++) {
    records.push(createFlowRecord({
      record_id: `ntp_${i}`,
      timestamp: new Date(baseTime + i * 30000).toISOString(),
      src_ip: '10.0.1.12',
      dst_ip: '10.0.0.5',
      dst_port: 123,
      protocol: 'UDP',
      total_bytes: 96
    }));
  }

  const findings = detectBeaconing(records, config);
  const ntpFinding = findings.find(f => f.destination_ip === '10.0.0.5');

  assert.ok(ntpFinding);
  assert.equal(ntpFinding.is_suspicious, false);
  assert.equal(ntpFinding.verdict, 'LEGITIMATE_NTP_SYNC');
  assert.ok(ntpFinding.rationale.includes('RFC 5905'));
});
