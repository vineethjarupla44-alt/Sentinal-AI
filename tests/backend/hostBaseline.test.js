import test from 'node:test';
import assert from 'node:assert/strict';
import { calculateHostBaselines, evaluateHostTrafficDeviation } from '../../backend/app/hostBaseline.js';
import { createFlowRecord } from '../../backend/app/types.js';

test('Host Baseline: Normal traffic establishes statistical baseline envelope', () => {
  const records = [];
  const baseTime = Date.now() - 600000;

  // Generate 10 standard web browsing flows
  for (let i = 0; i < 10; i++) {
    records.push(createFlowRecord({
      record_id: `flow_norm_${i}`,
      timestamp: new Date(baseTime + i * 15000).toISOString(),
      src_ip: '10.0.1.50',
      dst_ip: '142.250.190.46',
      dst_port: 443,
      protocol: 'TCP',
      bytes_out: 1200 + (i % 3) * 100,
      bytes_in: 4500 + (i % 3) * 200,
      total_bytes: 5700 + (i % 3) * 300
    }));
  }

  const baselines = calculateHostBaselines(records, {});
  const hostBm = baselines.get('10.0.1.50');

  assert.ok(hostBm, 'Should generate baseline for 10.0.1.50');
  assert.equal(hostBm.has_sufficient_history, true);
  assert.equal(hostBm.status, 'LEARNED_BASELINE');
  assert.ok(hostBm.metrics.byte_volume.mean > 0);
  assert.ok(hostBm.metrics.flow_count.mean > 0);
});

test('Host Baseline: Sudden traffic-volume deviation triggers anomaly finding', () => {
  const normalRecords = [];
  const baseTime = Date.now() - 600000;

  for (let i = 0; i < 10; i++) {
    normalRecords.push(createFlowRecord({
      record_id: `f_norm_${i}`,
      timestamp: new Date(baseTime + i * 20000).toISOString(),
      src_ip: '10.0.1.60',
      dst_ip: '10.0.0.10',
      dst_port: 53,
      protocol: 'UDP',
      bytes_out: 68,
      bytes_in: 140,
      total_bytes: 208
    }));
  }

  const baselines = calculateHostBaselines(normalRecords, {});

  // Observed sudden massive surge: 5,000,000 bytes and probing multiple targets
  const surgeFlows = [
    createFlowRecord({
      record_id: 'f_surge_1',
      timestamp: new Date().toISOString(),
      src_ip: '10.0.1.60',
      dst_ip: '198.51.100.99',
      dst_port: 445,
      protocol: 'TCP',
      bytes_out: 2500000,
      bytes_in: 2500000,
      total_bytes: 5000000
    })
  ];

  const evalResult = evaluateHostTrafficDeviation('10.0.1.60', surgeFlows, baselines, {});
  assert.equal(evalResult.has_anomaly, true);
  assert.equal(evalResult.status, 'DEVIATION_ALERT');
  
  const byteDev = evalResult.deviations.find(d => d.metric === 'Byte Volume');
  assert.ok(byteDev.is_anomalous);
  assert.ok(byteDev.z_score > 2.5);
  assert.ok(byteDev.deviation_percent > 200);
});

test('Host Baseline: Explicitly handles insufficient baseline history without false alarms', () => {
  const sparseRecords = [
    createFlowRecord({
      record_id: 'f_sparse_1',
      timestamp: new Date().toISOString(),
      src_ip: '10.0.1.99',
      dst_ip: '10.0.0.1',
      dst_port: 80,
      total_bytes: 500
    })
  ];

  const baselines = calculateHostBaselines(sparseRecords, {});
  const hostBm = baselines.get('10.0.1.99');

  assert.ok(hostBm);
  assert.equal(hostBm.has_sufficient_history, false);
  assert.equal(hostBm.status, 'INSUFFICIENT_HISTORY');
  assert.ok(hostBm.guidance.includes('Minimum 3 required'));

  const evalResult = evaluateHostTrafficDeviation('10.0.1.99', sparseRecords, baselines, {});
  assert.equal(evalResult.status, 'INSUFFICIENT_HISTORY');
  assert.equal(evalResult.has_anomaly, false);
});

test('Host Baseline: Scheduled nightly backups are not flagged as attack solely due to volume', () => {
  const config = {
    large_nightly_backups: [
      {
        src_ip: '10.0.20.15',
        dst_ip: '10.0.99.100',
        port: 445,
        scheduled_window_utc: { start_hour: 1, end_hour: 4 }
      }
    ]
  };

  const normalRecords = [];
  const baseTime = Date.now() - 3600000;
  for (let i = 0; i < 6; i++) {
    normalRecords.push(createFlowRecord({
      record_id: `f_b_${i}`,
      timestamp: new Date(baseTime + i * 60000).toISOString(),
      src_ip: '10.0.20.15',
      dst_ip: '10.0.99.100',
      dst_port: 445,
      total_bytes: 100000
    }));
  }

  const baselines = calculateHostBaselines(normalRecords, config);

  // Backup surge of 1.8 GB
  const backupSurge = [
    createFlowRecord({
      record_id: 'f_backup_surge',
      timestamp: '2026-10-15T02:15:00Z',
      src_ip: '10.0.20.15',
      dst_ip: '10.0.99.100',
      dst_port: 445,
      total_bytes: 1850000000
    })
  ];

  const evalResult = evaluateHostTrafficDeviation('10.0.20.15', backupSurge, baselines, config);
  assert.equal(evalResult.backup_mitigated, true);
  assert.equal(evalResult.has_anomaly, false, 'Authorized backup must not trigger false positive attack alert');
  assert.equal(evalResult.status, 'MITIGATED_ROUTINE');
});
