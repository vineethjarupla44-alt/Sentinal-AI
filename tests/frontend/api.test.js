import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from '../../backend/main.js';

test('Frontend API Contract: Backend health endpoint responds with UP status', async () => {
  const server = createServer();
  await new Promise(resolve => server.listen(0, resolve));
  const port = server.address().port;

  try {
    const res = await fetch(`http://localhost:${port}/health`);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.status, 'UP');
    assert.equal(data.service, 'Sentinel AI Backend API');
  } finally {
    server.close();
  }
});

test('Frontend API Contract: Status endpoint returns active baseline config and schemas', async () => {
  const server = createServer();
  await new Promise(resolve => server.listen(0, resolve));
  const port = server.address().port;

  try {
    const res = await fetch(`http://localhost:${port}/api/status`);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.status, 'ONLINE');
    assert.ok(data.config.approved_security_scanners.length > 0);
    assert.ok(data.schemas.schemas.zeek_conn_log);
    assert.ok(data.schemas.schemas.enterprise_firewall_vpc);
  } finally {
    server.close();
  }
});

test('Frontend API Contract: Custom CSV analysis endpoint normalizes and returns incidents', async () => {
  const server = createServer();
  await new Promise(resolve => server.listen(0, resolve));
  const port = server.address().port;

  const sampleCsv = `ts,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,proto,orig_bytes,resp_bytes,conn_state,label
2026-10-15T02:00:00Z,C1,10.0.1.1,50000,10.0.1.2,80,tcp,100,200,SF,benign_web
2026-10-15T02:00:01Z,C2,10.0.1.1,50001,10.0.1.2,443,tcp,100,200,SF,benign_web`;

  try {
    const res = await fetch(`http://localhost:${port}/api/analyze-custom`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ csv: sampleCsv, schema: 'zeek_conn_log' })
    });

    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.result.record_count, 2);
    assert.ok(Array.isArray(data.result.incidents));
  } finally {
    server.close();
  }
});

test('Frontend UI Contract: Static server hosts Stitch assets and all 6 screen components', async () => {
  const fs = await import('node:fs');
  const path = await import('node:path');

  const requiredFiles = [
    'frontend/index.html',
    'frontend/src/main.js',
    'frontend/src/styles/tokens.css',
    'frontend/src/styles/styles.css',
    'frontend/src/styles/animations.css',
    'frontend/src/components/Navigation.js',
    'frontend/src/components/DashboardScreen.js',
    'frontend/src/components/DatasetScreen.js',
    'frontend/src/components/InvestigationScreen.js',
    'frontend/src/components/ContextReplayScreen.js',
    'frontend/src/components/ConfigScreen.js',
    'frontend/src/components/ReportsScreen.js',
    'frontend/src/components/SvgCharts.js',
    'frontend/src/services/exportService.js'
  ];

  for (const relPath of requiredFiles) {
    const fullPath = path.resolve(relPath);
    assert.ok(fs.existsSync(fullPath), `Required frontend asset missing: ${relPath}`);
    const stat = fs.statSync(fullPath);
    assert.ok(stat.size > 50, `Frontend asset too small or empty: ${relPath}`);
  }
});

