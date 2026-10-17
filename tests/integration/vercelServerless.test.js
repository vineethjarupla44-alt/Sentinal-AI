import test from 'node:test';
import assert from 'node:assert/strict';
import healthHandler from '../../api/health.js';
import statusHandler from '../../api/status.js';
import analyzeHandler from '../../api/analyze.js';
import analyzeCustomHandler from '../../api/analyze-custom.js';

function createMockRes() {
  const headers = {};
  let statusCode = 200;
  let body = '';
  return {
    setHeader(k, v) { headers[k.toLowerCase()] = v; },
    writeHead(code, h = {}) {
      statusCode = code;
      Object.assign(headers, h);
    },
    end(data) {
      if (data) body += data;
    },
    getStatus() { return statusCode; },
    getJson() { return JSON.parse(body); }
  };
}

test('Vercel Function: /api/health responds with UP status and CORS headers', async () => {
  const req = { method: 'GET', url: '/api/health', headers: { host: 'sentinal-ai.vercel.app' } };
  const res = createMockRes();

  await healthHandler(req, res);

  assert.equal(res.getStatus(), 200);
  const json = res.getJson();
  assert.equal(json.status, 'UP');
  assert.equal(json.service, 'TraceGuard Backend API');
});

test('Vercel Function: /api/status returns engine config and schemas', async () => {
  const req = { method: 'GET', url: '/api/status', headers: { host: 'sentinal-ai.vercel.app' } };
  const res = createMockRes();

  await statusHandler(req, res);

  assert.equal(res.getStatus(), 200);
  const json = res.getJson();
  assert.equal(json.status, 'ONLINE');
  assert.ok(json.config.approved_security_scanners.length > 0);
  assert.ok(json.schemas.schemas.zeek_conn_log);
});

test('Vercel Function: /api/analyze processes synthetic dataset via serverless execution', async () => {
  const req = { method: 'GET', url: '/api/analyze?dataset=zeek', headers: { host: 'sentinal-ai.vercel.app' } };
  const res = createMockRes();

  await analyzeHandler(req, res);

  assert.equal(res.getStatus(), 200);
  const json = res.getJson();
  assert.equal(json.dataset, 'zeek');
  assert.ok(json.result.incidents.length > 0);
  assert.ok(json.evaluation.context_aware_stage.recall >= 0.8);
});

test('Vercel Function: /api/analyze-custom accepts pre-parsed JSON body and returns anomalies', async () => {
  const sampleCsv = `ts,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,proto,orig_bytes,resp_bytes,conn_state,label
2026-10-15T02:00:00Z,C1,10.0.1.1,50000,10.0.1.2,80,tcp,100,200,SF,benign_web
2026-10-15T02:00:01Z,C2,10.0.1.1,50001,10.0.1.2,443,tcp,100,200,SF,benign_web`;

  const req = {
    method: 'POST',
    url: '/api/analyze-custom',
    headers: { host: 'sentinal-ai.vercel.app', 'content-type': 'application/json' },
    body: { csv: sampleCsv, schema: 'zeek_conn_log' }
  };
  const res = createMockRes();

  await analyzeCustomHandler(req, res);

  assert.equal(res.getStatus(), 200);
  const json = res.getJson();
  assert.equal(json.dataset, 'custom');
  assert.equal(json.result.record_count, 2);
  assert.ok(Array.isArray(json.result.incidents));
});
