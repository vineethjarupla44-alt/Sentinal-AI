import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { TraceGuardPipeline } from './pipeline.js';
import { evaluateDetectionPerformance } from './evaluation.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Lazy singleton pipeline instance
let sharedPipeline = null;
function getPipeline() {
  if (!sharedPipeline) {
    sharedPipeline = new TraceGuardPipeline();
  }
  return sharedPipeline;
}

/**
 * Safely parse JSON body whether provided pre-parsed by serverless framework or as a readable stream
 */
async function parseBody(req) {
  if (req.body !== undefined && req.body !== null) {
    if (typeof req.body === 'object') return req.body;
    if (typeof req.body === 'string' && req.body.trim()) {
      try {
        return JSON.parse(req.body);
      } catch (e) {
        return null;
      }
    }
  }

  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', chunk => { raw += chunk; });
    req.on('end', () => {
      if (!raw || !raw.trim()) return resolve(null);
      try {
        resolve(JSON.parse(raw));
      } catch (err) {
        reject(err);
      }
    });
    req.on('error', reject);
  });
}

/**
 * Locate dataset CSV file across standard local and Vercel runtime directories
 */
function resolveDatasetPath(datasetKey) {
  let filename = 'zeek_sample_annotated.csv';
  if (datasetKey === 'firewall') filename = 'firewall_sample_annotated.csv';
  if (datasetKey === 'edge') filename = 'edge_cases_sample.csv';

  const candidates = [
    path.resolve(process.cwd(), 'datasets', 'synthetic', filename),
    path.resolve(process.cwd(), 'datasets', filename),
    path.resolve('datasets', 'synthetic', filename),
    path.resolve('datasets', filename),
    path.resolve(__dirname, '..', '..', 'datasets', 'synthetic', filename),
    path.resolve(__dirname, '..', '..', 'datasets', filename),
    path.resolve(__dirname, '..', 'datasets', 'synthetic', filename),
    path.resolve(__dirname, '..', 'datasets', filename)
  ];

  for (const p of candidates) {
    if (fs.existsSync(p)) {
      return p;
    }
  }
  return null;
}

/**
 * Universal request handler compatible with Node.js http.createServer and Vercel Serverless Functions
 */
export async function handleApiRequest(req, res) {
  // CORS Headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const parsedUrl = new URL(req.url, `http://${req.headers?.host || 'localhost'}`);
  const pathname = parsedUrl.pathname.replace(/\/+$/, '') || '/';

  // 1. Health Endpoint (/health or /api/health)
  if ((pathname === '/health' || pathname === '/api/health') && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: 'UP',
      service: 'TraceGuard Backend API',
      timestamp: new Date().toISOString()
    }));
    return;
  }

  // 2. Engine Status & Config (/api/status or /status)
  if ((pathname === '/api/status' || pathname === '/status') && req.method === 'GET') {
    const pipeline = getPipeline();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: 'ONLINE',
      engine: 'TraceGuard Adaptive Detection Engine v1.0.0',
      config: pipeline.config,
      schemas: pipeline.schemaMappings
    }));
    return;
  }

  // 3. Dataset Analysis Endpoint (/api/analyze or /analyze)
  if ((pathname === '/api/analyze' || pathname === '/analyze') && req.method === 'GET') {
    const datasetKey = parsedUrl.searchParams.get('dataset') || 'zeek';
    const datasetFile = resolveDatasetPath(datasetKey);

    if (!datasetFile) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: `Dataset file not found for key: ${datasetKey}` }));
      return;
    }

    try {
      const pipeline = getPipeline();
      const result = pipeline.processFile(datasetFile);
      const evalMetrics = evaluateDetectionPerformance(result);

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        dataset: datasetKey,
        file: datasetFile,
        result,
        evaluation: evalMetrics
      }));
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: err.message }));
    }
    return;
  }

  // 4. Custom CSV Upload & Ingestion (/api/analyze-custom or /analyze-custom)
  if ((pathname === '/api/analyze-custom' || pathname === '/analyze-custom') && req.method === 'POST') {
    try {
      const payload = await parseBody(req);
      if (!payload || !payload.csv) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Missing csv field in request body' }));
        return;
      }

      const pipeline = getPipeline();
      const result = pipeline.process(payload.csv, payload.schema || null);
      const evalMetrics = evaluateDetectionPerformance(result);

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        dataset: 'custom',
        result,
        evaluation: evalMetrics
      }));
    } catch (err) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: err.message }));
    }
    return;
  }

  // 5. Root API Discovery (/api)
  if (pathname === '/api' || pathname === '/api/') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      service: 'TraceGuard API',
      version: '1.0.0',
      status: 'ONLINE',
      endpoints: {
        health: '/health or /api/health',
        status: '/api/status',
        analyze: '/api/analyze?dataset=zeek|firewall|edge',
        analyzeCustom: 'POST /api/analyze-custom'
      }
    }));
    return;
  }

  // 6. Fallback 404
  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: `Endpoint not found: ${pathname}` }));
}
