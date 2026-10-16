import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { TraceGuardPipeline } from './app/pipeline.js';
import { evaluateDetectionPerformance } from './app/evaluation.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const pipeline = new TraceGuardPipeline();

export function createServer() {
  return http.createServer((req, res) => {
    // Standard CORS and JSON Headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const pathname = parsedUrl.pathname;

    // Health Endpoint
    if (pathname === '/health' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        status: 'UP',
        service: 'TraceGuard Backend API',
        timestamp: new Date().toISOString()
      }));
      return;
    }

    // Engine Status & Active Configurations
    if (pathname === '/api/status' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        status: 'ONLINE',
        engine: 'TraceGuard Adaptive Detection Engine v1.0.0',
        config: pipeline.config,
        schemas: pipeline.schemaMappings
      }));
      return;
    }

    // Dataset Analysis Endpoint
    if (pathname === '/api/analyze' && req.method === 'GET') {
      const datasetKey = parsedUrl.searchParams.get('dataset') || 'zeek';
      let candidateNames = ['zeek_sample_annotated.csv'];
      if (datasetKey === 'firewall') candidateNames = ['firewall_sample_annotated.csv'];
      if (datasetKey === 'edge') candidateNames = ['edge_cases_sample.csv'];

      const possiblePaths = [
        path.resolve('datasets', 'synthetic', candidateNames[0]),
        path.resolve('datasets', candidateNames[0]),
        path.resolve('..', 'datasets', 'synthetic', candidateNames[0]),
        path.resolve('..', 'datasets', candidateNames[0]),
        path.resolve(__dirname, '..', 'datasets', 'synthetic', candidateNames[0]),
        path.resolve(__dirname, '..', 'datasets', candidateNames[0])
      ];

      let datasetFile = null;
      for (const p of possiblePaths) {
        if (fs.existsSync(p)) {
          datasetFile = p;
          break;
        }
      }

      if (!datasetFile) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Dataset file not found for key: ${datasetKey}` }));
        return;
      }

      try {
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

    // Custom CSV Upload & Ingestion
    if (pathname === '/api/analyze-custom' && req.method === 'POST') {
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', () => {
        try {
          const payload = JSON.parse(body);
          const csvContent = payload.csv;
          const schema = payload.schema || null;

          if (!csvContent) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Missing csv field in request body' }));
            return;
          }

          const result = pipeline.process(csvContent, schema);
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
      });
      return;
    }

    // Default 404 for unhandled API paths
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Endpoint not found' }));
  });
}

const PORT = process.env.PORT || 3001;
const server = createServer();

if (process.argv[1] && process.argv[1].replace(/\\/g, '/').endsWith('backend/main.js')) {
  server.listen(PORT, () => {
    console.log(`[+] TraceGuard Backend API running at: http://localhost:${PORT}`);
    console.log(`    - Health check: http://localhost:${PORT}/health`);
    console.log(`    - Status & Config: http://localhost:${PORT}/api/status`);
    console.log(`    - Dataset Analysis: http://localhost:${PORT}/api/analyze?dataset=zeek`);
  });
}
