import http from 'node:http';
import { handleApiRequest } from './app/handler.js';

export function createServer() {
  return http.createServer((req, res) => {
    handleApiRequest(req, res);
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
