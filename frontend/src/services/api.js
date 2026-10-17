/**
 * TraceGuard - API Service Layer
 * Connects frontend dashboard with the detection backend API.
 * Automatically adapts between local development and cloud production (Vercel).
 */

const isLocalDev = typeof window !== 'undefined' &&
  (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') &&
  (window.location.port === '5173' || window.location.port === '5000');

const BACKEND_BASE = (typeof window !== 'undefined' && window.__TRACEGUARD_API_URL__)
  || (isLocalDev ? 'http://localhost:3001' : '');

export async function fetchHealth() {
  try {
    const res = await fetch(`${BACKEND_BASE}/health`);
    if (res.ok) return res.json();
  } catch (err) {
    // Fall back to /api/health if /health rewrite isn't active
  }
  const res2 = await fetch(`${BACKEND_BASE}/api/health`);
  if (!res2.ok) throw new Error(`Health check failed: ${res2.statusText}`);
  return res2.json();
}

export async function fetchEngineStatus() {
  const res = await fetch(`${BACKEND_BASE}/api/status`);
  if (!res.ok) throw new Error(`Failed to fetch engine status: ${res.statusText}`);
  return res.json();
}

export async function fetchDatasetAnalysis(datasetKey = 'zeek') {
  const res = await fetch(`${BACKEND_BASE}/api/analyze?dataset=${encodeURIComponent(datasetKey)}`);
  if (!res.ok) throw new Error(`Failed to analyze dataset (${datasetKey}): ${res.statusText}`);
  return res.json();
}

export async function analyzeCustomCSV(csvContent, forcedSchema = null) {
  const res = await fetch(`${BACKEND_BASE}/api/analyze-custom`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      csv: csvContent,
      schema: forcedSchema
    })
  });
  if (!res.ok) throw new Error(`Custom CSV analysis failed: ${res.statusText}`);
  return res.json();
}
