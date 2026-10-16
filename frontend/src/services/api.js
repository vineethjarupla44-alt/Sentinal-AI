/**
 * Sentinel AI - API Service Layer
 * Connects frontend dashboard with the detection backend API.
 */

const BACKEND_BASE = window.location.port === '3001'
  ? ''
  : 'http://localhost:3001';

export async function fetchHealth() {
  const res = await fetch(`${BACKEND_BASE}/health`);
  if (!res.ok) throw new Error(`Health check failed: ${res.statusText}`);
  return res.json();
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
