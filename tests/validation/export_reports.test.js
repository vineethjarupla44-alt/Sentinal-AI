import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { generateIncidentsCSV, generateExecutiveHTML, escapeCsvField, escapeHtml } from '../../frontend/src/services/exportService.js';
import { TraceGuardPipeline } from '../../backend/app/pipeline.js';
import { evaluateDetectionPerformance } from '../../backend/app/evaluation.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function getPath(rel) {
  const c1 = path.resolve(rel);
  const c2 = path.resolve(__dirname, '..', '..', rel);
  return fs.existsSync(c1) ? c1 : c2;
}

/**
 * TC-EXP-CSV-001: Forensic CSV Export Structure & RFC-4180 Escaping
 * Feature: Incident CSV Generation
 * Expected: 13 standard headers, correct row counts, and strict escaping of quotes/commas.
 */
test('TC-EXP-CSV-001: Forensic CSV export generates correct headers and escapes quotes/commas per RFC-4180', () => {
  // Unit test escaping helper
  assert.equal(escapeCsvField('normal'), '"normal"');
  assert.equal(escapeCsvField('has,comma'), '"has,comma"');
  assert.equal(escapeCsvField('has"quote'), '"has""quote"');
  assert.equal(escapeCsvField(null), '""');

  const mockPipelineData = {
    result: {
      incidents: [
        {
          incident_id: 'INC-2026-001',
          source_entity: '10.0.1.77',
          prioritization_score: 95,
          severity: 'CRITICAL',
          raw_score: 95,
          record_count: 8,
          duration_seconds: 45,
          first_seen: '2026-10-15T02:00:00Z',
          last_seen: '2026-10-15T02:00:45Z',
          distinct_rules_triggered: ['RULE-NET-SWEEP-001', 'RULE-LAT-MOVE-001'],
          context_summary: {
            is_benign_lookalike: false,
            mitigations: []
          }
        },
        {
          incident_id: 'INC-2026-002',
          source_entity: '10.0.50.5', // Scanner
          prioritization_score: 18,
          severity: 'INFORMATIONAL',
          raw_score: 75,
          record_count: 14,
          duration_seconds: 60,
          first_seen: '2026-10-15T03:00:00Z',
          last_seen: '2026-10-15T03:01:00Z',
          distinct_rules_triggered: ['RULE-PORT-SCAN-001'],
          context_summary: {
            is_benign_lookalike: true,
            mitigations: [{ type: 'APPROVED_SCANNER' }]
          }
        }
      ],
      context_replays: []
    }
  };

  const csv = generateIncidentsCSV(mockPipelineData);
  const lines = csv.split('\r\n');

  // Verify headers
  const headerLine = lines[0];
  const expectedHeaders = [
    'Incident_ID',
    'Source_Entity',
    'Prioritization_Score_0_to_100',
    'Severity',
    'Raw_Score',
    'Flow_Record_Count',
    'Duration_Seconds',
    'First_Seen',
    'Last_Seen',
    'Distinct_Rules_Triggered',
    'Is_Benign_Lookalike',
    'Unexplained_Evidence_Count',
    'Mitigations_Applied'
  ];
  assert.equal(headerLine, expectedHeaders.join(','));

  // Verify 2 data rows
  assert.equal(lines.length, 3);
  assert.ok(lines[1].includes('"INC-2026-001"'));
  assert.ok(lines[1].includes('"10.0.1.77"'));
  assert.ok(lines[1].includes('"NO"'));
  assert.ok(lines[2].includes('"INC-2026-002"'));
  assert.ok(lines[2].includes('"YES"'));
  assert.ok(lines[2].includes('"APPROVED_SCANNER"'));
});

/**
 * TC-EXP-HTML-001: Standalone HTML Executive Report Generation & XSS Sanitization
 * Feature: Executive HTML Report & XSS Defense
 * Expected: Valid HTML5 structure, styled executive cards, and strict sanitization of malicious script tags.
 */
test('TC-EXP-HTML-001: Standalone HTML executive report is valid HTML5 and sanitizes malicious script payloads', () => {
  // Test HTML escaping helper
  assert.equal(escapeHtml('<script>alert("XSS")</script>'), '&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;');
  assert.equal(escapeHtml("Tom & Jerry's"), 'Tom &amp; Jerry&#39;s');

  const maliciousPipelineData = {
    result: {
      record_count: 100,
      incidents: [
        {
          incident_id: 'INC-XSS-001',
          source_entity: '<script>alert("XSS")</script>', // Malicious input from un-sanitized source!
          prioritization_score: 99,
          severity: 'CRITICAL',
          raw_score: 99,
          record_count: 5,
          distinct_rules_triggered: ['RULE-<img src=x onerror=alert(1)>']
        }
      ],
      context_replays: []
    },
    evaluation: {
      naive_stage: { recall: 1.0 },
      context_aware_stage: { recall: 1.0 },
      improvement: { fp_reduction_percent: 60, precision_gain_percent: 18.7 }
    }
  };

  const html = generateExecutiveHTML(maliciousPipelineData);

  // Validate HTML structure
  assert.ok(html.startsWith('<!DOCTYPE html>'));
  assert.ok(html.includes('<title>TraceGuard - Executive Forensic Evaluation Report</title>'));
  assert.ok(html.includes('TRACEGUARD &bull; EXECUTIVE FORENSIC REPORT'));
  assert.ok(html.includes('60%'));
  assert.ok(html.includes('+18.7%'));

  // Critical: Verify malicious script payload was safely escaped and cannot execute
  assert.equal(html.includes('<script>alert("XSS")</script>'), false, 'Malicious script tag must NOT be injected into HTML');
  assert.ok(html.includes('&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;'), 'Script tag must be safely escaped as text entity');
  assert.equal(html.includes('<img src=x'), false, 'Malicious img tag must NOT be injected');
});

/**
 * TC-EXP-MATCH-001: Export Data Fidelity with Pipeline Analysis Output
 * Feature: End-to-End Export Fidelity
 * Expected: Generated CSV and HTML faithfully reflect live pipeline results.
 */
test('TC-EXP-MATCH-001: Exported report contents correspond 100% to actual pipeline analysis outputs', () => {
  const pipeline = new TraceGuardPipeline();
  const zeekPath = getPath('datasets/synthetic/zeek_sample_annotated.csv');
  const result = pipeline.processFile(zeekPath);
  const evaluation = evaluateDetectionPerformance(result);

  const bundle = { result, evaluation };

  const csv = generateIncidentsCSV(bundle);
  const html = generateExecutiveHTML(bundle);

  // CSV check
  const csvLines = csv.split('\r\n').filter(l => l.trim().length > 0);
  assert.equal(csvLines.length - 1, result.incidents.length, 'CSV row count must match incident count');

  // Verify all incident IDs exist in both CSV and HTML
  for (const inc of result.incidents) {
    assert.ok(csv.includes(`"${inc.incident_id}"`), `CSV must include ${inc.incident_id}`);
    assert.ok(html.includes(inc.incident_id), `HTML must include ${inc.incident_id}`);
    assert.ok(html.includes(inc.source_entity), `HTML must include ${inc.source_entity}`);
  }
});
