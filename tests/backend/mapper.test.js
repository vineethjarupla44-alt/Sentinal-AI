import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { normalizeCSV, detectSchema } from '../../backend/app/dataLoader.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function getPath(rel) {
  const c1 = path.resolve(rel);
  const c2 = path.resolve(__dirname, '..', '..', rel);
  return fs.existsSync(c1) ? c1 : c2;
}

const mappingPath = getPath('config/dataset_mapping.json');
const schemaConfigs = JSON.parse(fs.readFileSync(mappingPath, 'utf8'));

test('Schema Detection: correctly identifies Zeek vs Firewall headers', () => {
  const zeekHeaders = ['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'proto', 'service'];
  const fwHeaders = ['timestamp', 'session_id', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol', 'action'];

  assert.equal(detectSchema(zeekHeaders, schemaConfigs), 'zeek_conn_log');
  assert.equal(detectSchema(fwHeaders, schemaConfigs), 'enterprise_firewall_vpc');
});

test('Schema Normalization: parses Zeek dataset into canonical FlowRecord', () => {
  const zeekPath = getPath('datasets/synthetic/zeek_sample_annotated.csv');
  const zeekCsv = fs.readFileSync(zeekPath, 'utf8');
  const result = normalizeCSV(zeekCsv, schemaConfigs);

  assert.ok(result.records.length > 0);
  assert.equal(result.audit.schema_detected, 'zeek_conn_log');
  assert.equal(result.audit.malformed_rows, 0);

  const sample = result.records[0];
  assert.ok(sample.record_id);
  assert.ok(sample.src_ip);
  assert.ok(sample.dst_ip);
  assert.ok(typeof sample.dst_port === 'number');
  assert.ok(sample.epoch_ms > 0);
});

test('Schema Normalization: parses Enterprise Firewall dataset into same canonical schema', () => {
  const fwPath = getPath('datasets/synthetic/firewall_sample_annotated.csv');
  const fwCsv = fs.readFileSync(fwPath, 'utf8');
  const result = normalizeCSV(fwCsv, schemaConfigs);

  assert.ok(result.records.length > 0);
  assert.equal(result.audit.schema_detected, 'enterprise_firewall_vpc');

  const sample = result.records[0];
  assert.ok(sample.record_id.startsWith('FW-SESS'));
  assert.equal(sample.protocol, 'UDP');
  assert.equal(sample.action, 'ALLOW');
});

test('Edge Cases: Handles duplicates, missing fields, and bad rows gracefully', () => {
  const edgePath = getPath('datasets/synthetic/edge_cases_sample.csv');
  const edgeCsv = fs.readFileSync(edgePath, 'utf8');
  const result = normalizeCSV(edgeCsv, schemaConfigs, 'zeek_conn_log');

  assert.equal(result.audit.duplicates_suppressed, 1, 'Should suppress duplicate record');
  assert.ok(result.audit.malformed_rows >= 2, 'Should skip rows missing mandatory endpoints or invalid date');
  assert.ok(result.records.length >= 2, 'Should preserve valid rows');

  const missingPortRow = result.records.find(r => r.record_id === 'C_EDGE_02');
  assert.ok(missingPortRow, 'Row with empty ports should be parsed using defaults');
  assert.equal(missingPortRow.src_port, 0);
  assert.equal(missingPortRow.bytes_out, 0);
});
