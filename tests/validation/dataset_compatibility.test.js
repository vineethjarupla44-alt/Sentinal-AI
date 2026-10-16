import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { normalizeCSV, detectSchema, parseCSVLine } from '../../backend/app/dataLoader.js';
import { runAllDetectionRules } from '../../backend/app/detectionRules.js';
import { TraceGuardPipeline } from '../../backend/app/pipeline.js';
import { createFlowRecord } from '../../backend/app/types.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function getPath(rel) {
  const c1 = path.resolve(rel);
  const c2 = path.resolve(__dirname, '..', '..', rel);
  return fs.existsSync(c1) ? c1 : c2;
}

const mappingPath = getPath('config/dataset_mapping.json');
const schemaConfigs = JSON.parse(fs.readFileSync(mappingPath, 'utf8'));
const config = JSON.parse(fs.readFileSync(getPath('config/config.json'), 'utf8'));

/**
 * TC-SCHEMA-DISCLOSE-001: Synthetic Fixture Location Verification
 * Feature: Repository Fixture Auditing
 * Expected: Disclose accurately which fixture names exist and which are absent.
 */
test('TC-SCHEMA-DISCLOSE-001: Accurately audits dataset fixture locations without creating fake substitute files', () => {
  const requestedFiles = [
    'flows_dataset_A.csv',
    'flows_dataset_B_zeek_style.csv',
    'ground_truth_labels.csv'
  ];

  for (const f of requestedFiles) {
    const existsInRoot = fs.existsSync(path.resolve(f));
    const existsInDatasets = fs.existsSync(getPath(`datasets/${f}`));
    assert.equal(existsInRoot || existsInDatasets, false, `Requested hypothetical fixture '${f}' is confirmed absent in repository.`);
  }

  // Canonical existing fixtures
  assert.equal(fs.existsSync(getPath('datasets/synthetic/zeek_sample_annotated.csv')), true);
  assert.equal(fs.existsSync(getPath('datasets/synthetic/firewall_sample_annotated.csv')), true);
  assert.equal(fs.existsSync(getPath('datasets/synthetic/edge_cases_sample.csv')), true);
});

/**
 * TC-SCHEMA-MAP-001: Address Mapping
 * Feature: Source & Destination IP Field Mapping
 * Expected: Zeek (id.orig_h, id.resp_h) and Firewall (src_ip, dst_ip) normalize to src_ip, dst_ip.
 */
test('TC-SCHEMA-MAP-001: Normalizes source and destination IP addresses correctly across Zeek and Firewall schemas', () => {
  const zeekCsv = `ts,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,proto
2026-10-15T02:00:00Z,Z1,10.0.1.5,45000,10.0.2.10,80,tcp`;

  const fwCsv = `timestamp,session_id,src_ip,src_port,dst_ip,dst_port,protocol
2026-10-15T02:00:00Z,F1,10.0.1.5,45000,10.0.2.10,80,tcp`;

  const zResult = normalizeCSV(zeekCsv, schemaConfigs);
  const fResult = normalizeCSV(fwCsv, schemaConfigs);

  assert.equal(zResult.records[0].src_ip, '10.0.1.5');
  assert.equal(zResult.records[0].dst_ip, '10.0.2.10');
  assert.equal(fResult.records[0].src_ip, '10.0.1.5');
  assert.equal(fResult.records[0].dst_ip, '10.0.2.10');
});

/**
 * TC-SCHEMA-MAP-002: Port and Protocol Mapping
 * Feature: Port Number Parsing and Protocol Uppercasing
 * Expected: Integer ports and uppercase standardized protocol names.
 */
test('TC-SCHEMA-MAP-002: Converts destination ports to integers and standardizes protocol tokens', () => {
  const zeekCsv = `ts,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,proto
2026-10-15T02:00:00Z,Z1,10.0.1.5,51234,10.0.2.10,443,tcp
2026-10-15T02:00:01Z,Z2,10.0.1.5,51235,10.0.2.10,53,udp`;

  const result = normalizeCSV(zeekCsv, schemaConfigs);
  assert.equal(typeof result.records[0].dst_port, 'number');
  assert.equal(result.records[0].dst_port, 443);
  assert.equal(result.records[0].protocol, 'TCP');
  assert.equal(result.records[1].dst_port, 53);
  assert.equal(result.records[1].protocol, 'UDP');
});

/**
 * TC-SCHEMA-TIME-001: Timestamp Parsing and Chronological Sorting
 * Feature: ISO-8601 & Unix Timestamp Ingestion
 * Expected: Parse both ISO-8601 strings and Unix epoch seconds, sorting ascending.
 */
test('TC-SCHEMA-TIME-001: Parses Unix epoch timestamps and ISO-8601 dates with strict chronological ordering', () => {
  // Line 1: later timestamp (1760500060 = T+60s)
  // Line 2: earlier timestamp (1760500000 = T+0s)
  const csv = `ts,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,proto
1760500060,U2,10.0.1.1,1000,10.0.2.2,80,tcp
1760500000,U1,10.0.1.1,1001,10.0.2.2,80,tcp`;

  const result = normalizeCSV(csv, schemaConfigs, 'zeek_conn_log');
  assert.equal(result.records.length, 2);
  // Must be sorted chronologically
  assert.equal(result.records[0].record_id, 'U1');
  assert.equal(result.records[1].record_id, 'U2');
  assert.ok(result.records[0].epoch_ms < result.records[1].epoch_ms);
});

/**
 * TC-SCHEMA-METRIC-001: Byte Metric Mapping
 * Feature: Inbound and Outbound Byte Throughput
 * Expected: Numeric bytes_out, bytes_in, total_bytes calculated accurately.
 */
test('TC-SCHEMA-METRIC-001: Maps byte fields accurately and computes total bytes', () => {
  const fwCsv = `timestamp,session_id,src_ip,src_port,dst_ip,dst_port,protocol,bytes_sent,bytes_received
2026-10-15T02:00:00Z,F1,10.0.1.5,45000,10.0.2.10,80,tcp,1250,3750`;

  const result = normalizeCSV(fwCsv, schemaConfigs);
  const rec = result.records[0];
  assert.equal(rec.bytes_out, 1250);
  assert.equal(rec.bytes_in, 3750);
  assert.equal(rec.total_bytes, 5000);
});

/**
 * TC-SCHEMA-OPT-001: Missing Optional Columns
 * Feature: Fallback Defaults
 * Expected: Default values applied when optional columns are omitted from CSV.
 */
test('TC-SCHEMA-OPT-001: Applies schema defaults when optional columns are absent', () => {
  // Omit action, bytes_out, bytes_in, duration
  const minimalCsv = `ts,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,proto
2026-10-15T02:00:00Z,M1,10.0.1.5,45000,10.0.2.10,80,tcp`;

  const result = normalizeCSV(minimalCsv, schemaConfigs);
  const rec = result.records[0];
  assert.equal(rec.bytes_out, 0);
  assert.equal(rec.bytes_in, 0);
  assert.equal(rec.total_bytes, 0);
  assert.equal(rec.action, 'ALLOW');
});

/**
 * TC-SCHEMA-MALFORM-001: Empty & Malformed Rows
 * Feature: Safe Row Ingestion
 * Expected: Rows lacking mandatory endpoints are skipped and recorded in audit log.
 */
test('TC-SCHEMA-MALFORM-001: Skips rows with missing endpoint IPs and records audit log errors', () => {
  const malformedCsv = `ts,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,proto
2026-10-15T02:00:00Z,OK1,10.0.1.5,45000,10.0.2.10,80,tcp
2026-10-15T02:00:01Z,BAD1,,45000,10.0.2.10,80,tcp
2026-10-15T02:00:02Z,BAD2,10.0.1.5,45000,,80,tcp
,
2026-10-15T02:00:03Z,OK2,10.0.1.5,45001,10.0.2.10,80,tcp`;

  const result = normalizeCSV(malformedCsv, schemaConfigs);
  assert.equal(result.records.length, 2, 'Should only parse the 2 valid rows');
  assert.equal(result.audit.malformed_rows, 3, 'Should record 3 malformed rows');
  assert.ok(result.audit.errors.length >= 2);
});

/**
 * TC-SCHEMA-BADTS-001: Invalid Timestamp Formats
 * Feature: Timestamp Validation
 * Expected: Unparseable timestamp formats skipped without unhandled exception.
 */
test('TC-SCHEMA-BADTS-001: Gracefully rejects invalid timestamp formats without crashing', () => {
  const badTsCsv = `ts,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,proto
not-a-valid-timestamp,B1,10.0.1.5,45000,10.0.2.10,80,tcp
2026-10-15T02:00:00Z,OK1,10.0.1.5,45000,10.0.2.10,80,tcp`;

  const result = normalizeCSV(badTsCsv, schemaConfigs);
  assert.equal(result.records.length, 1);
  assert.equal(result.audit.malformed_rows, 1);
  assert.ok(result.audit.errors[0].includes('Invalid timestamp format'));
});

/**
 * TC-SCHEMA-CONSIST-001: Canonical Schema Consistency
 * Feature: Cross-Schema Schema Uniformity
 * Expected: All records adhere to the canonical FlowRecord object structure.
 */
test('TC-SCHEMA-CONSIST-001: Produces identical canonical FlowRecord structure regardless of input schema', () => {
  const zeekCsv = fs.readFileSync(getPath('datasets/synthetic/zeek_sample_annotated.csv'), 'utf8');
  const fwCsv = fs.readFileSync(getPath('datasets/synthetic/firewall_sample_annotated.csv'), 'utf8');

  const zResult = normalizeCSV(zeekCsv, schemaConfigs);
  const fResult = normalizeCSV(fwCsv, schemaConfigs);

  const requiredFields = ['record_id', 'timestamp', 'epoch_ms', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol', 'bytes_out', 'bytes_in', 'total_bytes'];

  for (const field of requiredFields) {
    assert.ok(zResult.records[0][field] !== undefined, `Zeek record must have ${field}`);
    assert.ok(fResult.records[0][field] !== undefined, `Firewall record must have ${field}`);
  }
});

/**
 * TC-SCHEMA-EQUIV-001: Equivalent Record Detection Invariance
 * Feature: Detection Rule Cross-Schema Consistency
 * Expected: Identical attack behavior formatted as Zeek or Firewall generates identical rule trigger.
 */
test('TC-SCHEMA-EQUIV-001: Identical attack flows in Zeek vs Firewall schemas trigger identical detection rules', () => {
  // 8 distinct target hosts on port 445 (Horizontal Network Sweep)
  const zeekRows = ['ts,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,proto'];
  const fwRows = ['timestamp,session_id,src_ip,src_port,dst_ip,dst_port,protocol'];

  for (let i = 1; i <= 8; i++) {
    const ts = new Date(1760500000000 + i * 1000).toISOString();
    zeekRows.push(`${ts},Z_${i},10.0.1.99,50000,10.0.2.${i},445,tcp`);
    fwRows.push(`${ts},F_${i},10.0.1.99,50000,10.0.2.${i},445,tcp`);
  }

  const zNorm = normalizeCSV(zeekRows.join('\n'), schemaConfigs);
  const fNorm = normalizeCSV(fwRows.join('\n'), schemaConfigs);

  const zDets = runAllDetectionRules(zNorm.records, config);
  const fDets = runAllDetectionRules(fNorm.records, config);

  assert.equal(zDets.length, 2, 'Zeek should detect both network sweep and lateral movement');
  assert.equal(fDets.length, 2, 'Firewall should detect both network sweep and lateral movement');
  assert.equal(zDets[0].rule_id, fDets[0].rule_id);
  assert.equal(zDets[1].rule_id, fDets[1].rule_id);
  assert.equal(zDets[0].distinct_count, fDets[0].distinct_count);
  assert.equal(zDets[1].distinct_count, fDets[1].distinct_count);
});

/**
 * TC-SCHEMA-LEAK-001: Label Separation (Zero Ground-Truth Leakage)
 * Feature: Evaluation Integrity
 * Expected: Detector algorithms never use the 'label' or 'ground_truth_label' field.
 */
test('TC-SCHEMA-LEAK-001: Detection rules do not inspect label fields ensuring zero ground-truth leakage', () => {
  // Create flows with benign label that actually perform a vertical port scan
  const deceptiveFlows = [];
  const baseEpoch = 1760500000000;

  for (let p = 1; p <= 12; p++) {
    deceptiveFlows.push(createFlowRecord({
      record_id: `leak_${p}`,
      timestamp: new Date(baseEpoch + p * 1000).toISOString(),
      src_ip: '10.0.1.200',
      dst_ip: '10.0.2.1',
      dst_port: 8000 + p,
      protocol: 'TCP',
      label: 'benign_normal_traffic' // Deceptive ground-truth label!
    }));
  }

  const detections = runAllDetectionRules(deceptiveFlows, config);
  assert.equal(detections.length, 1, 'Detection rule must trigger based solely on telemetry, ignoring label');
  assert.equal(detections[0].rule_id, 'RULE-PORT-SCAN-001');
});
