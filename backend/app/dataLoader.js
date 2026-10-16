import fs from 'node:fs';
import { createFlowRecord } from './types.js';

/**
 * Robust CSV Line Parser adhering to RFC-4180
 */
export function parseCSVLine(line) {
  const result = [];
  let current = '';
  let inQuotes = false;

  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    if (char === '"') {
      if (inQuotes && line[i + 1] === '"') {
        current += '"';
        i++; // skip escaped quote
      } else {
        inQuotes = !inQuotes;
      }
    } else if (char === ',' && !inQuotes) {
      result.push(current.trim());
      current = '';
    } else {
      current += char;
    }
  }
  result.push(current.trim());
  return result;
}

/**
 * Loads schema mapping definitions from config
 */
export function loadSchemaMappings(configPath) {
  if (typeof configPath === 'string') {
    const raw = fs.readFileSync(configPath, 'utf8');
    return JSON.parse(raw);
  }
  return configPath;
}

/**
 * Identifies best matching schema given CSV header column list
 */
export function detectSchema(headers, schemaConfigs) {
  let bestSchema = null;
  let maxScore = -1;

  for (const [key, schemaDef] of Object.entries(schemaConfigs.schemas || {})) {
    const expectedCols = Object.values(schemaDef.mapping);
    let matched = 0;
    for (const col of expectedCols) {
      if (headers.includes(col)) {
        matched++;
      }
    }
    const score = matched / expectedCols.length;
    if (score > maxScore && score >= 0.4) {
      maxScore = score;
      bestSchema = key;
    }
  }

  return bestSchema;
}

/**
 * Normalizes raw CSV content into canonical FlowRecord instances
 * @param {string} csvContent 
 * @param {object} schemaConfigs - Loaded dataset_mapping.json
 * @param {string} [forcedSchema] - Optional explicit schema override
 * @param {object} [options] - Deduplication and validation options
 */
export function normalizeCSV(csvContent, schemaConfigs, forcedSchema = null, options = {}) {
  const lines = csvContent
    .split(/\r?\n/)
    .map(l => l.trim())
    .filter(l => l.length > 0);

  if (lines.length < 2) {
    return {
      records: [],
      audit: {
        total_rows: 0,
        parsed_records: 0,
        duplicates_suppressed: 0,
        malformed_rows: 0,
        schema_detected: null,
        errors: ['CSV content is empty or contains no data rows.']
      }
    };
  }

  const rawHeaders = parseCSVLine(lines[0]);
  const schemaKey = forcedSchema || detectSchema(rawHeaders, schemaConfigs);

  if (!schemaKey || !schemaConfigs.schemas[schemaKey]) {
    throw new Error(
      `Unable to automatically detect compatible schema for headers: [${rawHeaders.join(', ')}]. ` +
      `Available schemas: ${Object.keys(schemaConfigs.schemas || {}).join(', ')}`
    );
  }

  const schemaDef = schemaConfigs.schemas[schemaKey];
  const fieldToHeaderMap = schemaDef.mapping;
  const defaults = schemaDef.defaults || {};

  const colIndexMap = {};
  for (let i = 0; i < rawHeaders.length; i++) {
    colIndexMap[rawHeaders[i]] = i;
  }

  const records = [];
  const seenDedupeKeys = new Set();
  let duplicatesCount = 0;
  let malformedCount = 0;
  const errors = [];

  for (let lineIndex = 1; lineIndex < lines.length; lineIndex++) {
    const row = parseCSVLine(lines[lineIndex]);
    if (row.length === 0 || (row.length === 1 && !row[0])) {
      continue;
    }

    const rawData = {};
    for (let c = 0; c < rawHeaders.length; c++) {
      rawData[rawHeaders[c]] = row[c] !== undefined ? row[c] : '';
    }

    // Map according to configured schema
    const mapped = {};
    for (const [canonicalField, sourceHeader] of Object.entries(fieldToHeaderMap)) {
      const idx = colIndexMap[sourceHeader];
      if (idx !== undefined && row[idx] !== undefined && row[idx] !== '') {
        mapped[canonicalField] = row[idx];
      } else if (defaults[canonicalField] !== undefined) {
        mapped[canonicalField] = defaults[canonicalField];
      }
    }

    // Safe handling for missing mandatory identity fields
    if (!mapped.src_ip || !mapped.dst_ip) {
      malformedCount++;
      errors.push(`Row ${lineIndex + 1}: Missing critical endpoint IP (src_ip: '${mapped.src_ip}', dst_ip: '${mapped.dst_ip}'). Row skipped.`);
      continue;
    }

    // Timestamp parsing validation
    let parsedTimestamp = mapped.timestamp;
    if (parsedTimestamp && !isNaN(Number(parsedTimestamp)) && Number(parsedTimestamp) > 1000000) {
      // Check for Unix seconds vs ms
      const numTs = Number(parsedTimestamp);
      parsedTimestamp = numTs < 10000000000 ? new Date(numTs * 1000).toISOString() : new Date(numTs).toISOString();
    } else if (parsedTimestamp) {
      const d = new Date(parsedTimestamp);
      if (isNaN(d.getTime())) {
        malformedCount++;
        errors.push(`Row ${lineIndex + 1}: Invalid timestamp format '${mapped.timestamp}'. Row skipped.`);
        continue;
      }
      parsedTimestamp = d.toISOString();
    } else {
      parsedTimestamp = new Date().toISOString();
    }
    mapped.timestamp = parsedTimestamp;

    // Deduplication check
    const dedupeKey = `${mapped.record_id || ''}|${mapped.timestamp}|${mapped.src_ip}|${mapped.dst_ip}|${mapped.dst_port}|${mapped.protocol}`;
    if (seenDedupeKeys.has(dedupeKey)) {
      duplicatesCount++;
      continue;
    }
    seenDedupeKeys.add(dedupeKey);

    mapped.raw_metadata = {
      original_schema: schemaKey,
      source_row_index: lineIndex + 1,
      unmapped_fields: rawData
    };

    records.push(createFlowRecord(mapped));
  }

  // Ensure chronological ordering for sliding time window correlation
  records.sort((a, b) => a.epoch_ms - b.epoch_ms);

  return {
    records,
    audit: {
      total_rows: lines.length - 1,
      parsed_records: records.length,
      duplicates_suppressed: duplicatesCount,
      malformed_rows: malformedCount,
      schema_detected: schemaKey,
      schema_name: schemaDef.name,
      errors
    }
  };
}
