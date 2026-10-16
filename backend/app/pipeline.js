import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadSchemaMappings, normalizeCSV } from './dataLoader.js';
import { runAllDetectionRules } from './detectionRules.js';
import { applyContextToDetection } from './trustedActivity.js';
import { groupAndScoreIncidents } from './incidentEngine.js';
import { generateAdaptiveContextReplay } from './contextReplay.js';
import { calculateHostBaselines, evaluateHostTrafficDeviation } from './hostBaseline.js';
import { detectBeaconing } from './beaconingDetector.js';
import { buildIncidentTimeline } from './timelineEngine.js';
import { buildIncidentCommunicationGraph } from './graphEngine.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function findConfigFile(filenameList) {
  const baseDirs = [
    path.resolve('config'),
    path.resolve('..', 'config'),
    path.resolve(__dirname, '..', '..', 'config'),
    path.resolve(__dirname, '..', 'config')
  ];

  for (const name of filenameList) {
    for (const dir of baseDirs) {
      const candidate = path.join(dir, name);
      if (fs.existsSync(candidate)) {
        return candidate;
      }
    }
  }
  return null;
}

/**
 * End-to-End Sentinel AI Detection Pipeline
 */
export class SentinelPipeline {
  constructor(config = null, schemaMappings = null) {
    this.config = config || this.loadDefaultConfig();
    this.schemaMappings = schemaMappings || this.loadDefaultSchemaMappings();
  }

  loadDefaultConfig() {
    const configPath = findConfigFile(['config.json', 'adaptive_config.json']);
    if (configPath && fs.existsSync(configPath)) {
      return JSON.parse(fs.readFileSync(configPath, 'utf8'));
    }
    return {};
  }

  loadDefaultSchemaMappings() {
    const schemaPath = findConfigFile(['dataset_mapping.json', 'schema_mappings.json']);
    if (schemaPath && fs.existsSync(schemaPath)) {
      return JSON.parse(fs.readFileSync(schemaPath, 'utf8'));
    }
    return { schemas: {} };
  }

  updateConfig(newConfig) {
    this.config = { ...this.config, ...newConfig };
  }

  process(csvContent, forcedSchema = null, options = {}) {
    const startTime = Date.now();

    // 1. Normalize CSV via column mapping layer
    const normalizationResult = normalizeCSV(csvContent, this.schemaMappings, forcedSchema, options);
    const records = normalizationResult.records;

    // 2. Detection Rules Execution (Naive/Volumetric)
    const rawDetections = runAllDetectionRules(records, this.config);

    // 2b. Behavioral Baselines & Beaconing Detection
    const hostBaselines = calculateHostBaselines(records, this.config);
    const beaconingFindings = detectBeaconing(records, this.config);

    // 3. Evidence-Preserving Context Evaluation
    const contextualizedDetections = rawDetections.map(det =>
      applyContextToDetection(det, this.config)
    );

    // 4. Incident Grouping & 0-100 Prioritization Scoring
    const incidents = groupAndScoreIncidents(contextualizedDetections, this.config);

    // 4b. Attach Baseline Deviations, Timelines & Communication Graphs to each Incident
    for (const incident of incidents) {
      const incidentFlows = records.filter(r => (incident.record_ids || []).includes(r.record_id));
      incident.baseline_deviation = evaluateHostTrafficDeviation(
        incident.source_entity,
        incidentFlows,
        hostBaselines,
        this.config
      );
      incident.timeline_events = buildIncidentTimeline(
        incident,
        records,
        contextualizedDetections,
        beaconingFindings
      );
      incident.communication_graph = buildIncidentCommunicationGraph(
        incident,
        records,
        contextualizedDetections,
        this.config
      );
      incident.beaconing_findings = beaconingFindings.filter(
        b => b.source_ip === incident.source_entity
      );
    }

    // 5. Adaptive Context Replay Generation
    const contextReplays = generateAdaptiveContextReplay(
      rawDetections,
      contextualizedDetections,
      incidents,
      this.config
    );

    const executionTimeMs = Date.now() - startTime;

    const mitigatedCount = contextualizedDetections.filter(
      d => d.context_mitigations.length > 0 && d.unexplained_evidence.length === 0 && d.adjusted_score < 30
    ).length;

    const unexplainedDeviationCount = contextualizedDetections.filter(
      d => d.unexplained_evidence.length > 0
    ).length;

    // Convert hostBaselines Map to serializable object
    const serializableBaselines = {};
    for (const [k, v] of hostBaselines.entries()) {
      serializableBaselines[k] = v;
    }

    return {
      success: true,
      execution_time_ms: executionTimeMs,
      audit: normalizationResult.audit,
      record_count: records.length,
      records,
      raw_detections: rawDetections,
      contextualized_detections: contextualizedDetections,
      incidents,
      context_replays: contextReplays,
      host_baselines: serializableBaselines,
      beaconing_findings: beaconingFindings,
      metrics_summary: {
        total_records_processed: records.length,
        raw_detections_count: rawDetections.length,
        incidents_generated: incidents.length,
        benign_lookalikes_mitigated: mitigatedCount,
        unexplained_deviations: unexplainedDeviationCount,
        false_positive_reduction_rate_pct: rawDetections.length > 0
          ? Math.round((mitigatedCount / rawDetections.length) * 100)
          : 0
      }
    };
  }

  processFile(filePath, forcedSchema = null, options = {}) {
    let resolvedPath = filePath;
    if (!fs.existsSync(resolvedPath)) {
      // Try resolving relative to project roots or dataset directories
      const alternatives = [
        path.resolve(filePath),
        path.resolve('datasets', filePath),
        path.resolve('datasets', 'synthetic', filePath),
        path.resolve('..', filePath),
        path.resolve('..', 'datasets', filePath),
        path.resolve('..', 'datasets', 'synthetic', filePath),
        path.resolve(__dirname, '..', '..', 'datasets', filePath),
        path.resolve(__dirname, '..', '..', 'datasets', 'synthetic', filePath),
        path.resolve(__dirname, '..', '..', filePath)
      ];
      for (const alt of alternatives) {
        if (fs.existsSync(alt)) {
          resolvedPath = alt;
          break;
        }
      }
    }

    if (!fs.existsSync(resolvedPath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    const content = fs.readFileSync(resolvedPath, 'utf8');
    return this.process(content, forcedSchema, options);
  }
}
