import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { SentinelPipeline } from './app/pipeline.js';
import { evaluateDetectionPerformance, generateMarkdownEvaluationReport } from './app/evaluation.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function printHeader(text) {
  console.log('\n' + '='.repeat(70));
  console.log(`  ${text}`);
  console.log('='.repeat(70));
}

function resolveDataset(name) {
  const candidates = [
    path.resolve('datasets', 'synthetic', name),
    path.resolve('datasets', name),
    path.resolve('..', 'datasets', 'synthetic', name),
    path.resolve('..', 'datasets', name),
    path.resolve(__dirname, '..', 'datasets', 'synthetic', name),
    path.resolve(__dirname, '..', 'datasets', name)
  ];
  for (const c of candidates) {
    if (fs.existsSync(c)) return c;
  }
  return path.resolve('datasets', name);
}

export function runCLI() {
  const zeekPath = resolveDataset('zeek_sample_annotated.csv');
  const fwPath = resolveDataset('firewall_sample_annotated.csv');

  printHeader('SENTINEL AI: ADAPTIVE DETECTION & BEHAVIOUR ANALYSIS ENGINE');
  console.log('[*] Initializing detection pipeline with external adaptive baselines...');

  const pipeline = new SentinelPipeline();

  // 1. Process Zeek Dataset
  console.log(`\n[+] Running analysis on Schema 1: Zeek conn.log (${zeekPath})`);
  const zeekResult = pipeline.processFile(zeekPath);
  console.log(`    - Parsed records: ${zeekResult.record_count} (Schema: ${zeekResult.audit.schema_name})`);
  console.log(`    - Raw detections triggered: ${zeekResult.raw_detections.length}`);
  console.log(`    - Prioritized incidents generated: ${zeekResult.incidents.length}`);
  console.log(`    - Benign lookalikes mitigated: ${zeekResult.metrics_summary.benign_lookalikes_mitigated}`);
  console.log(`    - Unexplained deviations flagged: ${zeekResult.metrics_summary.unexplained_deviations}`);

  // 2. Process Firewall Dataset
  console.log(`\n[+] Running analysis on Schema 2: Enterprise Firewall / VPC (${fwPath})`);
  const fwResult = pipeline.processFile(fwPath);
  console.log(`    - Parsed records: ${fwResult.record_count} (Schema: ${fwResult.audit.schema_name})`);
  console.log(`    - Raw detections triggered: ${fwResult.raw_detections.length}`);
  console.log(`    - Prioritized incidents generated: ${fwResult.incidents.length}`);

  // 3. Evaluate Performance
  printHeader('EMPIRICAL EVALUATION: BEFORE VS AFTER ADAPTIVE CONTEXT');
  const evaluation = evaluateDetectionPerformance(zeekResult);

  console.log(`Ground Truth Distribution:`);
  console.log(`  - Total Flows Evaluated: ${evaluation.sample_size}`);
  console.log(`  - Malicious Attack Flows: ${evaluation.ground_truth_distribution.malicious_attack_flows}`);
  console.log(`  - Benign Lookalikes (Scanners/Backups/Patching): ${evaluation.ground_truth_distribution.benign_lookalike_flows}`);
  console.log(`  - Standard Benign Flows: ${evaluation.ground_truth_distribution.standard_benign_flows}`);

  console.log(`\nMetric Comparison:`);
  console.log(`┌──────────────────────────────┬──────────────────┬──────────────────┐`);
  console.log(`│ Metric                       │ Naive IDS Mode   │ Context-Aware AI │`);
  console.log(`├──────────────────────────────┼──────────────────┼──────────────────┤`);
  console.log(`│ True Positives (TP)          │ ${String(evaluation.naive_stage.tp).padEnd(16)} │ ${String(evaluation.context_aware_stage.tp).padEnd(16)} │`);
  console.log(`│ False Positives (FP)         │ ${String(evaluation.naive_stage.fp).padEnd(16)} │ ${String(evaluation.context_aware_stage.fp).padEnd(16)} │`);
  console.log(`│ True Negatives (TN)          │ ${String(evaluation.naive_stage.tn).padEnd(16)} │ ${String(evaluation.context_aware_stage.tn).padEnd(16)} │`);
  console.log(`│ False Negatives (FN)         │ ${String(evaluation.naive_stage.fn).padEnd(16)} │ ${String(evaluation.context_aware_stage.fn).padEnd(16)} │`);
  console.log(`│ Precision                    │ ${((evaluation.naive_stage.precision * 100).toFixed(2) + '%').padEnd(16)} │ ${((evaluation.context_aware_stage.precision * 100).toFixed(2) + '%').padEnd(16)} │`);
  console.log(`│ Recall                       │ ${((evaluation.naive_stage.recall * 100).toFixed(2) + '%').padEnd(16)} │ ${((evaluation.context_aware_stage.recall * 100).toFixed(2) + '%').padEnd(16)} │`);
  console.log(`│ False Positive Rate (FPR)    │ ${((evaluation.naive_stage.fpr * 100).toFixed(2) + '%').padEnd(16)} │ ${((evaluation.context_aware_stage.fpr * 100).toFixed(2) + '%').padEnd(16)} │`);
  console.log(`│ F1-Score                     │ ${((evaluation.naive_stage.f1_score * 100).toFixed(2) + '%').padEnd(16)} │ ${((evaluation.context_aware_stage.f1_score * 100).toFixed(2) + '%').padEnd(16)} │`);
  console.log(`└──────────────────────────────┴──────────────────┴──────────────────┘`);

  console.log(`\nKey Improvement Summary:`);
  console.log(`  [*] False Positive Reduction: -${evaluation.improvement.fp_reduced_count} false alarms (${evaluation.improvement.fp_reduction_percent}% reduction)`);
  console.log(`  [*] Precision Gain: +${evaluation.improvement.precision_gain_percent}%`);
  console.log(`  [*] Recall Status: ${evaluation.improvement.recall_preserved ? '100% genuine attacks preserved without suppression' : 'Degraded'}`);

  // 4. Generate and save Markdown Report
  let docsDir = path.resolve('docs');
  if (!fs.existsSync(docsDir)) {
    docsDir = path.resolve('..', 'docs');
  }
  if (!fs.existsSync(docsDir)) {
    fs.mkdirSync(docsDir, { recursive: true });
  }

  const reportPath = path.join(docsDir, 'EVALUATION_REPORT.md');
  const markdownReport = generateMarkdownEvaluationReport(evaluation);
  fs.writeFileSync(reportPath, markdownReport, 'utf8');
  console.log(`\n[+] Full verification report saved to: ${reportPath}`);

  // 5. Adaptive Context Replay Output
  printHeader('ADAPTIVE CONTEXT REPLAY: LIVE INCIDENT INSPECTION');
  for (const replay of zeekResult.context_replays.slice(0, 3)) {
    console.log(`\n[ Incident ${replay.incident_id} - Entity: ${replay.source_entity} ]`);
    console.log(`  ├─ Stage 1 (Naive IDS): Score ${replay.naive_stage.raw_score} (${replay.naive_stage.naive_severity})`);
    console.log(`  ├─ Stage 2 (Adaptive):  Score ${replay.context_stage.adjusted_score} (${replay.context_stage.context_severity})`);
    console.log(`  ├─ Delta Assessment:    ${replay.delta_analysis.overall_score_change} (${replay.context_stage.context_status})`);
    for (const rd of replay.delta_analysis.rule_deltas) {
      console.log(`  │   └─ ${rd.rule_name}: ${rd.raw_score} -> ${rd.adjusted_score} (${rd.why_changed})`);
    }
    if (replay.unexplained_evidence.has_unexplained) {
      console.log(`  └─ UNEXPLAINED EVIDENCE: ${replay.unexplained_evidence.count} deviation(s) retained for analyst review!`);
    } else {
      console.log(`  └─ Profile Conformance: Strict match to baseline authorization.`);
    }
  }

  printHeader('SENTINEL AI PIPELINE EXECUTION COMPLETE');
}

if (process.argv[1] && process.argv[1].replace(/\\/g, '/').endsWith('backend/runAnalysis.js')) {
  runCLI();
}
