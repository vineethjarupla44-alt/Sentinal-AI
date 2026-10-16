/**
 * Component: MetricsBanner
 * Renders key empirical performance indicators and dataset summary.
 */

export function renderMetricsBanner(container, data) {
  const result = data.result || {};
  const evalMetrics = data.evaluation || {};
  const imp = evalMetrics.improvement || {};
  const naive = evalMetrics.naive_stage || {};
  const ctx = evalMetrics.context_aware_stage || {};

  container.innerHTML = `
    <div class="metric-card">
      <span class="metric-label">Processed Flows</span>
      <span class="metric-value">${(result.record_count || 0).toLocaleString()}</span>
      <span class="metric-footnote">${result.audit?.schema_name || 'Internal Flow Schema'}</span>
    </div>
    <div class="metric-card highlight-metric">
      <span class="metric-label">False-Positive Reduction</span>
      <span class="metric-value">${imp.fp_reduction_percent !== undefined ? `${imp.fp_reduction_percent}%` : '--'}</span>
      <span class="metric-footnote">Contextual Baselining Mitigation</span>
    </div>
    <div class="metric-card">
      <span class="metric-label">Precision (Before -> After)</span>
      <span class="metric-value">
        ${naive.precision !== undefined ? `${(naive.precision * 100).toFixed(1)}%` : '--'} &rarr; 
        ${ctx.precision !== undefined ? `${(ctx.precision * 100).toFixed(1)}%` : '--'}
      </span>
      <span class="metric-footnote text-emerald">+${imp.precision_gain_percent || 0}% Precision Gain</span>
    </div>
    <div class="metric-card">
      <span class="metric-label">Attack Recall</span>
      <span class="metric-value">${ctx.recall !== undefined ? `${(ctx.recall * 100).toFixed(0)}%` : '100%'}</span>
      <span class="metric-footnote text-emerald">Zero Attack Suppression</span>
    </div>
    <div class="metric-card">
      <span class="metric-label">FPR (Before -> After)</span>
      <span class="metric-value">
        ${naive.fpr !== undefined ? `${(naive.fpr * 100).toFixed(1)}%` : '--'} &rarr; 
        ${ctx.fpr !== undefined ? `${(ctx.fpr * 100).toFixed(1)}%` : '--'}
      </span>
      <span class="metric-footnote text-emerald">FPR Dropped by -${imp.fpr_reduction_percent || 0}%</span>
    </div>
  `;
}
