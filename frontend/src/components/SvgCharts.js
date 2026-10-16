/**
 * Sentinel AI - Pure SVG Chart Components
 * High-performance, lightweight, responsive data visualizations
 * - Bezier curve area chart (Traffic vs Baseline)
 * - Multi-ring concentric radial gauge (Severity & Classification)
 * - Circular risk score gauge (0-100 prioritization)
 * - Host traffic baseline deviation chart (Observed vs Expected envelope)
 * - Beaconing interval pulse timeline (delta t, jitter, periodicity)
 * - Interactive directed network communication graph
 */

/**
 * Generates an interactive smooth Bezier curve network traffic chart
 */
export function renderBezierTrafficChart(container, records = [], options = {}) {
  const width = options.width || 720;
  const height = options.height || 220;
  const padding = { top: 40, right: 30, bottom: 35, left: 45 };

  let points = [];
  if (records.length > 0) {
    const bucketCount = 10;
    const bucketSize = Math.max(1, Math.floor(records.length / bucketCount));
    for (let i = 0; i < bucketCount; i++) {
      const chunk = records.slice(i * bucketSize, (i + 1) * bucketSize);
      if (chunk.length === 0) break;
      const count = chunk.length;
      const totalBytes = chunk.reduce((sum, r) => sum + (r.total_bytes || 0), 0);
      const isMalicious = chunk.some(r => (r.label || '').includes('malicious') || (r.label || '').includes('scan'));
      const timeStr = chunk[0].timestamp ? chunk[0].timestamp.split('T')[1].slice(0, 5) : `T+${i * 5}m`;
      
      const trafficVal = (count * 18) + (totalBytes > 0 ? Math.round(Math.log10(totalBytes + 1) * 22) : 10);
      const baselineVal = Math.round(22 + Math.sin((i / (bucketCount - 1)) * Math.PI) * 14);

      points.push({
        label: timeStr,
        traffic: trafficVal,
        baseline: baselineVal,
        isMalicious
      });
    }
  }

  if (points.length < 2) {
    points = [
      { label: '02:00', traffic: 24, baseline: 22 },
      { label: '02:05', traffic: 38, baseline: 24 },
      { label: '02:10', traffic: 95, baseline: 26 },
      { label: '02:15', traffic: 185, baseline: 28 },
      { label: '02:20', traffic: 120, baseline: 27 },
      { label: '02:25', traffic: 45, baseline: 24 },
      { label: '02:30', traffic: 28, baseline: 22 }
    ];
  }

  const chartW = width - padding.left - padding.right;
  const chartH = height - padding.top - padding.bottom;
  const maxVal = Math.max(80, ...points.map(p => Math.max(p.traffic, p.baseline))) * 1.25;

  const getX = (idx) => padding.left + (idx / (points.length - 1)) * chartW;
  const getY = (val) => padding.top + chartH - (val / maxVal) * chartH;

  function buildSmoothBezier(pts, key) {
    if (pts.length === 0) return '';
    let d = `M ${getX(0)} ${getY(pts[0][key])}`;
    for (let i = 0; i < pts.length - 1; i++) {
      const x0 = getX(i);
      const y0 = getY(pts[i][key]);
      const x1 = getX(i + 1);
      const y1 = getY(pts[i + 1][key]);
      const dx = (x1 - x0) * 0.45;
      d += ` C ${x0 + dx} ${y0}, ${x1 - dx} ${y1}, ${x1} ${y1}`;
    }
    return d;
  }

  const trafficPath = buildSmoothBezier(points, 'traffic');
  const baselinePath = buildSmoothBezier(points, 'baseline');
  const areaPath = `${trafficPath} L ${getX(points.length - 1)} ${padding.top + chartH} L ${getX(0)} ${padding.top + chartH} Z`;

  let peakIdx = 0;
  points.forEach((p, idx) => {
    if (p.traffic > points[peakIdx].traffic) peakIdx = idx;
  });

  const peakX = getX(peakIdx);
  const peakY = getY(points[peakIdx].traffic);

  const svg = `
    <svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="xMidYMid meet" class="traffic-bezier-svg" style="width: 100%; height: auto; display: block;">
      <defs>
        <linearGradient id="trafficGradient" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="#69E2C2" stop-opacity="0.32"/>
          <stop offset="60%" stop-color="#69E2C2" stop-opacity="0.08"/>
          <stop offset="100%" stop-color="#69E2C2" stop-opacity="0.0"/>
        </linearGradient>
        <linearGradient id="baselineGradient" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0%" stop-color="#65D9DF" stop-opacity="0.75"/>
          <stop offset="100%" stop-color="#4ADE80" stop-opacity="0.75"/>
        </linearGradient>
        <filter id="neonGlow" x="-20%" y="-20%" width="140%" height="140%">
          <feGaussianBlur stdDeviation="2.5" result="blur"/>
          <feMerge>
            <feMergeNode in="blur"/>
            <feMergeNode in="SourceGraphic"/>
          </feMerge>
        </filter>
      </defs>

      <!-- Grid lines -->
      <line x1="${padding.left}" y1="${padding.top + chartH * 0.25}" x2="${width - padding.right}" y2="${padding.top + chartH * 0.25}" stroke="rgba(105, 226, 194, 0.08)" stroke-dasharray="3 3"/>
      <line x1="${padding.left}" y1="${padding.top + chartH * 0.5}" x2="${width - padding.right}" y2="${padding.top + chartH * 0.5}" stroke="rgba(105, 226, 194, 0.08)" stroke-dasharray="3 3"/>
      <line x1="${padding.left}" y1="${padding.top + chartH * 0.75}" x2="${width - padding.right}" y2="${padding.top + chartH * 0.75}" stroke="rgba(105, 226, 194, 0.08)" stroke-dasharray="3 3"/>
      <line x1="${padding.left}" y1="${padding.top + chartH}" x2="${width - padding.right}" y2="${padding.top + chartH}" stroke="rgba(105, 226, 194, 0.15)"/>

      <!-- Traffic Area & Curves -->
      <path d="${areaPath}" fill="url(#trafficGradient)"/>
      <path d="${baselinePath}" fill="none" stroke="url(#baselineGradient)" stroke-width="2" stroke-dasharray="4 4" opacity="0.85"/>
      <path d="${trafficPath}" fill="none" stroke="#69E2C2" stroke-width="2.5" filter="url(#neonGlow)"/>

      <!-- X-axis Labels -->
      ${points.map((p, i) => `
        <text x="${getX(i)}" y="${height - 10}" text-anchor="middle" fill="#688A85" font-size="11" font-family="Inter, sans-serif">${p.label}</text>
      `).join('')}

      <!-- Peak Tooltip Callout -->
      <line x1="${peakX}" y1="${peakY}" x2="${peakX}" y2="${padding.top + chartH}" stroke="#FF8057" stroke-width="1.2" stroke-dasharray="3 3"/>
      <circle cx="${peakX}" cy="${peakY}" r="4.5" fill="#0A1517" stroke="#FF8057" stroke-width="2.5"/>
      <g transform="translate(${Math.min(width - 105, Math.max(padding.left + 5, peakX - 42))}, ${Math.max(6, peakY - 32)})">
        <rect width="84" height="24" rx="6" fill="#102B2E" stroke="rgba(255, 128, 87, 0.5)" filter="drop-shadow(0 4px 10px rgba(0,0,0,0.5))"/>
        <text x="42" y="16" text-anchor="middle" fill="#E6F5F2" font-size="10.5" font-weight="600" font-family="Inter, sans-serif">Peak Spike</text>
      </g>
    </svg>
  `;

  container.innerHTML = svg;
}

/**
 * Generates a concentric multi-ring circular gauge matching Reference Image 1
 */
export function renderConcentricRadialGauge(container, stats = {}) {
  const size = 190;
  const strokeWidth = 8;
  const center = size / 2;

  const rings = [
    { label: 'Critical Risk', percent: stats.criticalPercent || 72, color: '#FF8057', radius: 72 },
    { label: 'High Priority', percent: stats.highPercent || 54, color: '#69E2C2', radius: 59 },
    { label: 'Mitigated Benign', percent: stats.mitigatedPercent || 48, color: '#65D9DF', radius: 46 },
    { label: 'Verified Clean', percent: stats.cleanPercent || 30, color: '#4ADE80', radius: 33 }
  ];

  const ringsSvg = rings.map(r => {
    const circumference = 2 * Math.PI * r.radius;
    const arcLength = circumference * 0.75;
    const progressLength = arcLength * (Math.min(100, Math.max(0, r.percent)) / 100);
    const dashOffset = arcLength - progressLength;

    return `
      <circle
        cx="${center}"
        cy="${center}"
        r="${r.radius}"
        fill="none"
        stroke="rgba(105, 226, 194, 0.12)"
        stroke-width="${strokeWidth}"
        stroke-linecap="round"
        stroke-dasharray="${arcLength} ${circumference}"
        transform="rotate(135 ${center} ${center})"
      />
      <circle
        cx="${center}"
        cy="${center}"
        r="${r.radius}"
        fill="none"
        stroke="${r.color}"
        stroke-width="${strokeWidth}"
        stroke-linecap="round"
        stroke-dasharray="${arcLength} ${circumference}"
        stroke-dashoffset="${dashOffset}"
        transform="rotate(135 ${center} ${center})"
        style="transition: stroke-dashoffset 0.8s cubic-bezier(0.16, 1, 0.3, 1);"
      />
    `;
  }).join('');

  const legendHtml = rings.map(r => `
    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 7px; font-size: 11.5px;">
      <span style="display: flex; align-items: center; gap: 7px; color: #A2C2BC;">
        <span style="width: 7px; height: 7px; border-radius: 50%; background: ${r.color}; display: inline-block; flex-shrink: 0;"></span>
        ${r.label}
      </span>
      <strong style="color: #E6F5F2; font-family: var(--font-mono); font-size: 11px;">${r.percent}%</strong>
    </div>
  `).join('');

  container.innerHTML = `
    <div style="display: flex; align-items: center; gap: 14px; justify-content: center; width: 100%;">
      <svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" style="flex-shrink: 0;">
        ${ringsSvg}
      </svg>
      <div style="flex: 1; min-width: 125px;">
        ${legendHtml}
      </div>
    </div>
  `;
}

/**
 * Generates circular risk score gauge for an incident (0-100)
 */
export function renderCircularScore(score, maxScore = 100, size = 68) {
  const strokeWidth = 6;
  const radius = (size - strokeWidth) / 2;
  const center = size / 2;
  const circumference = 2 * Math.PI * radius;
  const pct = Math.min(100, Math.max(0, (score / maxScore) * 100));
  const offset = circumference - (pct / 100) * circumference;

  const color = score >= 75 ? '#F87171' : score >= 50 ? '#FF8057' : score >= 25 ? '#69E2C2' : '#65D9DF';

  return `
    <div style="position: relative; width: ${size}px; height: ${size}px; display: inline-flex; align-items: center; justify-content: center;">
      <svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" style="transform: rotate(-90deg);">
        <circle cx="${center}" cy="${center}" r="${radius}" fill="none" stroke="rgba(105, 226, 194, 0.15)" stroke-width="${strokeWidth}"/>
        <circle cx="${center}" cy="${center}" r="${radius}" fill="none" stroke="${color}" stroke-width="${strokeWidth}"
          stroke-linecap="round" stroke-dasharray="${circumference}" stroke-dashoffset="${offset}"
          style="transition: stroke-dashoffset 0.6s ease;"/>
      </svg>
      <div style="position: absolute; text-align: center;">
        <span style="font-size: 15px; font-weight: 800; font-family: var(--font-mono); color: #E6F5F2;">${score}</span>
      </div>
    </div>
  `;
}

/**
 * DELIVERABLE 2: Host Traffic versus Baseline Deviation Chart
 * Renders an SVG comparison of observed host metrics against the learned normal baseline envelope
 */
export function renderHostDeviationChart(container, deviationData) {
  if (!deviationData || deviationData.status === 'INSUFFICIENT_HISTORY') {
    container.innerHTML = `
      <div class="empty-state-notice">
        <div style="font-size: 13px; font-weight: 700; color: #FF8057; margin-bottom: 4px;">Baseline In Progress (Insufficient History)</div>
        <div style="font-size: 12px; color: var(--text-secondary);">${deviationData?.explanation || 'Minimum 3 historical observations required to establish statistical baseline.'}</div>
      </div>
    `;
    return;
  }

  const devs = deviationData.deviations || [];
  const width = 680;
  const height = 220;
  const padding = { top: 30, right: 30, bottom: 40, left: 60 };

  const chartW = width - padding.left - padding.right;
  const chartH = height - padding.top - padding.bottom;
  const barGroupWidth = chartW / devs.length;
  const barWidth = Math.min(36, barGroupWidth * 0.35);

  const barsSvg = devs.map((d, i) => {
    const xCenter = padding.left + i * barGroupWidth + barGroupWidth / 2;
    const xExp = xCenter - barWidth - 4;
    const xObs = xCenter + 4;

    // Normalize height relative to the max of observed or expected for that metric
    const maxVal = Math.max(d.observed, d.expected, 1) * 1.25;
    const hExp = (d.expected / maxVal) * chartH;
    const hObs = (d.observed / maxVal) * chartH;

    const yExp = padding.top + chartH - hExp;
    const yObs = padding.top + chartH - hObs;

    const obsColor = d.is_anomalous ? (d.is_mitigated ? '#4ADE80' : '#FF8057') : '#69E2C2';

    return `
      <g class="dev-bar-group">
        <!-- Expected Normal Bar -->
        <rect x="${xExp}" y="${yExp}" width="${barWidth}" height="${hExp}" rx="4" fill="rgba(101, 217, 223, 0.4)" stroke="#65D9DF" stroke-width="1.2"/>
        
        <!-- Observed Value Bar -->
        <rect x="${xObs}" y="${yObs}" width="${barWidth}" height="${hObs}" rx="4" fill="${obsColor}" stroke="${d.is_anomalous ? '#FFA39E' : '#A8F5E1'}" stroke-width="1.5"/>

        <!-- Metric Label -->
        <text x="${xCenter}" y="${height - 12}" text-anchor="middle" fill="#A2C2BC" font-size="11" font-weight="600">${d.metric}</text>

        <!-- Deviation Badge -->
        <text x="${xObs + barWidth / 2}" y="${Math.max(14, yObs - 8)}" text-anchor="middle" fill="${obsColor}" font-size="10" font-weight="800" font-family="var(--font-mono)">
          ${d.deviation_percent >= 0 ? `+${d.deviation_percent}%` : `${d.deviation_percent}%`}
        </text>
      </g>
    `;
  }).join('');

  container.innerHTML = `
    <div style="width: 100%;">
      <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px; font-size: 12px;">
        <div style="color: var(--text-secondary);">
          <strong style="color: var(--text-primary);">${deviationData.host_ip}</strong> &bull; Status: 
          <span class="status-tag ${deviationData.has_anomaly ? 'status-alert' : 'status-active'}">${deviationData.status}</span>
        </div>
        <div style="display: flex; align-items: center; gap: 14px;">
          <span style="display: flex; align-items: center; gap: 5px;"><span style="width: 10px; height: 10px; background: rgba(101, 217, 223, 0.5); border: 1px solid #65D9DF; border-radius: 2px;"></span> Expected Normal</span>
          <span style="display: flex; align-items: center; gap: 5px;"><span style="width: 10px; height: 10px; background: #69E2C2; border-radius: 2px;"></span> Observed</span>
          <span style="display: flex; align-items: center; gap: 5px;"><span style="width: 10px; height: 10px; background: #FF8057; border-radius: 2px;"></span> Anomalous Breach</span>
        </div>
      </div>

      <svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="xMidYMid meet" style="width: 100%; height: auto; display: block; background: rgba(10, 21, 23, 0.4); border-radius: 12px; border: 1px solid var(--border-card);">
        <!-- Base line -->
        <line x1="${padding.left}" y1="${padding.top + chartH}" x2="${width - padding.right}" y2="${padding.top + chartH}" stroke="rgba(105, 226, 194, 0.2)"/>
        ${barsSvg}
      </svg>

      <div style="margin-top: 10px; padding: 10px 14px; background: rgba(16, 33, 36, 0.7); border-radius: 8px; border: 1px solid var(--border-subtle); font-size: 11.5px; color: var(--text-secondary); line-height: 1.5;">
        <strong style="color: #65D9DF;">Forensic Rationale:</strong> ${deviationData.explanation}
      </div>
    </div>
  `;
}

/**
 * DELIVERABLE 3: Candidate Beaconing Interval Pulse Timeline
 * Visualizes repeated connection intervals, jitter, and statistical regularity
 */
export function renderBeaconIntervalChart(container, beaconFindings = []) {
  if (!beaconFindings || beaconFindings.length === 0) {
    container.innerHTML = `
      <div class="empty-state-notice">
        <div style="font-size: 13px; font-weight: 700; color: #69E2C2; margin-bottom: 4px;">Zero Automated Beaconing Detected</div>
        <div style="font-size: 12px; color: var(--text-secondary);">No recurring outbound channels or low-jitter periodic keepalive patterns observed for this entity.</div>
      </div>
    `;
    return;
  }

  const primary = beaconFindings[0];
  const dps = primary.interval_datapoints || [];
  const width = 680;
  const height = 180;
  const padding = { top: 25, right: 30, bottom: 35, left: 50 };

  const chartW = width - padding.left - padding.right;
  const chartH = height - padding.top - padding.bottom;

  const maxInterval = Math.max(10, ...dps.map(d => d.interval_seconds)) * 1.2;
  const getX = (idx) => padding.left + (idx / Math.max(1, dps.length - 1)) * chartW;
  const getY = (val) => padding.top + chartH - (val / maxInterval) * chartH;

  const meanY = getY(primary.metrics.mean_interval_seconds);

  const ticksSvg = dps.map((d, i) => {
    const x = getX(i);
    const y = getY(d.interval_seconds);
    const isSusp = primary.is_suspicious;
    const dotColor = isSusp ? '#FF8057' : '#69E2C2';

    return `
      <!-- Interval pulse stem -->
      <line x1="${x}" y1="${padding.top + chartH}" x2="${x}" y2="${y}" stroke="${isSusp ? 'rgba(255, 128, 87, 0.4)' : 'rgba(105, 226, 194, 0.4)'}" stroke-width="1.5" stroke-dasharray="2 2"/>
      <!-- Pulse bead -->
      <circle cx="${x}" cy="${y}" r="4" fill="${dotColor}" stroke="#0A1517" stroke-width="1.5"/>
      <text x="${x}" y="${Math.max(12, y - 6)}" text-anchor="middle" fill="#E6F5F2" font-size="9" font-family="var(--font-mono)">${d.interval_seconds}s</text>
    `;
  }).join('');

  container.innerHTML = `
    <div style="width: 100%;">
      <!-- Header Metrics Strip -->
      <div style="display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin-bottom: 12px;">
        <div style="background: rgba(16, 33, 36, 0.7); padding: 8px 12px; border-radius: 8px; border: 1px solid var(--border-card);">
          <div style="font-size: 10px; color: var(--text-muted); text-transform: uppercase;">Mean Interval</div>
          <div style="font-size: 15px; font-weight: 800; font-family: var(--font-mono); color: #69E2C2;">${primary.metrics.mean_interval_seconds}s</div>
        </div>
        <div style="background: rgba(16, 33, 36, 0.7); padding: 8px 12px; border-radius: 8px; border: 1px solid var(--border-card);">
          <div style="font-size: 10px; color: var(--text-muted); text-transform: uppercase;">Median Interval</div>
          <div style="font-size: 15px; font-weight: 800; font-family: var(--font-mono); color: #65D9DF;">${primary.metrics.median_interval_seconds}s</div>
        </div>
        <div style="background: rgba(16, 33, 36, 0.7); padding: 8px 12px; border-radius: 8px; border: 1px solid var(--border-card);">
          <div style="font-size: 10px; color: var(--text-muted); text-transform: uppercase;">Interval Jitter (CV)</div>
          <div style="font-size: 15px; font-weight: 800; font-family: var(--font-mono); color: ${primary.metrics.coefficient_of_variation <= 0.20 ? '#FF8057' : '#4ADE80'};">
            ${primary.metrics.coefficient_of_variation} (${primary.metrics.jitter_pct}%)
          </div>
        </div>
        <div style="background: rgba(16, 33, 36, 0.7); padding: 8px 12px; border-radius: 8px; border: 1px solid var(--border-card);">
          <div style="font-size: 10px; color: var(--text-muted); text-transform: uppercase;">Repetitions</div>
          <div style="font-size: 15px; font-weight: 800; font-family: var(--font-mono); color: #E6F5F2;">${primary.repetition_count} flows</div>
        </div>
        <div style="background: rgba(16, 33, 36, 0.7); padding: 8px 12px; border-radius: 8px; border: 1px solid var(--border-card);">
          <div style="font-size: 10px; color: var(--text-muted); text-transform: uppercase;">Verdict</div>
          <div style="font-size: 11px; font-weight: 800; color: ${primary.is_suspicious ? '#FFA39E' : '#4ADE80'};">${primary.verdict}</div>
        </div>
      </div>

      <!-- Pulse SVG Timeline -->
      <svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="xMidYMid meet" style="width: 100%; height: auto; display: block; background: rgba(10, 21, 23, 0.4); border-radius: 12px; border: 1px solid var(--border-card);">
        <!-- Mean baseline dashed guide -->
        <line x1="${padding.left}" y1="${meanY}" x2="${width - padding.right}" y2="${meanY}" stroke="#65D9DF" stroke-dasharray="4 4" stroke-width="1"/>
        <text x="${width - padding.right - 5}" y="${meanY - 5}" text-anchor="end" fill="#65D9DF" font-size="9" font-family="var(--font-mono)">Mean: ${primary.metrics.mean_interval_seconds}s</text>

        <!-- Axis base -->
        <line x1="${padding.left}" y1="${padding.top + chartH}" x2="${width - padding.right}" y2="${padding.top + chartH}" stroke="rgba(105, 226, 194, 0.2)"/>
        
        ${ticksSvg}
      </svg>

      <div style="margin-top: 10px; padding: 10px 14px; background: rgba(16, 33, 36, 0.7); border-radius: 8px; border: 1px solid var(--border-subtle); font-size: 11.5px; color: var(--text-secondary); line-height: 1.5;">
        <strong style="color: ${primary.is_suspicious ? '#FF8057' : '#69E2C2'};">Behavioral Classification:</strong> ${primary.rationale}
      </div>
    </div>
  `;
}

/**
 * DELIVERABLE 5: Interactive Directed Network Communication Graph
 * Renders communicating hosts as nodes and traffic flows as directed edges with thickness proportional to data volume
 */
export function renderNetworkCommunicationGraph(container, graphData, onSelectNodeOrEdge) {
  if (!graphData || !graphData.nodes || graphData.nodes.length === 0) {
    container.innerHTML = `
      <div class="empty-state-notice">
        <div style="font-size: 13px; font-weight: 700; color: var(--text-primary); margin-bottom: 4px;">Zero Topology Data</div>
        <div style="font-size: 12px; color: var(--text-secondary);">No network graph nodes available for this incident.</div>
      </div>
    `;
    return;
  }

  const nodes = graphData.nodes;
  const edges = graphData.edges;

  const width = 680;
  const height = 300;

  // Source node at left-center
  const srcNode = nodes.find(n => n.is_source) || nodes[0];
  const targetNodes = nodes.filter(n => n.id !== srcNode.id);

  const srcPos = { x: 130, y: height / 2 };

  // Arrange target nodes radially or rightwards
  const targetPositions = new Map();
  targetNodes.forEach((t, i) => {
    const total = targetNodes.length;
    const yStep = (height - 80) / Math.max(1, total - 1);
    const y = total === 1 ? height / 2 : 40 + i * yStep;
    const x = 520;
    targetPositions.set(t.id, { x, y });
  });

  // Build edges SVG
  const edgesSvg = edges.map(e => {
    const p1 = e.source === srcNode.id ? srcPos : (targetPositions.get(e.source) || srcPos);
    const p2 = e.target === srcNode.id ? srcPos : (targetPositions.get(e.target) || { x: 520, y: height / 2 });

    const dx = p2.x - p1.x;
    const dy = p2.y - p1.y;
    const cx1 = p1.x + dx * 0.45;
    const cy1 = p1.y;
    const cx2 = p1.x + dx * 0.55;
    const cy2 = p2.y;

    const pathD = `M ${p1.x} ${p1.y} C ${cx1} ${cy1}, ${cx2} ${cy2}, ${p2.x} ${p2.y}`;
    const strokeColor = e.is_suspicious ? '#FF8057' : '#65D9DF';

    return `
      <path
        d="${pathD}"
        fill="none"
        stroke="${strokeColor}"
        stroke-width="${e.weight || 2}"
        stroke-opacity="0.75"
        marker-end="url(#arrowHead${e.is_suspicious ? 'Alert' : 'Normal'})"
        class="interactive-graph-edge"
        data-id="${e.id}"
        style="cursor: pointer; transition: stroke-width 0.2s, stroke-opacity 0.2s;"
      />
    `;
  }).join('');

  // Build nodes SVG
  const nodesSvg = nodes.map(n => {
    const pos = n.is_source ? srcPos : (targetPositions.get(n.id) || { x: 520, y: height / 2 });
    const isSrc = n.is_source;
    const fillColor = isSrc ? (n.is_suspicious ? '#1E2D2B' : '#102B2E') : '#102124';
    const strokeColor = n.is_suspicious ? (isSrc ? '#FF8057' : '#FFA39E') : '#69E2C2';
    const radius = isSrc ? 22 : 16;

    return `
      <g class="interactive-graph-node" data-id="${n.id}" style="cursor: pointer;">
        <!-- Pulsing halo for source -->
        ${isSrc ? `<circle cx="${pos.x}" cy="${pos.y}" r="${radius + 7}" fill="none" stroke="${strokeColor}" stroke-opacity="0.3" stroke-width="1.5" class="pulse-dot"/>` : ''}
        
        <circle cx="${pos.x}" cy="${pos.y}" r="${radius}" fill="${fillColor}" stroke="${strokeColor}" stroke-width="2"/>
        
        <!-- Icon / letter in center -->
        <text x="${pos.x}" y="${pos.y + 4}" text-anchor="middle" fill="#FFFFFF" font-size="${isSrc ? '11' : '9'}" font-weight="700">
          ${isSrc ? 'SRC' : 'DST'}
        </text>

        <!-- IP label -->
        <text x="${pos.x}" y="${pos.y + radius + 14}" text-anchor="middle" fill="#E6F5F2" font-size="10.5" font-family="var(--font-mono)" font-weight="600">
          ${n.id}
        </text>

        <!-- Role tag -->
        <text x="${pos.x}" y="${pos.y + radius + 26}" text-anchor="middle" fill="#A2C2BC" font-size="9">
          ${n.role}
        </text>
      </g>
    `;
  }).join('');

  container.innerHTML = `
    <div style="width: 100%;">
      <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px; font-size: 12px;">
        <span style="color: var(--text-secondary);">
          Topology: <strong style="color: var(--text-primary);">${nodes.length} Hosts</strong> &bull; <strong style="color: var(--text-primary);">${edges.length} Active Channels</strong>
        </span>
        <div style="display: flex; align-items: center; gap: 12px;">
          <span style="display: flex; align-items: center; gap: 5px;"><span style="width: 8px; height: 8px; border-radius: 50%; background: #FF8057;"></span> Suspicious Edge</span>
          <span style="display: flex; align-items: center; gap: 5px;"><span style="width: 8px; height: 8px; border-radius: 50%; background: #65D9DF;"></span> Standard Edge</span>
          <span style="color: var(--text-muted); font-size: 11px;">(Click any host or link to inspect)</span>
        </div>
      </div>

      <svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="xMidYMid meet" style="width: 100%; height: auto; display: block; background: rgba(10, 21, 23, 0.4); border-radius: 12px; border: 1px solid var(--border-card);">
        <defs>
          <marker id="arrowHeadNormal" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto">
            <path d="M 0 1 L 8 5 L 0 9 z" fill="#65D9DF"/>
          </marker>
          <marker id="arrowHeadAlert" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto">
            <path d="M 0 1 L 8 5 L 0 9 z" fill="#FF8057"/>
          </marker>
        </defs>

        <!-- Edges -->
        ${edgesSvg}

        <!-- Nodes -->
        ${nodesSvg}
      </svg>

      <!-- Inspector card below graph -->
      <div id="graphElementInspector" style="margin-top: 10px; padding: 10px 14px; background: rgba(16, 33, 36, 0.7); border-radius: 8px; border: 1px solid var(--border-subtle); font-size: 11.5px; color: var(--text-secondary);">
        <strong style="color: #65D9DF;">Topology Inspector:</strong> Click on any computer node or communication arrow to view connection details, ports, and data volume.
      </div>
    </div>
  `;

  // Attach interactive node/edge click handlers
  const inspectorBox = container.querySelector('#graphElementInspector');

  container.querySelectorAll('.interactive-graph-node').forEach(elem => {
    elem.addEventListener('click', () => {
      const id = elem.getAttribute('data-id');
      const node = nodes.find(n => n.id === id);
      if (node && inspectorBox) {
        inspectorBox.innerHTML = `
          <strong style="color: #69E2C2;">Host Node:</strong> <span style="font-family: var(--font-mono); color: #FFFFFF;">${node.id}</span> &bull; 
          Role: <strong style="color: #A8F5E1;">${node.role}</strong> &bull; 
          Traffic: <strong>${(node.byte_volume || 0).toLocaleString()} B</strong> (${node.flow_count || 0} flows) &bull; 
          Threat Status: <span class="status-tag ${node.is_suspicious ? 'status-alert' : 'status-active'}">${node.is_suspicious ? 'Flagged Suspect' : 'Normal'}</span>
        `;
      }
    });
  });

  container.querySelectorAll('.interactive-graph-edge').forEach(elem => {
    elem.addEventListener('click', () => {
      const id = elem.getAttribute('data-id');
      const edge = edges.find(e => e.id === id);
      if (edge && inspectorBox) {
        inspectorBox.innerHTML = `
          <strong style="color: #FF8057;">Communication Link:</strong> <span style="font-family: var(--font-mono); color: #FFFFFF;">${edge.source} &rarr; ${edge.target}</span> &bull; 
          Ports Contacted: <strong style="color: #65D9DF;">[${edge.ports.join(', ')}]</strong> (${edge.protocols.join(', ')}) &bull; 
          Data Transferred: <strong>${(edge.byte_volume || 0).toLocaleString()} B</strong> across ${edge.flow_count} flow(s) &bull; 
          Link Classification: <span class="status-tag ${edge.is_suspicious ? 'status-alert' : 'status-active'}">${edge.is_suspicious ? 'Suspicious Channel' : 'Benign Channel'}</span>
        `;
      }
    });
  });
}
