/**
 * Sentinel AI - Pure SVG Chart Components
 * High-performance, lightweight, responsive data visualizations
 * Inspired by Google Stitch / reference UI:
 * - Bezier curve area chart (Traffic vs Baseline)
 * - Multi-ring concentric radial gauge (Severity & Classification)
 * - Circular risk score gauge (0-100 prioritization)
 */

/**
 * Generates an interactive smooth Bezier curve network traffic chart
 */
export function renderBezierTrafficChart(container, records = [], options = {}) {
  const width = options.width || 720;
  const height = options.height || 220;
  const padding = { top: 40, right: 30, bottom: 35, left: 45 };

  // Aggregate telemetry records into time buckets
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
      
      // Compute organic traffic curve based on flow density and byte throughput
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

  // Fallback defaults if no records
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

  // Build organic, smooth cubic Bezier path without flat clipping
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

  // Find peak point for callout
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
          <stop offset="0%" stop-color="#A477F5" stop-opacity="0.32"/>
          <stop offset="60%" stop-color="#A477F5" stop-opacity="0.08"/>
          <stop offset="100%" stop-color="#A477F5" stop-opacity="0.0"/>
        </linearGradient>
        <linearGradient id="baselineGradient" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0%" stop-color="#58D7E8" stop-opacity="0.75"/>
          <stop offset="100%" stop-color="#34D399" stop-opacity="0.75"/>
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
      <line x1="${padding.left}" y1="${padding.top + chartH * 0.25}" x2="${width - padding.right}" y2="${padding.top + chartH * 0.25}" stroke="rgba(164, 119, 245, 0.08)" stroke-dasharray="3 3"/>
      <line x1="${padding.left}" y1="${padding.top + chartH * 0.5}" x2="${width - padding.right}" y2="${padding.top + chartH * 0.5}" stroke="rgba(164, 119, 245, 0.08)" stroke-dasharray="3 3"/>
      <line x1="${padding.left}" y1="${padding.top + chartH * 0.75}" x2="${width - padding.right}" y2="${padding.top + chartH * 0.75}" stroke="rgba(164, 119, 245, 0.08)" stroke-dasharray="3 3"/>
      <line x1="${padding.left}" y1="${padding.top + chartH}" x2="${width - padding.right}" y2="${padding.top + chartH}" stroke="rgba(164, 119, 245, 0.15)"/>

      <!-- Traffic Area & Curves -->
      <path d="${areaPath}" fill="url(#trafficGradient)"/>
      <path d="${baselinePath}" fill="none" stroke="url(#baselineGradient)" stroke-width="2" stroke-dasharray="4 4" opacity="0.85"/>
      <path d="${trafficPath}" fill="none" stroke="#A477F5" stroke-width="2.5" filter="url(#neonGlow)"/>

      <!-- X-axis Labels -->
      ${points.map((p, i) => `
        <text x="${getX(i)}" y="${height - 10}" text-anchor="middle" fill="#84729E" font-size="11" font-family="Inter, sans-serif">${p.label}</text>
      `).join('')}

      <!-- Peak Tooltip Callout -->
      <line x1="${peakX}" y1="${peakY}" x2="${peakX}" y2="${padding.top + chartH}" stroke="#FF8A48" stroke-width="1.2" stroke-dasharray="3 3"/>
      <circle cx="${peakX}" cy="${peakY}" r="4.5" fill="#180D28" stroke="#FF8A48" stroke-width="2.5"/>
      <g transform="translate(${Math.min(width - 105, Math.max(padding.left + 5, peakX - 42))}, ${Math.max(6, peakY - 32)})">
        <rect width="84" height="24" rx="6" fill="#24143F" stroke="rgba(255, 138, 72, 0.5)" filter="drop-shadow(0 4px 10px rgba(0,0,0,0.5))"/>
        <text x="42" y="16" text-anchor="middle" fill="#F7F2FF" font-size="10.5" font-weight="600" font-family="Inter, sans-serif">Peak Spike</text>
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
    { label: 'Critical Risk', percent: stats.criticalPercent || 72, color: '#FF8A48', radius: 72 },
    { label: 'High Priority', percent: stats.highPercent || 54, color: '#A477F5', radius: 59 },
    { label: 'Mitigated Benign', percent: stats.mitigatedPercent || 48, color: '#58D7E8', radius: 46 },
    { label: 'Verified Clean', percent: stats.cleanPercent || 30, color: '#34D399', radius: 33 }
  ];

  const ringsSvg = rings.map(r => {
    const circumference = 2 * Math.PI * r.radius;
    // 270 degree arc (3/4 circle)
    const arcLength = circumference * 0.75;
    const progressLength = arcLength * (Math.min(100, Math.max(0, r.percent)) / 100);
    const dashOffset = arcLength - progressLength;

    return `
      <circle
        cx="${center}"
        cy="${center}"
        r="${r.radius}"
        fill="none"
        stroke="rgba(164, 119, 245, 0.12)"
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
      <span style="display: flex; align-items: center; gap: 7px; color: #B9A9D0;">
        <span style="width: 7px; height: 7px; border-radius: 50%; background: ${r.color}; display: inline-block; flex-shrink: 0;"></span>
        ${r.label}
      </span>
      <strong style="color: #F7F2FF; font-family: var(--font-mono); font-size: 11px;">${r.percent}%</strong>
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

  const color = score >= 75 ? '#EF4444' : score >= 50 ? '#FF8A48' : score >= 25 ? '#A477F5' : '#58D7E8';

  return `
    <div style="position: relative; width: ${size}px; height: ${size}px; display: inline-flex; align-items: center; justify-content: center;">
      <svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" style="transform: rotate(-90deg);">
        <circle cx="${center}" cy="${center}" r="${radius}" fill="none" stroke="rgba(164, 119, 245, 0.15)" stroke-width="${strokeWidth}"/>
        <circle cx="${center}" cy="${center}" r="${radius}" fill="none" stroke="${color}" stroke-width="${strokeWidth}"
          stroke-linecap="round" stroke-dasharray="${circumference}" stroke-dashoffset="${offset}"
          style="transition: stroke-dashoffset 0.6s ease;"/>
      </svg>
      <div style="position: absolute; text-align: center;">
        <span style="font-size: 15px; font-weight: 800; font-family: var(--font-mono); color: #F7F2FF;">${score}</span>
      </div>
    </div>
  `;
}
