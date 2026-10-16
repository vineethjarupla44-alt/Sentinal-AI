/**
 * Sentinel AI - Modern Vertical Left Sidebar Navigation
 * Transforms the application navigation into a sleek vertical sidebar matching the Google Stitch aesthetic.
 */

export function renderNavigation(container, currentScreen, onNavigate, onDatasetChange, onUploadClick, onRefreshClick) {
  // Preserve selected dataset value across re-renders if previously set
  const prevSelectedDataset = container.querySelector('#globalDatasetSelect')?.value;

  const screens = [
    { id: 'dashboard', label: 'Dashboard', icon: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>' },
    { id: 'dataset', label: 'Datasets', icon: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>' },
    { id: 'investigation', label: 'Threats', icon: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>' },
    { id: 'replay', label: 'Smart Filter', signature: true, icon: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polygon points="10 8 16 12 10 16 10 8"/></svg>' },
    { id: 'config', label: 'Safe Rules', icon: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>' },
    { id: 'reports', label: 'Reports', icon: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>' }
  ];

  container.innerHTML = `
    <div class="sidebar-shell">
      <!-- Top Brand Header -->
      <div class="sidebar-header">
        <div class="nav-brand">
          <div class="nav-logo-mark">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M12 2L2 7l10 5 10-5-10-5z" stroke="#C5A4FF"/>
              <path d="M2 17l10 5 10-5" stroke="#A477F5"/>
              <path d="M2 12l10 5 10-5" stroke="#58D7E8"/>
            </svg>
          </div>
          <div class="nav-brand-text">
            <div class="nav-title-row">
              <span class="nav-title">SENTINEL AI</span>
              <span class="nav-badge-pill">v1.0</span>
            </div>
            <span class="nav-subtitle">Smart Threat Shield</span>
          </div>
        </div>
      </div>

      <div class="sidebar-divider"></div>

      <!-- Main Navigation Menu -->
      <div class="sidebar-nav-section">
        <div class="sidebar-section-label">MENU</div>
        <nav class="sidebar-nav" aria-label="Main Navigation">
          ${screens.map(s => `
            <button class="nav-pill-btn ${currentScreen === s.id ? 'active' : ''} ${s.signature ? 'is-signature' : ''}" data-screen="${s.id}">
              <span class="nav-pill-icon">${s.icon}</span>
              <span class="nav-pill-text">${s.label}</span>
              ${s.signature ? '<span class="signature-sparkle">★</span>' : ''}
            </button>
          `).join('')}
        </nav>
      </div>

      <div class="sidebar-divider"></div>

      <!-- Telemetry Dataset & Pipeline Actions -->
      <div class="sidebar-telemetry-section">
        <div class="sidebar-section-label">DATASET</div>
        <div class="schema-select-wrapper sidebar-select-wrapper">
          <span class="schema-icon-dot"></span>
          <select id="globalDatasetSelect" class="schema-dropdown-select sidebar-dropdown" aria-label="Select Telemetry Dataset">
            <option value="zeek">Dataset 1: Standard (Zeek)</option>
            <option value="firewall">Dataset 2: Firewall (VPC)</option>
            <option value="edge">Dataset 3: Dirty Data (Edge)</option>
          </select>
        </div>

        <div class="sidebar-action-buttons">
          <button id="navUploadBtn" class="btn-stitch-glass sidebar-btn" title="Upload custom CSV telemetry">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
            <span>Upload CSV</span>
          </button>

          <button id="navRefreshBtn" class="btn-stitch-gradient sidebar-btn" title="Re-run telemetry detection pipeline">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 2v6h-6M3 12a9 9 0 0 1 15-6.7L21 8M3 22v-6h6M21 12a9 9 0 0 1-15 6.7L3 16"/></svg>
            <span>Run Scan</span>
          </button>
        </div>
      </div>

      <!-- Sidebar Footer Status -->
      <div class="sidebar-footer">
        <div class="sidebar-status-card">
          <div class="nav-status-pill" title="Backend connection active">
            <span class="status-indicator-dot"></span>
            <span class="status-text">ONLINE</span>
          </div>
          <span class="sidebar-engine-tag">Air-Gapped & Secure</span>
        </div>
      </div>
    </div>
  `;

  // Restore dataset dropdown selection if it existed
  if (prevSelectedDataset) {
    const datasetSelect = container.querySelector('#globalDatasetSelect');
    if (datasetSelect && Array.from(datasetSelect.options).some(o => o.value === prevSelectedDataset)) {
      datasetSelect.value = prevSelectedDataset;
    }
  }

  // Attach event listeners
  container.querySelectorAll('.nav-pill-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const screenId = btn.getAttribute('data-screen');
      onNavigate(screenId);
    });
  });

  const datasetSelect = container.querySelector('#globalDatasetSelect');
  if (datasetSelect) {
    datasetSelect.addEventListener('change', (e) => {
      onDatasetChange(e.target.value);
    });
  }

  const uploadBtn = container.querySelector('#navUploadBtn');
  if (uploadBtn) {
    uploadBtn.addEventListener('click', onUploadClick);
  }

  const refreshBtn = container.querySelector('#navRefreshBtn');
  if (refreshBtn) {
    refreshBtn.addEventListener('click', onRefreshClick);
  }
}
