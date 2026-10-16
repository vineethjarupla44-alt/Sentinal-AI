/**
 * Sentinel AI - Screen 5: Configuration & Trusted Activity
 * Friendly UI explorer for reading and inspecting organizational baselines:
 * - Approved security scanners
 * - Nightly backup schedules
 * - Maintenance windows
 * - Trusted patch servers & domain controllers
 * - Detection thresholds
 * - Schema mappings
 * - JSON viewer with copy functionality
 */

export function renderConfigScreen(container, engineStatus) {
  const config = engineStatus?.config || {};
  const schemas = engineStatus?.schemas?.schemas || {};

  const scanners = config.approved_security_scanners || [];
  const backups = config.large_nightly_backups || [];
  const maintenance = config.maintenance_windows || [];
  const patchServers = config.patch_servers || [];
  const trustedHosts = config.trusted_activity || [];
  const thresholds = config.detection_thresholds || {};

  let activeSubTab = 'scanners';
  let searchTerm = '';

  function renderView() {
    container.innerHTML = `
      <div class="config-screen animate-fade-in">
        <!-- Screen Header -->
        <div class="screen-header-row">
          <div>
            <h1 class="screen-title">Safe Rules & Settings</h1>
            <p class="screen-desc">Manage approved scanners, schedules, and thresholds in external config.json.</p>
          </div>
          <div class="config-actions">
            <button id="copyFullJsonBtn" class="btn-stitch-glass">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
              <span>Copy JSON</span>
            </button>
          </div>
        </div>

        <!-- Subtabs & Search Bar -->
        <div class="config-nav-bar panel-stitch">
          <div class="config-subtabs-row">
            <button class="config-subtab ${activeSubTab === 'scanners' ? 'active' : ''}" data-tab="scanners">
              Scanners (${scanners.length})
            </button>
            <button class="config-subtab ${activeSubTab === 'backups' ? 'active' : ''}" data-tab="backups">
              Backups (${backups.length})
            </button>
            <button class="config-subtab ${activeSubTab === 'maintenance' ? 'active' : ''}" data-tab="maintenance">
              Maintenance (${maintenance.length})
            </button>
            <button class="config-subtab ${activeSubTab === 'patch' ? 'active' : ''}" data-tab="patch">
              Patch & AD (${patchServers.length + trustedHosts.length})
            </button>
            <button class="config-subtab ${activeSubTab === 'thresholds' ? 'active' : ''}" data-tab="thresholds">
              Thresholds
            </button>
            <button class="config-subtab ${activeSubTab === 'json' ? 'active' : ''}" data-tab="json">
              Settings JSON
            </button>
          </div>

          <div class="config-search-box">
            <input type="text" id="configSearchInput" class="stitch-input stitch-input-sm" placeholder="Search rules by IP or tool..." value="${searchTerm}">
          </div>
        </div>

        <!-- Active Subtab Content Panel -->
        <div class="config-content-area">
          ${renderTabContent()}
        </div>
      </div>
    `;

    // Bind event listeners
    container.querySelectorAll('.config-subtab').forEach(tab => {
      tab.addEventListener('click', () => {
        activeSubTab = tab.getAttribute('data-tab');
        renderView();
      });
    });

    const searchInput = container.querySelector('#configSearchInput');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        searchTerm = e.target.value.toLowerCase();
        renderView();
      });
    }

    const copyBtn = container.querySelector('#copyFullJsonBtn');
    if (copyBtn) {
      copyBtn.addEventListener('click', () => {
        navigator.clipboard.writeText(JSON.stringify(config, null, 2));
        copyBtn.querySelector('span').textContent = 'JSON Copied!';
        setTimeout(() => { copyBtn.querySelector('span').textContent = 'Copy Full JSON'; }, 2000);
      });
    }
  }

  function renderTabContent() {
    if (activeSubTab === 'scanners') {
      const filtered = scanners.filter(s => !searchTerm || s.ip.includes(searchTerm) || s.hostname.toLowerCase().includes(searchTerm) || s.vendor.toLowerCase().includes(searchTerm));
      return `
        <div class="config-cards-grid">
          ${filtered.map(s => `
            <div class="panel-stitch profile-card">
              <div class="profile-header">
                <div>
                  <h3 class="profile-title">${s.vendor}</h3>
                  <code class="code-ip">${s.ip}</code> &bull; <span class="profile-host">${s.hostname}</span>
                </div>
                <span class="status-tag status-clean">${Math.round(s.max_mitigation_factor * 100)}% Max Mitigation</span>
              </div>
              <div class="profile-body">
                <div class="profile-row">
                  <span class="profile-label">Authorized Active Schedule (UTC):</span>
                  <span class="profile-value highlight">${String(s.active_schedule_utc.start_hour).padStart(2, '0')}:00 &mdash; ${String(s.active_schedule_utc.end_hour).padStart(2, '0')}:00 UTC</span>
                </div>
                <div class="profile-row">
                  <span class="profile-label">Authorized Scan Ports:</span>
                  <span class="profile-value">${Array.isArray(s.authorized_ports) ? s.authorized_ports.join(', ') : s.authorized_ports}</span>
                </div>
                <div class="profile-row">
                  <span class="profile-label">Rule Tag:</span>
                  <span class="type-pill">${s.tag}</span>
                </div>
              </div>
            </div>
          `).join('') || '<div class="empty-state">No security scanners match the search term.</div>'}
        </div>
      `;
    }

    if (activeSubTab === 'backups') {
      const filtered = backups.filter(b => !searchTerm || b.name.toLowerCase().includes(searchTerm) || b.src_ip.includes(searchTerm) || b.dst_ip.includes(searchTerm));
      return `
        <div class="config-cards-grid">
          ${filtered.map(b => `
            <div class="panel-stitch profile-card">
              <div class="profile-header">
                <div>
                  <h3 class="profile-title">${b.name}</h3>
                  <code class="code-ip">${b.src_ip}</code> &rarr; <code class="code-ip">${b.dst_ip}</code>
                </div>
                <span class="status-tag status-clean">${Math.round(b.max_mitigation_factor * 100)}% Mitigation</span>
              </div>
              <div class="profile-body">
                <div class="profile-row">
                  <span class="profile-label">Scheduled Window (UTC):</span>
                  <span class="profile-value highlight">${String(b.scheduled_window_utc.start_hour).padStart(2, '0')}:00 &mdash; ${String(b.scheduled_window_utc.end_hour).padStart(2, '0')}:00 UTC</span>
                </div>
                <div class="profile-row">
                  <span class="profile-label">Protocol & Port:</span>
                  <span class="profile-value">${b.protocol} / Port ${b.port}</span>
                </div>
                <div class="profile-row">
                  <span class="profile-label">Expected Volume Threshold:</span>
                  <span class="profile-value">&gt; ${(b.expected_min_bytes / 1000000).toFixed(1)} MB</span>
                </div>
              </div>
            </div>
          `).join('') || '<div class="empty-state">No backup schedules match the search term.</div>'}
        </div>
      `;
    }

    if (activeSubTab === 'maintenance') {
      return `
        <div class="config-cards-grid">
          ${maintenance.map(m => `
            <div class="panel-stitch profile-card">
              <div class="profile-header">
                <div>
                  <h3 class="profile-title">${m.name}</h3>
                  <span class="type-pill">${m.id}</span>
                </div>
                <span class="status-tag status-clean">${Math.round(m.mitigation_factor * 100)}% Mitigation</span>
              </div>
              <div class="profile-body">
                <div class="profile-row">
                  <span class="profile-label">Active Days of Week:</span>
                  <span class="profile-value">${m.days_of_week.map(d => ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'][d]).join(', ')}</span>
                </div>
                <div class="profile-row">
                  <span class="profile-label">UTC Maintenance Window:</span>
                  <span class="profile-value highlight">${String(m.start_hour_utc).padStart(2, '0')}:00 &mdash; ${String(m.end_hour_utc).padStart(2, '0')}:00 UTC</span>
                </div>
              </div>
            </div>
          `).join('')}
        </div>
      `;
    }

    if (activeSubTab === 'patch') {
      return `
        <div class="config-cards-grid">
          ${patchServers.map(p => `
            <div class="panel-stitch profile-card">
              <div class="profile-header">
                <div>
                  <h3 class="profile-title">${p.service}</h3>
                  <code class="code-ip">${p.ip}</code> (${p.hostname})
                </div>
                <span class="status-tag status-clean">${Math.round(p.max_mitigation_factor * 100)}% Mitigation</span>
              </div>
              <div class="profile-body">
                <div class="profile-row">
                  <span class="profile-label">Authorized Distribution Ports:</span>
                  <span class="profile-value">${p.ports.join(', ')}</span>
                </div>
                <div class="profile-row">
                  <span class="profile-label">Target Subnets:</span>
                  <span class="profile-value">${p.allowed_dest_subnets.join(', ')}</span>
                </div>
              </div>
            </div>
          `).join('')}

          ${trustedHosts.map(t => `
            <div class="panel-stitch profile-card">
              <div class="profile-header">
                <div>
                  <h3 class="profile-title">${t.role}</h3>
                  <code class="code-ip">${t.ip}</code> (${t.hostname})
                </div>
                <span class="type-pill">Trusted Host</span>
              </div>
              <div class="profile-body">
                <div class="profile-row">
                  <span class="profile-label">Standard Operating Ports:</span>
                  <span class="profile-value">${t.ports.join(', ')}</span>
                </div>
              </div>
            </div>
          `).join('')}
        </div>
      `;
    }

    if (activeSubTab === 'thresholds') {
      const ps = thresholds.port_scan || {};
      const ns = thresholds.network_sweep || {};
      const lm = thresholds.lateral_movement || {};

      return `
        <div class="config-cards-grid">
          <div class="panel-stitch profile-card">
            <h3 class="profile-title">Vertical Port Scan Thresholds</h3>
            <div class="profile-body">
              <div class="profile-row">
                <span class="profile-label">Sliding Time Window:</span>
                <span class="profile-value">${ps.window_seconds}s</span>
              </div>
              <div class="profile-row">
                <span class="profile-label">Min Distinct Ports Trigger:</span>
                <span class="profile-value highlight">${ps.min_distinct_ports} ports</span>
              </div>
              <div class="profile-row">
                <span class="profile-label">High Severity Port Trigger:</span>
                <span class="profile-value">${ps.high_severity_port_count} ports</span>
              </div>
              <div class="profile-row">
                <span class="profile-label">Base Volumetric Score:</span>
                <span class="profile-value">${ps.base_severity_score} pts</span>
              </div>
            </div>
          </div>

          <div class="panel-stitch profile-card">
            <h3 class="profile-title">Horizontal Network Sweep Thresholds</h3>
            <div class="profile-body">
              <div class="profile-row">
                <span class="profile-label">Sliding Time Window:</span>
                <span class="profile-value">${ns.window_seconds}s</span>
              </div>
              <div class="profile-row">
                <span class="profile-label">Min Distinct Target Hosts:</span>
                <span class="profile-value highlight">${ns.min_distinct_hosts} hosts</span>
              </div>
              <div class="profile-row">
                <span class="profile-label">High Severity Host Trigger:</span>
                <span class="profile-value">${ns.high_severity_host_count} hosts</span>
              </div>
              <div class="profile-row">
                <span class="profile-label">Base Volumetric Score:</span>
                <span class="profile-value">${ns.base_severity_score} pts</span>
              </div>
            </div>
          </div>

          <div class="panel-stitch profile-card">
            <h3 class="profile-title">Lateral Movement & Spreading Thresholds</h3>
            <div class="profile-body">
              <div class="profile-row">
                <span class="profile-label">Sliding Time Window:</span>
                <span class="profile-value">${lm.window_seconds}s</span>
              </div>
              <div class="profile-row">
                <span class="profile-label">Admin Port Fanout Threshold:</span>
                <span class="profile-value highlight">${lm.fanout_threshold} targets</span>
              </div>
              <div class="profile-row">
                <span class="profile-label">Monitored Admin Ports:</span>
                <span class="profile-value">${(lm.admin_ports || []).join(', ')} (SSH, SMB, RDP, WinRM)</span>
              </div>
              <div class="profile-row">
                <span class="profile-label">Base Volumetric Score:</span>
                <span class="profile-value">${lm.base_severity_score} pts</span>
              </div>
            </div>
          </div>
        </div>
      `;
    }

    if (activeSubTab === 'json') {
      return `
        <div class="panel-stitch">
          <div class="panel-header-row">
            <div>
              <h3 class="panel-heading">Active Engine Configuration JSON (Live)</h3>
              <p class="panel-subheading">Loaded directly from <code>/api/status</code></p>
            </div>
          </div>
          <pre class="json-code-viewer"><code>${JSON.stringify(config, null, 2)}</code></pre>
        </div>
      `;
    }

    return '';
  }

  renderView();
}
