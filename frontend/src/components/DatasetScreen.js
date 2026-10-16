/**
 * Sentinel AI - Screen 2: Dataset Analysis & Dual-Schema Ingestion
 * - Dataset selector (Zeek Bro, Enterprise Firewall/VPC, Edge Cases)
 * - Interactive Drag-and-Drop CSV dropzone & file picker
 * - Canonical schema mapping preview
 * - Telemetry validation & data quality summary (Accepted, Rejected, Duplicate, Incomplete)
 * - Temporal training/evaluation period info
 * - Clear Analyze button with progress states
 */

export function renderDatasetScreen(container, currentData, currentConfig, onSelectDataset, onUploadCustom, onReAnalyze) {
  const result = currentData?.result || {};
  const audit = result.audit || {};
  const currentDatasetKey = currentData?.dataset || 'zeek';
  const records = result.records || [];

  // Compute time range
  let firstTime = '--';
  let lastTime = '--';
  let durationSec = '--';
  if (records.length > 0 && records[0].timestamp) {
    firstTime = records[0].timestamp;
    lastTime = records[records.length - 1].timestamp;
    try {
      const diffMs = new Date(lastTime).getTime() - new Date(firstTime).getTime();
      durationSec = `${Math.max(0, Math.round(diffMs / 1000))}s`;
    } catch (e) {
      durationSec = 'N/A';
    }
  }

  // Active schema mapping info from currentConfig or defaults
  const schemaMappings = currentConfig?.schemas?.schemas || {};
  const activeSchemaKey = audit.schema_detected || (currentDatasetKey === 'firewall' ? 'enterprise_firewall_vpc' : 'zeek_conn_log');
  const activeSchema = schemaMappings[activeSchemaKey] || {
    name: audit.schema_name || 'Canonical Flow Telemetry',
    mapping: {
      record_id: 'uid / session_id',
      timestamp: 'ts / timestamp',
      src_ip: 'id.orig_h / src_ip',
      src_port: 'id.orig_p / src_port',
      dst_ip: 'id.resp_h / dst_ip',
      dst_port: 'id.resp_p / dst_port',
      protocol: 'proto / protocol',
      bytes_out: 'orig_bytes / bytes_sent',
      bytes_in: 'resp_bytes / bytes_received',
      label: 'label / ground_truth_label'
    }
  };

  const mappingEntries = Object.entries(activeSchema.mapping || {});

  container.innerHTML = `
    <div class="dataset-screen animate-fade-in">
      <!-- Screen Header -->
      <div class="screen-header-row">
        <div>
          <h1 class="screen-title">Datasets & Logs</h1>
          <p class="screen-desc">Import and normalize network flow logs across schemas.</p>
        </div>
        <div class="screen-header-actions">
          <button id="screenAnalyzeBtn" class="btn-stitch-primary">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
            <span>Re-Analyze Log</span>
          </button>
        </div>
      </div>

      <!-- Dataset Selection Tabs -->
      <div class="dataset-selector-tabs">
        <button class="dataset-tab-btn ${currentDatasetKey === 'zeek' ? 'active' : ''}" data-key="zeek">
          <div class="tab-btn-title">Dataset 1: Standard (Zeek)</div>
          <div class="tab-btn-subtitle">56 records &bull; Zeek schema</div>
        </button>
        <button class="dataset-tab-btn ${currentDatasetKey === 'firewall' ? 'active' : ''}" data-key="firewall">
          <div class="tab-btn-title">Dataset 2: Firewall (VPC)</div>
          <div class="tab-btn-subtitle">41 records &bull; Firewall schema</div>
        </button>
        <button class="dataset-tab-btn ${currentDatasetKey === 'edge' ? 'active' : ''}" data-key="edge">
          <div class="tab-btn-title">Dataset 3: Dirty Data</div>
          <div class="tab-btn-subtitle">Edge cases & errors</div>
        </button>
      </div>

      <!-- Main Two-Column Ingestion Workspace -->
      <div class="dataset-workspace-grid">
        <!-- Left: Upload Dropzone & Telemetry File Ingestion -->
        <div class="panel-stitch">
          <div class="panel-header-row">
            <div>
              <h2 class="panel-heading">Upload Network Log (CSV)</h2>
              <p class="panel-subheading">Drop a CSV file or paste text below</p>
            </div>
            <span class="status-tag status-clean">Universal CSV</span>
          </div>

          <!-- Drag and Drop Zone -->
          <div id="dragDropZone" class="drag-drop-area">
            <input type="file" id="datasetFileInput" accept=".csv,.txt" style="display: none;" />
            <div class="drop-icon">
              <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="#A477F5" stroke-width="2">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                <polyline points="17 8 12 3 7 8"/>
                <line x1="12" y1="3" x2="12" y2="15"/>
              </svg>
            </div>
            <div class="drop-text">
              <strong>Drag & drop CSV log file here</strong> or <span class="drop-browse-link" id="browseFileLink">browse files</span>
            </div>
            <div class="drop-hints">Supports Zeek conn.log, Palo Alto, AWS VPC Flow, or custom CSV</div>
          </div>

          <!-- Paste CSV Accordion -->
          <div class="paste-csv-accordion">
            <div class="paste-header" id="togglePasteSection">
              <span>Or paste raw CSV text directly</span>
              <span class="accordion-arrow">&darr;</span>
            </div>
            <div id="pasteBodySection" class="paste-body" style="display: none;">
              <textarea id="rawCsvTextarea" class="stitch-textarea" rows="5" placeholder="ts,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,proto,orig_bytes,resp_bytes,conn_state,label..."></textarea>
              <div class="paste-actions">
                <button id="btnProcessPastedCsv" class="btn-stitch-primary btn-sm">Process & Analyze</button>
              </div>
            </div>
          </div>

          <!-- Temporal Evaluation Window Card -->
          <div class="temporal-info-card">
            <div class="temporal-item">
              <span class="temporal-label">Start Time</span>
              <span class="temporal-value">${firstTime}</span>
            </div>
            <div class="temporal-item">
              <span class="temporal-label">End Time</span>
              <span class="temporal-value">${lastTime}</span>
            </div>
            <div class="temporal-item">
              <span class="temporal-label">Duration</span>
              <span class="temporal-value highlight">${durationSec}</span>
            </div>
          </div>
        </div>

        <!-- Right: Data Quality Summary & Canonical Column Mapping -->
        <div class="dataset-right-column">
          <!-- Data Quality & Validation Summary -->
          <div class="panel-stitch">
            <div class="panel-header-row">
              <div>
                <h2 class="panel-heading">Data Quality Check</h2>
                <p class="panel-subheading">Validation and error inspection</p>
              </div>
              <span class="badge-status-pill badge-violet">${audit.schema_name || 'Active Schema'}</span>
            </div>

            <div class="quality-metrics-grid">
              <div class="quality-card card-accepted">
                <div class="quality-label">Valid Rows</div>
                <div class="quality-num">${audit.parsed_records !== undefined ? audit.parsed_records : records.length}</div>
                <div class="quality-foot">Clean Records</div>
              </div>
              <div class="quality-card card-rejected">
                <div class="quality-label">Skipped Rows</div>
                <div class="quality-num">${audit.malformed_rows || 0}</div>
                <div class="quality-foot">Formatting Errors</div>
              </div>
              <div class="quality-card card-duplicates">
                <div class="quality-label">Duplicates</div>
                <div class="quality-num">${audit.duplicates_suppressed || 0}</div>
                <div class="quality-foot">Repeated Rows</div>
              </div>
              <div class="quality-card card-total">
                <div class="quality-label">Total Rows</div>
                <div class="quality-num">${audit.total_rows !== undefined ? audit.total_rows : records.length}</div>
                <div class="quality-foot">Raw Input Lines</div>
              </div>
            </div>

            <!-- Validation Error Logs if present (e.g. Edge cases) -->
            ${(audit.errors && audit.errors.length > 0) ? `
              <div class="validation-errors-box">
                <div class="validation-errors-title">
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#FF8A48" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                  Edge Cases Handled (${audit.errors.length} Warnings)
                </div>
                <ul class="validation-error-list">
                  ${audit.errors.map(e => `<li><code>${e}</code></li>`).join('')}
                </ul>
              </div>
            ` : `
              <div class="validation-clean-notice">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#34D399" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
                <span>Zero row corruption. All connection records passed schema validation.</span>
              </div>
            `}
          </div>

          <!-- Column Mapping Preview -->
          <div class="panel-stitch">
            <div class="panel-header-row">
              <div>
                <h2 class="panel-heading">Column Mapping</h2>
                <p class="panel-subheading">Translates vendor columns into standard fields</p>
              </div>
              <span class="status-tag status-active">Auto-Mapped</span>
            </div>

            <div class="mapping-table-wrapper">
              <table class="stitch-table">
                <thead>
                  <tr>
                    <th>Standard Field</th>
                    <th>Source Column</th>
                    <th>Data Type</th>
                  </tr>
                </thead>
                <tbody>
                  ${mappingEntries.map(([canon, src]) => `
                    <tr>
                      <td><code class="canon-field">${canon}</code></td>
                      <td><span class="source-field">${src}</span></td>
                      <td><span class="type-pill">${canon.includes('port') || canon.includes('bytes') ? 'Number' : canon.includes('time') ? 'Timestamp' : 'Text'}</span></td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
  `;

  // Attach Event Listeners
  container.querySelectorAll('.dataset-tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const key = btn.getAttribute('data-key');
      onSelectDataset(key);
    });
  });

  const screenAnalyzeBtn = container.querySelector('#screenAnalyzeBtn');
  if (screenAnalyzeBtn) {
    screenAnalyzeBtn.addEventListener('click', onReAnalyze);
  }

  // Drag and Drop & File Browse
  const dropZone = container.querySelector('#dragDropZone');
  const fileInput = container.querySelector('#datasetFileInput');
  const browseLink = container.querySelector('#browseFileLink');

  if (browseLink && fileInput) {
    browseLink.addEventListener('click', () => fileInput.click());
  }

  if (fileInput) {
    fileInput.addEventListener('change', (e) => {
      const file = e.target.files[0];
      if (file) {
        const reader = new FileReader();
        reader.onload = (event) => {
          onUploadCustom(event.target.result);
        };
        reader.readAsText(file);
      }
    });
  }

  if (dropZone) {
    dropZone.addEventListener('dragover', (e) => {
      e.preventDefault();
      dropZone.classList.add('dragover');
    });
    dropZone.addEventListener('dragleave', () => {
      dropZone.classList.remove('dragover');
    });
    dropZone.addEventListener('drop', (e) => {
      e.preventDefault();
      dropZone.classList.remove('dragover');
      const files = e.dataTransfer.files;
      if (files.length > 0) {
        const file = files[0];
        const reader = new FileReader();
        reader.onload = (event) => {
          onUploadCustom(event.target.result);
        };
        reader.readAsText(file);
      }
    });
  }

  // Paste Accordion
  const togglePaste = container.querySelector('#togglePasteSection');
  const pasteBody = container.querySelector('#pasteBodySection');
  const btnProcessPasted = container.querySelector('#btnProcessPastedCsv');
  const textarea = container.querySelector('#rawCsvTextarea');

  if (togglePaste && pasteBody) {
    togglePaste.addEventListener('click', () => {
      const isHidden = pasteBody.style.display === 'none';
      pasteBody.style.display = isHidden ? 'block' : 'none';
      togglePaste.querySelector('.accordion-arrow').innerHTML = isHidden ? '&uarr;' : '&darr;';
    });
  }

  if (btnProcessPasted && textarea) {
    btnProcessPasted.addEventListener('click', () => {
      const content = textarea.value.trim();
      if (!content) {
        alert('Please paste CSV flow content first.');
        return;
      }
      onUploadCustom(content);
    });
  }
}
