/**
 * TraceGuard - UploadModal Component
 * Modern glassmorphic modal matching Google Stitch aesthetic
 * Allows analysts to paste or upload telemetry for normalization & detection.
 */

export function createUploadModal(onUploadSubmit) {
  const modal = document.createElement('div');
  modal.className = 'modal-backdrop';
  modal.style.display = 'none';

  modal.innerHTML = `
    <div class="modal-box animate-fade-in">
      <div class="modal-header">
        <div>
          <h3 class="modal-title">Ingest Network Flow Telemetry</h3>
          <p class="modal-desc">Upload a CSV dataset or paste flow records. The normalizer maps vendor headers into canonical FlowRecord schema.</p>
        </div>
        <button class="modal-close-btn" id="closeUploadModal" aria-label="Close modal">&times;</button>
      </div>

      <div class="modal-body">
        <div class="form-group">
          <label class="form-label" for="modalSchemaSelect">Schema Mapping Strategy:</label>
          <select id="modalSchemaSelect" class="stitch-select">
            <option value="">Auto-Detect Headers (Recommended)</option>
            <option value="zeek_conn_log">Schema 1: Zeek / Bro conn.log (CSV)</option>
            <option value="enterprise_firewall_vpc">Schema 2: Enterprise Firewall / VPC Flow</option>
          </select>
        </div>

        <div class="form-group">
          <label class="form-label" for="modalFileInput">Select Flow Dataset (.csv or .txt):</label>
          <input type="file" id="modalFileInput" accept=".csv,.txt" class="stitch-file-input">
        </div>

        <div class="form-group">
          <label class="form-label" for="modalTextarea">Or Paste Raw CSV Telemetry:</label>
          <textarea id="modalTextarea" rows="6" class="stitch-textarea" placeholder="ts,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,proto,orig_bytes,resp_bytes,conn_state,label..."></textarea>
        </div>
      </div>

      <div class="modal-footer">
        <button id="cancelUploadModalBtn" class="btn-stitch-glass">Cancel</button>
        <button id="submitUploadModalBtn" class="btn-stitch-primary">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
          <span>Normalize & Ingest</span>
        </button>
      </div>
    </div>
  `;

  document.body.appendChild(modal);

  const closeBtn = modal.querySelector('#closeUploadModal');
  const cancelBtn = modal.querySelector('#cancelUploadModalBtn');
  const submitBtn = modal.querySelector('#submitUploadModalBtn');
  const fileInput = modal.querySelector('#modalFileInput');
  const textarea = modal.querySelector('#modalTextarea');
  const schemaSelect = modal.querySelector('#modalSchemaSelect');

  function hide() {
    modal.style.display = 'none';
  }

  function show() {
    modal.style.display = 'flex';
  }

  closeBtn.addEventListener('click', hide);
  cancelBtn.addEventListener('click', hide);
  modal.addEventListener('click', (e) => {
    if (e.target === modal) hide();
  });

  fileInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (event) => {
        textarea.value = event.target.result;
      };
      reader.readAsText(file);
    }
  });

  submitBtn.addEventListener('click', () => {
    const content = textarea.value.trim();
    if (!content) {
      alert('Please select a CSV file or paste flow telemetry.');
      return;
    }
    const schema = schemaSelect.value || null;
    hide();
    onUploadSubmit(content, schema);
  });

  return { show, hide };
}
