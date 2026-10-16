# Sentinel AI: Network Traffic Anomaly & Behaviour Analysis

> **Adaptive Detection, Log Compatibility & Forensic Context Replay Platform**

Sentinel AI is a beginner-friendly, modular cybersecurity platform that normalizes disparate network flow logs (Zeek `conn.log` and Enterprise Firewall / Cloud VPC logs), detects malicious traffic patterns (vertical port scans, horizontal network sweeps, and lateral spreading), and leverages external organizational context to achieve up to **100% false-positive reduction** on benign lookalikes without ever discarding forensic evidence.

---

## 1. Project Directory Structure

```
Sentinel-AI/
├── backend/                  # Detection engine & REST API service
│   ├── app/                  # Modular backend detection components
│   │   ├── types.js          # Canonical FlowRecord & SOC severity types
│   │   ├── dataLoader.js     # RFC-4180 CSV parser & column-mapping normalizer
│   │   ├── detectionRules.js # Volumetric anomaly detection rules
│   │   ├── trustedActivity.js# Context baselining & FP reduction
│   │   ├── incidentEngine.js # Threat actor clustering & 0-100 scoring
│   │   ├── contextReplay.js  # Adaptive Context Replay engine
│   │   ├── evaluation.js     # Empirical metrics evaluation
│   │   └── pipeline.js       # End-to-end orchestration pipeline
│   ├── main.js               # Backend REST API server (port 3001)
│   ├── runAnalysis.js        # Offline CLI analysis & report generator
│   └── package.json          # Backend npm scripts
├── frontend/                 # SOC Analyst Dashboard web application
│   ├── src/
│   │   ├── components/       # MetricsBanner, IncidentQueue, ContextReplay, EvidenceTable, UploadModal
│   │   ├── services/         # api.js REST API client
│   │   ├── styles/           # Dark mode glassmorphic CSS
│   │   ├── types/            # Frontend types and constants
│   │   └── main.js           # Frontend application controller
│   ├── public/               # Static assets
│   ├── index.html            # Main dashboard HTML entry point
│   ├── server.js             # Frontend static dev server (port 5173)
│   └── package.json          # Frontend npm scripts
├── config/                   # Externalized JSON baselines & mappings
│   ├── config.json           # Approved scanners, backups, maintenance windows, patch servers
│   └── dataset_mapping.json  # Normalization rules for Zeek & Firewall schemas
├── datasets/                 # Sanitized & synthetic flow telemetry
│   ├── original/             # Raw schema specifications & header definitions
│   └── synthetic/            # Annotated datasets with ground truth labels
├── tests/                    # Automated test suites
│   ├── backend/              # Data mapper, detection rules, context tests
│   ├── integration/          # End-to-end pipeline & dynamic config tests
│   └── frontend/             # REST API contracts & health tests
├── docs/                     # Technical documentation
│   ├── ARCHITECTURE.md       # Architecture & pipeline flow diagram
│   ├── DATASET_MAPPING.md    # Dual-schema column mapping specification
│   ├── EVALUATION_REPORT.md  # Empirical precision/recall/FPR benchmark
│   └── LIMITATIONS.md        # Real-world engineering boundaries
├── README.md                 # Project guide (this file)
├── .gitignore                # Git ignore rules
└── package.json              # Root convenience scripts
```

---

## 2. Prerequisites & Quick Installation

### Prerequisites
- **Node.js**: v18.0.0 or higher (v24.x recommended, verified).
- No external npm packages or native compilers required. The entire engine runs using Node's standard libraries (`node:http`, `node:fs`, `node:test`, `node:assert`).

### Installation
Clone or navigate to the repository:
```bash
git clone https://github.com/vineethjarupla44-alt/Sentinal-AI.git
cd Sentinal-AI
```

---

## 3. How to Run the Project

### Option A: Running Backend and Frontend in Separate Terminals

#### Terminal 1 — Start the Backend API (Port 3001)
```bash
cd backend
npm start
```
*The backend API will start on `http://localhost:3001`.*
- Health check: `http://localhost:3001/health`
- Configuration & status: `http://localhost:3001/api/status`

#### Terminal 2 — Start the Frontend Dashboard (Port 5173)
```bash
cd frontend
npm run dev
```
*Open your browser and navigate to `http://localhost:5173`.*

---

### Option B: Running from the Project Root

From the project root directory, you can also run:
```bash
# Start the Backend API
npm run backend

# In a separate terminal, start the Frontend Dashboard
npm run frontend

# Run offline CLI analysis and generate report
npm run analyze
```

---

## 4. How to Upload & Analyze Datasets

1. Open the dashboard at `http://localhost:5173`.
2. **Switch Built-in Schemas**: Use the dropdown in the header to toggle between:
   - **Schema 1: Zeek `conn.log`**: Standard network sensor logs.
   - **Schema 2: Enterprise Firewall / VPC Flow**: Palo Alto and AWS VPC flow schema.
   - **Edge Cases**: Malformed lines, duplicates, and missing ports.
3. **Upload Custom Telemetry**: Click the **"Upload CSV"** button in the header:
   - Select your `.csv` file or paste raw CSV rows into the text area.
   - Choose whether to auto-detect the schema or select a specific format.
   - Click **"Process & Analyze"**. The backend normalizes the logs, detects behavioral patterns, and immediately updates the incident queue and replay inspector.

---

## 5. How to Run Tests

Sentinel AI includes a complete automated test suite organized across unit, integration, and contract tests (29 passing tests, 0 failures):

```bash
# Run all 29 automated tests from the root directory
npm test
```

### Test Suite Structure
- `tests/backend/hostBaseline.test.js`: Validates temporal host baselining, Z-score deviations, insufficient history handling, and backup mitigations.
- `tests/backend/beaconing.test.js`: Validates periodic C2 beaconing detection, jitter CV calculation, and legitimate NTP/DC disambiguation.
- `tests/backend/timelineAndGraph.test.js`: Validates chronological timeline sequencing, attack-stage hypotheses, and directed communication graph construction.
- `tests/backend/mapper.test.js`: Validates RFC-4180 parsing, schema detection, duplicate suppression, and safe defaults.
- `tests/backend/detection.test.js`: Validates vertical port scans, horizontal network sweeps, and lateral spreading indicators.
- `tests/backend/context.test.js`: Validates approved security scanners, scheduled backups, WSUS patch servers, and maintenance windows.
- `tests/integration/pipeline.test.js`: Validates end-to-end flow from CSV ingestion to Adaptive Context Replay.
- `tests/integration/config.test.js`: Validates dynamic threshold and scanner changes without code modifications.
- `tests/frontend/api.test.js`: Validates backend REST API contracts and `/health` endpoints.

---

## 6. How to View Evaluation Results

1. **In the Web Dashboard**: The top metrics banner displays live KPI cards (Processed Flows, False-Positive Reduction, Precision Before/After, Recall, and FPR).
2. **Via Terminal CLI**:
   ```bash
   npm run eval
   # or
   npm run analyze
   ```
   Outputs the empirical confusion matrix and before/after metrics table directly to the console.
3. **In the Markdown Report**: Read the complete evaluation benchmark in [`docs/EVALUATION_REPORT.md`](file:///c:/Users/sonal/OneDrive/Desktop/Sentinal%20AI/docs/EVALUATION_REPORT.md).

---

## 7. Key Features Explained for Beginners

- **Advanced Anomaly Visualizations (Screen 3 Sub-tabs)**:
  - **Baseline & Deviation**: Visualizes host traffic against learned normal statistical envelopes with metric-level Z-scores and deviation percentages. Explicitly handles insufficient history without false alerts.
  - **Beaconing & Intervals**: Detects repetitive automated callbacks, calculating $\Delta t$ intervals, mean/median timings, and Coefficient of Variation ($CV = \sigma / \mu$) jitter to identify stealth C2 channels vs NTP/DNS sync.
  - **Attack Timeline**: Chronological progression with delta timestamps and evidence-backed attack-stage hypotheses (`Reconnaissance`, `Lateral Movement`, `C2`, `Unusual Outbound Transfer`, `Unclassified`).
  - **Network Communication Graph**: Interactive directed SVG graph showing host nodes and flow edges with line thickness scaled to data volume and suspicious channels highlighted in coral/red.
- **Log Compatibility**: You don't need separate tools for firewall logs and Zeek logs. Our column mapping layer (`config/dataset_mapping.json`) converts both into one internal format.
- **Evidence Preservation**: When a Nessus vulnerability scanner or nightly backup triggers a port scan or sweep rule, Sentinel AI doesn't delete the alert. It deprioritizes the score, explains why, and keeps 100% of the raw flow records for audit compliance.
- **Adaptive Context Replay**: Shows analysts the raw naive finding versus the context-adjusted finding side-by-side, detailing exactly what points were deducted and highlighting any **unexplained deviations** (such as unauthorized ports or off-schedule activity).
- **0–100 Mathematical Prioritization**: Correlates multiple attack behaviors from the same threat actor and assigns an auditable prioritization score.

