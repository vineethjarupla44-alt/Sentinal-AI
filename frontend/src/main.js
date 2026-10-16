/**
 * Sentinel AI - Main Application Controller
 * Manages reactive screen routing, telemetry state synchronization,
 * API requests, and Google Stitch UI rendering across all 6 screens.
 */

import { fetchEngineStatus, fetchDatasetAnalysis, analyzeCustomCSV } from './services/api.js';
import { renderNavigation } from './components/Navigation.js';
import { renderDashboardScreen } from './components/DashboardScreen.js';
import { renderDatasetScreen } from './components/DatasetScreen.js';
import { renderInvestigationScreen } from './components/InvestigationScreen.js';
import { renderContextReplayScreen } from './components/ContextReplayScreen.js';
import { renderConfigScreen } from './components/ConfigScreen.js';
import { renderReportsScreen } from './components/ReportsScreen.js';
import { createUploadModal } from './components/UploadModal.js';
import { showToast } from './components/Toast.js';
import { initBackground3D } from './components/Background3D.js';

// Application State
let currentScreen = 'dashboard';
let currentDatasetKey = 'zeek';
let currentData = null;
let engineStatus = null;
let selectedIncidentId = null;
let isLoading = false;

// DOM Elements
const navHeader = document.getElementById('navHeader');
const screenContainer = document.getElementById('screenContainer');

// Initialize Upload Modal
const uploadModal = createUploadModal(async (csvContent, schema) => {
  setLoadingState(true, 'Normalizing and analyzing custom telemetry...');
  try {
    currentData = await analyzeCustomCSV(csvContent, schema);
    currentDatasetKey = 'custom';
    if (currentData.result.incidents && currentData.result.incidents.length > 0) {
      selectedIncidentId = currentData.result.incidents[0].incident_id;
    }
    showToast(`Processed ${(currentData.result.record_count || 0)} flow records successfully`, 'success');
    navigateTo('dataset');
  } catch (err) {
    showToast(`Ingestion error: ${err.message}`, 'warning');
    console.error('Custom CSV ingestion failed:', err);
  } finally {
    setLoadingState(false);
  }
});

/**
 * Set loading overlay or message
 */
function setLoadingState(loading, message = 'Processing...') {
  isLoading = loading;
  if (loading) {
    screenContainer.innerHTML = `
      <div style="display: flex; flex-direction: column; align-items: center; justify-content: center; min-height: 400px; gap: 16px;">
        <div class="pulse-dot" style="width: 24px; height: 24px; border-radius: 50%; background: var(--accent-primary); box-shadow: 0 0 20px var(--accent-primary);"></div>
        <div style="font-size: 15px; font-weight: 600; color: var(--accent-highlight);">${message}</div>
      </div>
    `;
  }
}

/**
 * Switch Active Screen
 */
export function navigateTo(screenId) {
  currentScreen = screenId;
  updateNav();
  renderActiveScreen();
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

/**
 * Update Top Navigation Bar
 */
function updateNav() {
  renderNavigation(
    navHeader,
    currentScreen,
    navigateTo,
    handleDatasetChange,
    () => uploadModal.show(),
    handleRefresh
  );
}

/**
 * Render the Active Screen Component
 */
function renderActiveScreen() {
  if (!currentData) {
    setLoadingState(true, 'Connecting to Sentinel AI Engine...');
    return;
  }

  switch (currentScreen) {
    case 'dashboard':
      renderDashboardScreen(
        screenContainer,
        currentData,
        navigateTo,
        handleSelectIncident
      );
      break;

    case 'dataset':
      renderDatasetScreen(
        screenContainer,
        currentData,
        engineStatus,
        handleDatasetChange,
        (content) => uploadModal.show(),
        handleRefresh
      );
      break;

    case 'investigation':
      renderInvestigationScreen(
        screenContainer,
        currentData,
        selectedIncidentId,
        handleSelectIncident
      );
      break;

    case 'replay':
      renderContextReplayScreen(
        screenContainer,
        currentData,
        selectedIncidentId,
        handleSelectIncident
      );
      break;

    case 'config':
      renderConfigScreen(
        screenContainer,
        engineStatus
      );
      break;

    case 'reports':
      renderReportsScreen(
        screenContainer,
        currentData
      );
      break;

    default:
      navigateTo('dashboard');
      break;
  }
}

/**
 * Incident selection event
 */
function handleSelectIncident(incidentId) {
  selectedIncidentId = incidentId;
  renderActiveScreen();
}

/**
 * Handle dataset dropdown / tab changes
 */
async function handleDatasetChange(datasetKey) {
  currentDatasetKey = datasetKey;
  setLoadingState(true, `Loading telemetry dataset: ${datasetKey}...`);
  try {
    currentData = await fetchDatasetAnalysis(datasetKey);
    if (currentData.result.incidents && currentData.result.incidents.length > 0) {
      selectedIncidentId = currentData.result.incidents[0].incident_id;
    }
    showToast(`Loaded ${currentData.result.audit?.schema_name || datasetKey} (${currentData.result.record_count} flows)`, 'success');
  } catch (err) {
    console.error('Failed to switch dataset:', err);
    showToast(`Failed to load dataset: ${err.message}`, 'warning');
  } finally {
    setLoadingState(false);
    updateNav();
    renderActiveScreen();
  }
}

/**
 * Refresh current analysis
 */
async function handleRefresh() {
  if (currentDatasetKey === 'custom') {
    showToast('Re-running custom telemetry analysis', 'info');
    renderActiveScreen();
    return;
  }
  await handleDatasetChange(currentDatasetKey);
}

/**
 * Bootstrap Application
 */
async function initApp() {
  initBackground3D();
  updateNav();
  setLoadingState(true, 'Initializing Sentinel AI detection pipeline...');

  try {
    // 1. Fetch Engine Status & Config
    engineStatus = await fetchEngineStatus();
  } catch (err) {
    console.warn('Backend engine status fetch deferred:', err);
  }

  try {
    // 2. Fetch Initial Zeek Dataset Analysis
    currentData = await fetchDatasetAnalysis('zeek');
    if (currentData.result.incidents && currentData.result.incidents.length > 0) {
      selectedIncidentId = currentData.result.incidents[0].incident_id;
    }
  } catch (err) {
    console.error('Initial analysis load failed:', err);
    screenContainer.innerHTML = `
      <div class="panel-stitch" style="margin-top: 40px; text-align: center; border-color: rgba(239, 68, 68, 0.4);">
        <h2 style="color: #FFA39E; margin-bottom: 8px;">Backend Connection Offline</h2>
        <p style="color: var(--text-secondary); margin-bottom: 16px;">
          Sentinel AI frontend could not connect to <code>http://localhost:3001</code>.<br>
          Please verify that the backend engine is running with: <code>npm run backend</code>
        </p>
        <button id="retryBtn" class="btn-stitch-primary">Retry Connection</button>
      </div>
    `;
    const retryBtn = document.getElementById('retryBtn');
    if (retryBtn) retryBtn.addEventListener('click', initApp);
    return;
  }

  setLoadingState(false);
  updateNav();
  renderActiveScreen();
}

// Start Application
initApp();
