import { app, BrowserWindow, dialog, ipcMain, session } from 'electron';
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { collectBaseline, getBaselineStatus } from '../collector/baselineService';
import { checkInternetConnectivity } from '../collector/connectivityService';
import {
  createBaselineDiagnosticsBundle,
  listBaselineDiagnosticsBundles
} from '../collector/diagnosticsService';
import { getBaselineEvents, getBaselineTimeline } from '../collector/historyService';
import { scanLocalNetwork } from '../collector/localNetworkService';
import { getBaselineNetworks } from '../collector/networkService';
import { analyzeBaselineRun } from '../collector/runAnalysis';
import { compareBaselineRuns } from '../collector/runComparison';
import { listBaselineRuns } from '../collector/runHistory';
import { cancelDeviceIntelligenceUpdate, runAiThreatReview, runDeviceIntelligenceUpdate } from '../collector/deviceIntelligence';
import { listDeviceHistory, listScanLocations, runDeviceVulnerabilityLookup } from '../collector/deviceInventory';
import {
  applyWindowsScanIdentity,
  getWindowsScanIdentityState,
  restoreWindowsScanIdentity
} from '../platform/windows/scanIdentity';
import { getWindowsWifiProfileSecret } from '../platform/windows/wlanProfiles';
import { disposeRadioChronCoreClient, getRadioChronCoreClient } from 'radiochron';
import { resetRadioChronBle, scanRadioChronBle } from '../platform/radiochronBle';
import {
  appendBleHistory,
  clearBleHistory,
  readBleHistory,
  type DesktopBleViewResult
} from '../platform/bleHistory';
import { demoBleHistory, demoBleScanResult } from '../demo/bleFixtures';
import {
  demoBaselineEvents,
  demoBaselineNetworks,
  demoBaselineRuns,
  demoBaselineStatus,
  demoBaselineTimeline,
  demoDeviceHistory,
  demoDiagnosticsBundles,
  demoScanIdentityState,
  demoScanLocations
} from '../demo/fixtures';
import type {
  AiThreatReviewResult,
  AiThreatReviewScope,
  BaselineCollectionCancelResult,
  BaselineNetworksResult,
  CollectResult,
  ConnectivityCheckResult,
  DetectorAlert,
  DeviceIntelligenceUpdateResult,
  DeviceHistoryResult,
  DeviceVulnerabilityLookupResult,
  LocalNetworkScanMode,
  LocalNetworkScanResult,
  ScanIdentityChangeRequest,
  ScanIdentityChangeResult,
  ScanIdentityState,
  ScanLocationInput,
  ScanLocationsResult,
  VulnerabilityLookupMode,
  WifiProfileSecretResult,
  WindowsWifiNetwork,
  WindowsWifiSnapshot
} from '../collector/types';

let mainWindow: BrowserWindow | null = null;
let sampleCollectionInFlight: Promise<CollectResult> | null = null;
let sampleCollectionAbortController: AbortController | null = null;
const DEMO_MODE = process.env.RADIOCHRON_DEMO === '1';

function createWindow(): void {
  mainWindow = new BrowserWindow({
    width: 1360,
    height: 820,
    minWidth: 1220,
    minHeight: 720,
    show: false,
    autoHideMenuBar: true,
    webPreferences: {
      preload: join(__dirname, '../preload/index.js'),
      sandbox: true,
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  mainWindow.on('ready-to-show', () => {
    mainWindow?.show();
  });

  if (DEMO_MODE && process.env.RADIOCHRON_CAPTURE_DIR) {
    mainWindow.webContents.once('did-finish-load', () => {
      void captureDemoScreenshots(mainWindow, process.env.RADIOCHRON_CAPTURE_DIR ?? '');
    });
  }

  if (process.env.ELECTRON_RENDERER_URL) {
    const rendererUrl = new URL(process.env.ELECTRON_RENDERER_URL);
    if (DEMO_MODE) rendererUrl.searchParams.set('demo', '1');
    mainWindow.loadURL(rendererUrl.toString());
  } else {
    mainWindow.loadFile(join(__dirname, '../renderer/index.html'), DEMO_MODE ? { query: { demo: '1' } } : undefined);
  }
}

async function captureDemoScreenshots(window: BrowserWindow | null, captureDir: string): Promise<void> {
  if (!window || !captureDir) return;
  try {
    await mkdir(captureDir, { recursive: true });
    await window.webContents.executeJavaScript(`new Promise((resolve, reject) => {
      const deadline = Date.now() + 15000;
      const poll = () => {
        if (document.body.innerText.includes('Lab Mesh 6E')) return resolve(true);
        if (Date.now() >= deadline) return reject(new Error('demo data did not render'));
        setTimeout(poll, 100);
      };
      poll();
    })`);

    await window.webContents.executeJavaScript(`document.querySelector('[data-radio-mode="wifi"]')?.click()`);
    for (const tab of ['overview', 'map', 'network', 'reports', 'channels']) {
      await window.webContents.executeJavaScript(`document.querySelector('[data-app-tab="${tab}"]')?.click()`);
      await new Promise((resolve) => setTimeout(resolve, 450));
      const image = await window.webContents.capturePage();
      await writeFile(join(captureDir, `radiochron-desktop-${tab}.png`), image.toPNG());
      if (tab === 'reports') {
        await writeFile(join(captureDir, 'radiochron-desktop-analytics.png'), image.toPNG());
        await window.webContents.executeJavaScript(`{
          const element = document.querySelector('.radio-presence-panel');
          document.documentElement.style.scrollBehavior = 'auto';
          if (element) window.scrollTo(0, window.scrollY + element.getBoundingClientRect().top - 58);
        }`);
        await new Promise((resolve) => setTimeout(resolve, 180));
        const patternsImage = await window.webContents.capturePage();
        await writeFile(join(captureDir, 'radiochron-desktop-wifi-presence.png'), patternsImage.toPNG());
        await window.webContents.executeJavaScript(`window.scrollTo(0, 0)`);
      }
    }
    await window.webContents.executeJavaScript(`document.querySelector('[data-radio-mode="bluetooth"]')?.click()`);
    await new Promise((resolve) => setTimeout(resolve, 50));
    for (const view of ['overview', 'map', 'devices', 'history', 'findings']) {
      await window.webContents.executeJavaScript(`document.querySelector('[data-bluetooth-view="${view}"]')?.click()`);
      await new Promise((resolve) => setTimeout(resolve, 450));
      const image = await window.webContents.capturePage();
      const filename = view === 'overview' ? 'radiochron-desktop-bluetooth.png' : `radiochron-desktop-bluetooth-${view}.png`;
      await writeFile(join(captureDir, filename), image.toPNG());
      if (view === 'map') {
        await window.webContents.executeJavaScript(`document.querySelector('.ble-map-center')?.dispatchEvent(new MouseEvent('dblclick', { bubbles: true }))`);
        await new Promise((resolve) => setTimeout(resolve, 180));
        const sensorImage = await window.webContents.capturePage();
        await writeFile(join(captureDir, 'radiochron-desktop-bluetooth-sensor-detail.png'), sensorImage.toPNG());
        await window.webContents.executeJavaScript(`document.querySelector('.ble-sensor-modal .secondary-button')?.click()`);
      }
      if (view === 'history') {
        await writeFile(join(captureDir, 'radiochron-desktop-bluetooth-analytics.png'), image.toPNG());
        await window.webContents.executeJavaScript(`{
          const element = document.querySelector('.radio-presence-panel');
          document.documentElement.style.scrollBehavior = 'auto';
          if (element) window.scrollTo(0, window.scrollY + element.getBoundingClientRect().top - 58);
        }`);
        await new Promise((resolve) => setTimeout(resolve, 180));
        const patternsImage = await window.webContents.capturePage();
        await writeFile(join(captureDir, 'radiochron-desktop-bluetooth-presence.png'), patternsImage.toPNG());
        await window.webContents.executeJavaScript(`window.scrollTo(0, 0)`);
      }
    }
    await window.webContents.executeJavaScript(`document.querySelector('[data-bluetooth-view="devices"]')?.click()`);
    await new Promise((resolve) => setTimeout(resolve, 250));
    await window.webContents.executeJavaScript(`document.querySelector('.ble-device-table tbody tr:first-child button')?.click()`);
    await new Promise((resolve) => setTimeout(resolve, 250));
    const detailImage = await window.webContents.capturePage();
    await writeFile(join(captureDir, 'radiochron-desktop-bluetooth-device-detail.png'), detailImage.toPNG());
    app.quit();
  } catch (error) {
    console.error('RadioChron demo screenshot capture failed', error);
    app.exit(1);
  }
}

ipcMain.handle('monitor:capabilities', async () => ({
  schema: 'monitor.bridge_capabilities.v1',
  generated_at_utc: new Date().toISOString(),
  demo_mode: DEMO_MODE,
  platform: process.platform,
  ipc: {
    device_vulnerability_lookup: true,
    device_history: true,
    device_intelligence_update: true,
    ai_threat_review: true,
    wifi_profile_secret: process.platform === 'win32',
    connectivity_check: true,
    radiochron_analysis: true,
    radiochron_chronicle: true,
    radiochron_ble: true,
    local_network_scan: process.platform === 'win32',
    scan_identity: process.platform === 'win32',
    scan_locations: true,
    report_pdf_export: true
  }
}));
ipcMain.handle('baseline:status', async () => DEMO_MODE ? demoBaselineStatus() : getBaselineStatus());
ipcMain.handle('baseline:networks', async (_event, options?: {
  refreshScan?: unknown;
  scanSettleMs?: unknown;
  useDeviceIntelligence?: unknown;
  persistInventory?: unknown;
  location?: unknown;
}) => {
  if (DEMO_MODE) return demoBaselineNetworks();
  const result = await getBaselineNetworks({
    refreshScan: options?.refreshScan === true,
    scanSettleMs: boundedInteger(options?.scanSettleMs, 4500, 0, 10_000),
    useDeviceIntelligence: options?.useDeviceIntelligence === false ? false : undefined,
    persistInventory: options?.persistInventory === false ? false : true,
    location: readOptionalScanLocation(options?.location)
  });
  return withRadioChronAnalysis(result);
});
ipcMain.handle(
  'connectivity:check',
  async (_event, options?: { downloadBytes?: unknown; timeoutMs?: unknown }): Promise<ConnectivityCheckResult> =>
    checkInternetConnectivity({
      downloadBytes: boundedInteger(options?.downloadBytes, 750_000, 128_000, 5_000_000),
      timeoutMs: boundedInteger(options?.timeoutMs, 8_000, 2_000, 20_000)
    })
);
ipcMain.handle('radiochron:analysis', async (_event, options?: { refreshScan?: unknown }) =>
  getRadioChronCoreClient().analyze({ refreshScan: options?.refreshScan === true })
);
ipcMain.handle('radiochron:chronicle-status', async () => getRadioChronCoreClient().chronicle.status());
ipcMain.handle('radiochron:chronicle-recent', async (_event, options?: { maxEntries?: unknown }) =>
  getRadioChronCoreClient().chronicle.recent({
    maxEntries: boundedInteger(options?.maxEntries, 100, 1, 2_000)
  })
);
ipcMain.handle(
  'radiochron:ble-scan',
  async (_event, options?: { durationMs?: unknown; zone?: unknown }): Promise<DesktopBleViewResult> => {
    if (DEMO_MODE) return demoBleScanResult();
    const zone = readOptionalText(options?.zone, 120);
    const result = await scanRadioChronBle({
      durationMs: boundedInteger(options?.durationMs, 4_000, 250, 30_000),
      zone
    });
    return {
      ...result,
      analytics_history: await appendBleHistory(desktopBleHistoryPath(), result, zone)
    };
  }
);
ipcMain.handle(
  'radiochron:ble-history',
  async () => DEMO_MODE ? demoBleHistory() : readBleHistory(desktopBleHistoryPath())
);
ipcMain.handle('radiochron:ble-reset', async () => {
  if (DEMO_MODE) return { reset: true as const };
  const result = await resetRadioChronBle();
  await clearBleHistory(desktopBleHistoryPath());
  return result;
});
ipcMain.handle(
  'local-network:scan',
  async (_event, options?: { mode?: unknown; snapshot?: unknown }): Promise<LocalNetworkScanResult> =>
    scanLocalNetwork({
      mode: readLocalNetworkScanMode(options?.mode),
      snapshot: readOptionalWifiSnapshot(options?.snapshot)
    })
);
ipcMain.handle(
  'scan-identity:state',
  async (_event, options?: { interfaceName?: unknown; adapterName?: unknown }): Promise<ScanIdentityState> =>
    DEMO_MODE ? demoScanIdentityState() : getWindowsScanIdentityState({
      interfaceName: readOptionalText(options?.interfaceName, 120),
      adapterName: readOptionalText(options?.adapterName, 240)
    })
);
ipcMain.handle(
  'scan-identity:apply',
  async (_event, options?: unknown): Promise<ScanIdentityChangeResult> =>
    applyWindowsScanIdentity(readScanIdentityChangeRequest(options, true))
);
ipcMain.handle(
  'scan-identity:restore',
  async (_event, options?: unknown): Promise<ScanIdentityChangeResult> =>
    restoreWindowsScanIdentity(readScanIdentityChangeRequest(options, false))
);
ipcMain.handle(
  'baseline:diagnostics',
  async (
    _event,
    options?: {
      lastRuns?: unknown;
      lastEvents?: unknown;
      windowMinutes?: unknown;
      minCycles?: unknown;
    }
  ) =>
    createBaselineDiagnosticsBundle({
      outDir: null,
      runsDir: null,
      lastRuns: boundedInteger(options?.lastRuns, 10, 1, 100),
      lastEvents: boundedInteger(options?.lastEvents, 100, 1, 300),
      windowMinutes: boundedInteger(options?.windowMinutes, 10, 1, 120),
      minCycles: boundedInteger(options?.minCycles, 2, 2, 20)
    })
);
ipcMain.handle('baseline:diagnostics:list', async (_event, options?: { last?: unknown }) =>
  DEMO_MODE ? demoDiagnosticsBundles() : listBaselineDiagnosticsBundles({
    last: boundedInteger(options?.last, 10, 1, 100),
    diagnosticsDir: null
  })
);
ipcMain.handle('baseline:events', async (_event, options?: { last?: unknown }) =>
  DEMO_MODE ? demoBaselineEvents() : getBaselineEvents({
    last: boundedInteger(options?.last, 25, 1, 200)
  })
);
ipcMain.handle('baseline:runs', async (_event, options?: { last?: unknown }) =>
  DEMO_MODE ? demoBaselineRuns() : listBaselineRuns({
    last: boundedInteger(options?.last, 10, 1, 100),
    runsDir: null
  })
);
ipcMain.handle('baseline:collectSample', async (_event, options?: { durationSeconds?: unknown; intervalSeconds?: unknown; maxEvents?: unknown }) => {
  if (sampleCollectionInFlight) {
    throw new Error('Baseline sample collection is already running');
  }

  sampleCollectionAbortController = new AbortController();
  sampleCollectionInFlight = collectBaseline({
    durationSeconds: boundedInteger(options?.durationSeconds, 60, 5, 600),
    intervalSeconds: boundedInteger(options?.intervalSeconds, 5, 1, 60),
    maxEvents: boundedInteger(options?.maxEvents, 100, 10, 500),
    outDir: null,
    abortSignal: sampleCollectionAbortController.signal
  });

  try {
    return await sampleCollectionInFlight;
  } finally {
    sampleCollectionInFlight = null;
    sampleCollectionAbortController = null;
  }
});
ipcMain.handle('baseline:cancelCollection', async (): Promise<BaselineCollectionCancelResult> => {
  if (!sampleCollectionInFlight || !sampleCollectionAbortController) {
    return {
      cancelled: false,
      message: 'No baseline collection is running'
    };
  }

  sampleCollectionAbortController.abort();
  return {
    cancelled: true,
    message: 'Baseline collection cancellation requested'
  };
});
ipcMain.handle('baseline:analyze', async (_event, options?: { runId?: unknown; windowMinutes?: unknown; minCycles?: unknown }) =>
  analyzeBaselineRun({
    runId: readRunId(options?.runId),
    runsDir: null,
    windowMinutes: boundedInteger(options?.windowMinutes, 10, 1, 120),
    minCycles: boundedInteger(options?.minCycles, 2, 2, 20)
  })
);
ipcMain.handle(
  'baseline:compare',
  async (
    _event,
    options?: {
      baselineRunId?: unknown;
      candidateRunId?: unknown;
      windowMinutes?: unknown;
      minCycles?: unknown;
    }
  ) =>
    compareBaselineRuns({
      baselineRunId: readRunId(options?.baselineRunId),
      candidateRunId: readRunId(options?.candidateRunId),
      runsDir: null,
      windowMinutes: boundedInteger(options?.windowMinutes, 10, 1, 120),
      minCycles: boundedInteger(options?.minCycles, 2, 2, 20)
    })
);
ipcMain.handle('baseline:timeline', async (_event, options?: { last?: unknown; windowMinutes?: unknown; minCycles?: unknown }) =>
  DEMO_MODE ? demoBaselineTimeline() : getBaselineTimeline({
    last: boundedInteger(options?.last, 60, 1, 300),
    windowMinutes: boundedInteger(options?.windowMinutes, 10, 1, 120),
    minCycles: boundedInteger(options?.minCycles, 2, 2, 20)
  })
);
ipcMain.handle(
  'device:intelligence:update',
  async (
    _event,
    options?: { provider?: unknown; network?: unknown; jobId?: unknown }
  ): Promise<DeviceIntelligenceUpdateResult> =>
    runDeviceIntelligenceUpdate({
      provider: readDeviceIntelligenceProvider(options?.provider),
      network: readWifiNetwork(options?.network),
      jobId: readOptionalAiJobId(options?.jobId)
    })
);
ipcMain.handle(
  'device:vulnerability:lookup',
  async (
    _event,
    options?: {
      mode?: unknown;
      network?: unknown;
      selectedCheckIds?: unknown;
      operatorNote?: unknown;
    }
  ): Promise<DeviceVulnerabilityLookupResult> =>
    runDeviceVulnerabilityLookup({
      mode: readVulnerabilityLookupMode(options?.mode),
      network: readWifiNetwork(options?.network),
      selectedCheckIds: readStringArray(options?.selectedCheckIds, 24, 120),
      operatorNote: readOptionalText(options?.operatorNote, 500)
    })
);
ipcMain.handle(
  'device:history',
  async (_event, options?: { newWindowHours?: unknown }): Promise<DeviceHistoryResult> =>
    DEMO_MODE ? demoDeviceHistory() : listDeviceHistory({
      newWindowHours: boundedInteger(options?.newWindowHours, 24, 1, 24 * 30)
    })
);
ipcMain.handle(
  'scan-locations:list',
  async (): Promise<ScanLocationsResult> =>
    DEMO_MODE ? demoScanLocations() : listScanLocations()
);
ipcMain.handle(
  'device:intelligence:cancel',
  async (_event, options?: { jobId?: unknown }): Promise<{ cancelled: boolean }> => ({
    cancelled: cancelDeviceIntelligenceUpdate(readRequiredAiJobId(options?.jobId))
  })
);
ipcMain.handle(
  'wifi:profile-secret',
  async (_event, options?: { ssid?: unknown }): Promise<WifiProfileSecretResult> =>
    getWindowsWifiProfileSecret({
      ssid: readSsid(options?.ssid)
    })
);
ipcMain.handle(
  'ai:threat-review',
  async (
    _event,
    options?: {
      provider?: unknown;
      scope?: unknown;
      networks?: unknown;
      snapshot?: unknown;
      alerts?: unknown;
    }
  ): Promise<AiThreatReviewResult> =>
    runAiThreatReview({
      provider: readAiThreatReviewProvider(options?.provider),
      scope: readThreatReviewScope(options?.scope),
      networks: readWifiNetworks(options?.networks),
      snapshot: readOptionalWifiSnapshot(options?.snapshot),
      alerts: readDetectorAlerts(options?.alerts)
    })
);
ipcMain.handle(
  'report:export-pdf',
  async (_event, options?: { html?: unknown; filename?: unknown }): Promise<{ saved: boolean; path: string | null; error: string | null }> =>
    exportReportPdf({
      html: readReportHtml(options?.html),
      filename: readOptionalText(options?.filename, 120)
    })
);

async function exportReportPdf(options: { html: string; filename: string | null }): Promise<{ saved: boolean; path: string | null; error: string | null }> {
  const sourceWindow = mainWindow ?? BrowserWindow.getFocusedWindow() ?? undefined;
  const defaultFilename = sanitizePdfFilename(options.filename ?? 'monitor-vulnerability-report.pdf');
  const saveDialogOptions = {
    title: 'Save vulnerability report PDF',
    defaultPath: defaultFilename,
    filters: [{ name: 'PDF', extensions: ['pdf'] }]
  };
  const saveResult = sourceWindow
    ? await dialog.showSaveDialog(sourceWindow, saveDialogOptions)
    : await dialog.showSaveDialog(saveDialogOptions);

  if (saveResult.canceled || !saveResult.filePath) {
    return { saved: false, path: null, error: null };
  }

  const pdfWindow = new BrowserWindow({
    width: 960,
    height: 1280,
    show: false,
    webPreferences: {
      sandbox: true,
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  try {
    await pdfWindow.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(options.html)}`);
    const pdf = await pdfWindow.webContents.printToPDF({
      printBackground: true,
      pageSize: 'A4',
      margins: {
        top: 0.35,
        bottom: 0.35,
        left: 0.35,
        right: 0.35
      }
    });
    await writeFile(saveResult.filePath, pdf);
    return { saved: true, path: saveResult.filePath, error: null };
  } catch (error: unknown) {
    return {
      saved: false,
      path: null,
      error: error instanceof Error ? error.message : String(error)
    };
  } finally {
    pdfWindow.destroy();
  }
}

function boundedInteger(value: unknown, fallback: number, min: number, max: number): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return fallback;
  }

  return Math.min(max, Math.max(min, Math.trunc(value)));
}

function readRunId(value: unknown): string {
  if (typeof value !== 'string') {
    throw new Error('runId is required');
  }

  const trimmed = value.trim();
  if (!trimmed || trimmed.length > 160 || /[\\/]/.test(trimmed)) {
    throw new Error('runId is invalid');
  }

  return trimmed;
}

function readDeviceIntelligenceProvider(value: unknown): DeviceIntelligenceUpdateResult['provider'] {
  if (value === 'smart' || value === 'codex' || value === 'claude') {
    return value;
  }

  throw new Error('AI provider is invalid');
}

function readAiThreatReviewProvider(value: unknown): AiThreatReviewResult['provider'] {
  if (value === 'codex' || value === 'claude') {
    return value;
  }

  throw new Error('AI review provider is invalid');
}

function readVulnerabilityLookupMode(value: unknown): VulnerabilityLookupMode {
  if (value === undefined || value === null || value === 'passive') {
    return 'passive';
  }

  throw new Error('Vulnerability lookup mode is invalid');
}

function readLocalNetworkScanMode(value: unknown): LocalNetworkScanMode {
  if (value === 'passive' || value === 'poll' || value === 'active') {
    return value;
  }

  throw new Error('Local network scan mode is invalid');
}

function readScanIdentityChangeRequest(value: unknown, requireLocalMac: boolean): ScanIdentityChangeRequest {
  if (value !== undefined && value !== null && typeof value !== 'object') {
    throw new Error('Scan identity request is invalid');
  }

  const request = (value ?? {}) as {
    interfaceName?: unknown;
    adapterName?: unknown;
    computerName?: unknown;
    macAddress?: unknown;
    restartAdapter?: unknown;
  };

  return {
    interfaceName: readOptionalText(request.interfaceName, 120),
    adapterName: readOptionalText(request.adapterName, 240),
    computerName: readOptionalComputerName(request.computerName),
    macAddress: readOptionalScanMacAddress(request.macAddress, requireLocalMac),
    restartAdapter: request.restartAdapter !== false
  };
}

function readOptionalComputerName(value: unknown): string | null {
  const text = readOptionalText(value, 15);
  if (!text) {
    return null;
  }

  const normalized = text.toUpperCase();
  if (!/^[A-Z0-9](?:[A-Z0-9-]{0,13}[A-Z0-9])?$/.test(normalized) || /^\d+$/.test(normalized)) {
    throw new Error('Computer name must be 1-15 letters, digits, or hyphens, and cannot be only digits.');
  }

  return normalized;
}

function readOptionalScanMacAddress(value: unknown, requireLocal: boolean): string | null {
  const text = readOptionalText(value, 64);
  if (!text) {
    return null;
  }

  const hex = text.replace(/[^a-fA-F0-9]/g, '').toLowerCase();
  if (hex.length !== 12 || hex === '000000000000') {
    throw new Error('Scan MAC must contain exactly 12 hexadecimal characters.');
  }
  const firstOctet = Number.parseInt(hex.slice(0, 2), 16);
  if (!Number.isFinite(firstOctet) || (firstOctet & 1) === 1) {
    throw new Error('Scan MAC must be a unicast address.');
  }
  if (requireLocal && (firstOctet & 2) !== 2) {
    throw new Error('Scan MAC must be locally administered so it does not impersonate a vendor OUI.');
  }

  return hex.match(/.{2}/g)?.join(':') ?? null;
}

function readOptionalScanLocation(value: unknown): ScanLocationInput | null {
  if (value === undefined || value === null) {
    return null;
  }
  if (typeof value !== 'object') {
    throw new Error('Scan location is invalid');
  }

  const location = value as {
    latitude?: unknown;
    longitude?: unknown;
    source?: unknown;
    label?: unknown;
  };
  if (typeof location.latitude !== 'number' || !Number.isFinite(location.latitude)) {
    throw new Error('Scan location latitude is invalid');
  }
  if (typeof location.longitude !== 'number' || !Number.isFinite(location.longitude)) {
    throw new Error('Scan location longitude is invalid');
  }
  if (location.latitude < -90 || location.latitude > 90 || location.longitude < -180 || location.longitude > 180) {
    throw new Error('Scan location coordinates are out of range');
  }
  if (location.source !== 'browser' && location.source !== 'manual') {
    throw new Error('Scan location source is invalid');
  }

  return {
    latitude: location.latitude,
    longitude: location.longitude,
    source: location.source,
    label: readOptionalText(location.label, 120)
  };
}

function readStringArray(value: unknown, maxItems: number, maxLength: number): string[] | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }
  if (!Array.isArray(value)) {
    throw new Error('String list is invalid');
  }

  return value
    .slice(0, maxItems)
    .map((item) => {
      if (typeof item !== 'string') {
        throw new Error('String list item is invalid');
      }
      return item.trim().slice(0, maxLength);
    })
    .filter(Boolean);
}

function readOptionalText(value: unknown, maxLength: number): string | null {
  if (value === undefined || value === null) {
    return null;
  }
  if (typeof value !== 'string') {
    throw new Error('Text value is invalid');
  }

  const trimmed = value.trim();
  return trimmed ? trimmed.slice(0, maxLength) : null;
}

function readReportHtml(value: unknown): string {
  if (typeof value !== 'string') {
    throw new Error('Report HTML is required');
  }

  const trimmed = value.trim();
  if (!trimmed || trimmed.length > 1_500_000) {
    throw new Error('Report HTML is invalid');
  }

  return trimmed;
}

function sanitizePdfFilename(value: string): string {
  const cleaned = value
    .trim()
    .replace(/[<>:"/\\|?*\u0000-\u001f]+/g, '-')
    .replace(/\s+/g, ' ')
    .slice(0, 120)
    .trim();
  const fallback = cleaned || 'monitor-vulnerability-report';
  return fallback.toLowerCase().endsWith('.pdf') ? fallback : `${fallback}.pdf`;
}

function readOptionalAiJobId(value: unknown): string | null {
  if (value === undefined || value === null) {
    return null;
  }

  return readRequiredAiJobId(value);
}

function readRequiredAiJobId(value: unknown): string {
  if (typeof value !== 'string') {
    throw new Error('AI job id is required');
  }

  const trimmed = value.trim();
  if (!trimmed || trimmed.length > 120 || !/^[a-zA-Z0-9_.:-]+$/.test(trimmed)) {
    throw new Error('AI job id is invalid');
  }

  return trimmed;
}

function readWifiNetwork(value: unknown): WindowsWifiNetwork {
  if (
    typeof value === 'object' &&
    value !== null &&
    (value as WindowsWifiNetwork).schema === 'wifi.windows_baseline.v1' &&
    (value as WindowsWifiNetwork).event_type === 'windows_wifi_network'
  ) {
    return value as WindowsWifiNetwork;
  }

  throw new Error('Wi-Fi network evidence is invalid');
}

function readWifiNetworks(value: unknown): WindowsWifiNetwork[] {
  if (value === undefined || value === null) {
    return [];
  }
  if (!Array.isArray(value)) {
    throw new Error('Wi-Fi network evidence list is invalid');
  }

  return value.slice(0, 120).map(readWifiNetwork);
}

function readOptionalWifiSnapshot(value: unknown): WindowsWifiSnapshot | null {
  if (value === undefined || value === null) {
    return null;
  }

  if (
    typeof value === 'object' &&
    value !== null &&
    (value as WindowsWifiSnapshot).schema === 'wifi.windows_baseline.v1' &&
    (value as WindowsWifiSnapshot).event_type === 'windows_wifi_snapshot'
  ) {
    return value as WindowsWifiSnapshot;
  }

  throw new Error('Wi-Fi snapshot evidence is invalid');
}

function readDetectorAlerts(value: unknown): DetectorAlert[] {
  if (value === undefined || value === null) {
    return [];
  }
  if (!Array.isArray(value)) {
    throw new Error('Detector alert evidence list is invalid');
  }

  return value.slice(0, 50).map((item) => {
    if (
      typeof item === 'object' &&
      item !== null &&
      (item as DetectorAlert).schema === 'wifi.alert.v1' &&
      (item as DetectorAlert).event_type === 'alert'
    ) {
      return item as DetectorAlert;
    }

    throw new Error('Detector alert evidence is invalid');
  });
}

function readThreatReviewScope(value: unknown): AiThreatReviewScope {
  if (value === 'map' || value === 'detector') {
    return value;
  }

  throw new Error('AI threat review scope is invalid');
}

function readSsid(value: unknown): string {
  if (typeof value !== 'string') {
    throw new Error('SSID is required');
  }

  const trimmed = value.trim();
  if (!trimmed || trimmed.length > 128 || /[\r\n]/.test(trimmed)) {
    throw new Error('SSID is invalid');
  }

  return trimmed;
}

async function withRadioChronAnalysis(result: BaselineNetworksResult): Promise<BaselineNetworksResult> {
  try {
    return {
      ...result,
      radiochron_analysis: await getRadioChronCoreClient().analyze(),
      radiochron_analysis_error: null
    };
  } catch (error) {
    return {
      ...result,
      radiochron_analysis: null,
      radiochron_analysis_error: error instanceof Error ? error.message : String(error)
    };
  }
}

function desktopBleHistoryPath(): string {
  return join(app.getPath('userData'), 'radiochron', 'ble-history-v1.json');
}

async function startDesktopChronicle(): Promise<void> {
  const chronicleDir = join(app.getPath('userData'), 'chronicle');
  await mkdir(chronicleDir, { recursive: true });
  process.env.RADIOCHRON_CHRONICLE_PATH = join(chronicleDir, 'wifi-events.jsonl');
  await getRadioChronCoreClient().chronicle.start({ intervalSeconds: 5, signalThresholdDb: 5 });
}

app.whenReady().then(async () => {
  session.defaultSession.setPermissionRequestHandler((_webContents, permission, callback) => {
    callback(permission === 'geolocation');
  });

  if (!DEMO_MODE) {
    try {
      await startDesktopChronicle();
    } catch (error) {
      console.warn('RadioChron chronicle could not start', error);
    }
  }

  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('before-quit', () => {
  disposeRadioChronCoreClient();
});
