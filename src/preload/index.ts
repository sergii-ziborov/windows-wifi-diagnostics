import { contextBridge, ipcRenderer } from 'electron';

contextBridge.exposeInMainWorld('monitor', {
  getBridgeCapabilities: () => ipcRenderer.invoke('monitor:capabilities'),
  getBaselineStatus: () => ipcRenderer.invoke('baseline:status'),
  getBaselineNetworks: (options?: {
    refreshScan?: boolean;
    scanSettleMs?: number;
    useDeviceIntelligence?: boolean;
    persistInventory?: boolean;
    location?: {
      latitude: number;
      longitude: number;
      source: 'browser' | 'manual';
      label?: string | null;
    } | null;
  }) =>
    ipcRenderer.invoke('baseline:networks', options),
  runConnectivityCheck: (options?: { downloadBytes?: number; timeoutMs?: number }) =>
    ipcRenderer.invoke('connectivity:check', options),
  getRadioChronAnalysis: (options?: { refreshScan?: boolean }) =>
    ipcRenderer.invoke('radiochron:analysis', options),
  getRadioChronChronicleStatus: () => ipcRenderer.invoke('radiochron:chronicle-status'),
  getRadioChronChronicleRecent: (options?: { maxEntries?: number }) =>
    ipcRenderer.invoke('radiochron:chronicle-recent', options),
  scanBluetooth: (options?: { durationMs?: number; zone?: string | null }) =>
    ipcRenderer.invoke('radiochron:ble-scan', options),
  resetBluetoothTracker: () => ipcRenderer.invoke('radiochron:ble-reset'),
  scanLocalNetwork: (options: { mode: 'passive' | 'poll' | 'active'; snapshot?: unknown | null }) =>
    ipcRenderer.invoke('local-network:scan', options),
  getScanIdentityState: (options?: { interfaceName?: string | null; adapterName?: string | null }) =>
    ipcRenderer.invoke('scan-identity:state', options),
  applyScanIdentity: (options: {
    interfaceName?: string | null;
    adapterName?: string | null;
    computerName?: string | null;
    macAddress?: string | null;
    restartAdapter?: boolean;
  }) => ipcRenderer.invoke('scan-identity:apply', options),
  restoreScanIdentity: (options?: {
    interfaceName?: string | null;
    adapterName?: string | null;
    restartAdapter?: boolean;
  }) => ipcRenderer.invoke('scan-identity:restore', options),
  createBaselineDiagnosticsBundle: (options?: {
    lastRuns?: number;
    lastEvents?: number;
    windowMinutes?: number;
    minCycles?: number;
  }) => ipcRenderer.invoke('baseline:diagnostics', options),
  getBaselineDiagnosticsBundles: (options?: { last?: number }) => ipcRenderer.invoke('baseline:diagnostics:list', options),
  getBaselineRuns: (options?: { last?: number }) => ipcRenderer.invoke('baseline:runs', options),
  collectBaselineSample: (options?: { durationSeconds?: number; intervalSeconds?: number; maxEvents?: number }) =>
    ipcRenderer.invoke('baseline:collectSample', options),
  cancelBaselineCollection: () => ipcRenderer.invoke('baseline:cancelCollection'),
  getBaselineRunAnalysis: (options: { runId: string; windowMinutes?: number; minCycles?: number }) =>
    ipcRenderer.invoke('baseline:analyze', options),
  getBaselineRunComparison: (options: {
    baselineRunId: string;
    candidateRunId: string;
    windowMinutes?: number;
    minCycles?: number;
  }) => ipcRenderer.invoke('baseline:compare', options),
  getBaselineEvents: (options?: { last?: number }) => ipcRenderer.invoke('baseline:events', options),
  getBaselineTimeline: (options?: { last?: number; windowMinutes?: number; minCycles?: number }) =>
    ipcRenderer.invoke('baseline:timeline', options),
  updateDeviceIntelligence: (options: { provider: 'smart' | 'codex' | 'claude'; network: unknown; jobId?: string }) =>
    ipcRenderer.invoke('device:intelligence:update', options),
  runDeviceVulnerabilityLookup: (options: {
    mode: 'passive';
    network: unknown;
    selectedCheckIds?: string[];
    operatorNote?: string | null;
  }) =>
    ipcRenderer.invoke('device:vulnerability:lookup', options),
  getDeviceHistory: (options?: { newWindowHours?: number }) =>
    ipcRenderer.invoke('device:history', options),
  getScanLocations: () => ipcRenderer.invoke('scan-locations:list'),
  cancelDeviceIntelligenceUpdate: (options: { jobId: string }) =>
    ipcRenderer.invoke('device:intelligence:cancel', options),
  getWifiProfileSecret: (options: { ssid: string }) => ipcRenderer.invoke('wifi:profile-secret', options),
  runAiThreatReview: (options: {
    provider: 'codex' | 'claude';
    scope: 'map' | 'detector';
    networks?: unknown[];
    snapshot?: unknown | null;
    alerts?: unknown[];
  }) => ipcRenderer.invoke('ai:threat-review', options),
  exportReportPdf: (options: { html: string; filename?: string | null }) =>
    ipcRenderer.invoke('report:export-pdf', options)
});
