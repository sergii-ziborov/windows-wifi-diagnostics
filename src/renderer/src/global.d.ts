import type {
  AiThreatReviewResult,
  AiThreatReviewScope,
  BaselineEventsResult,
  BaselineRunAnalysisResult,
  BaselineRunComparisonResult,
  BaselineRunsResult,
  BaselineNetworksResult,
  BaselineStatus,
  BaselineTimelineResult,
  BaselineCollectionCancelResult,
  BaselineDiagnosticsBundleResult,
  BaselineDiagnosticsBundlesResult,
  CollectResult,
  ConnectivityCheckResult,
  DeviceIntelligenceUpdateResult,
  DeviceHistoryResult,
  DeviceVulnerabilityLookupResult,
  DetectorAlert,
  LocalNetworkScanMode,
  LocalNetworkScanResult,
  ScanIdentityChangeRequest,
  ScanIdentityChangeResult,
  ScanIdentityState,
  ScanLocationInput,
  ScanLocationsResult,
  WifiProfileSecretResult,
  WindowsWifiNetwork,
  WindowsWifiSnapshot
} from '../../collector/types';

interface MonitorBridgeCapabilities {
  schema: 'monitor.bridge_capabilities.v1';
  generated_at_utc: string;
  demo_mode: boolean;
  platform: NodeJS.Platform;
  ipc: {
    device_vulnerability_lookup: boolean;
    device_history: boolean;
    device_intelligence_update: boolean;
    ai_threat_review: boolean;
    wifi_profile_secret: boolean;
    connectivity_check: boolean;
    local_network_scan: boolean;
    scan_identity: boolean;
    scan_locations: boolean;
    report_pdf_export: boolean;
  };
}

declare global {
  interface Window {
    monitor?: {
      getBridgeCapabilities?: () => Promise<MonitorBridgeCapabilities>;
      getBaselineStatus: () => Promise<BaselineStatus>;
      getBaselineNetworks: (options?: {
        refreshScan?: boolean;
        scanSettleMs?: number;
        useDeviceIntelligence?: boolean;
        persistInventory?: boolean;
        location?: ScanLocationInput | null;
      }) => Promise<BaselineNetworksResult>;
      runConnectivityCheck?: (options?: { downloadBytes?: number; timeoutMs?: number }) => Promise<ConnectivityCheckResult>;
      scanLocalNetwork?: (options: {
        mode: LocalNetworkScanMode;
        snapshot?: WindowsWifiSnapshot | null;
      }) => Promise<LocalNetworkScanResult>;
      getScanIdentityState?: (options?: {
        interfaceName?: string | null;
        adapterName?: string | null;
      }) => Promise<ScanIdentityState>;
      applyScanIdentity?: (options: ScanIdentityChangeRequest) => Promise<ScanIdentityChangeResult>;
      restoreScanIdentity?: (options?: Pick<ScanIdentityChangeRequest, 'interfaceName' | 'adapterName' | 'restartAdapter'>) => Promise<ScanIdentityChangeResult>;
      createBaselineDiagnosticsBundle: (options?: {
        lastRuns?: number;
        lastEvents?: number;
        windowMinutes?: number;
        minCycles?: number;
      }) => Promise<BaselineDiagnosticsBundleResult>;
      getBaselineDiagnosticsBundles: (options?: { last?: number }) => Promise<BaselineDiagnosticsBundlesResult>;
      getBaselineRuns: (options?: { last?: number }) => Promise<BaselineRunsResult>;
      collectBaselineSample: (options?: {
        durationSeconds?: number;
        intervalSeconds?: number;
        maxEvents?: number;
      }) => Promise<CollectResult>;
      cancelBaselineCollection: () => Promise<BaselineCollectionCancelResult>;
      getBaselineRunAnalysis: (options: {
        runId: string;
        windowMinutes?: number;
        minCycles?: number;
      }) => Promise<BaselineRunAnalysisResult>;
      getBaselineRunComparison: (options: {
        baselineRunId: string;
        candidateRunId: string;
        windowMinutes?: number;
        minCycles?: number;
      }) => Promise<BaselineRunComparisonResult>;
      getBaselineEvents: (options?: { last?: number }) => Promise<BaselineEventsResult>;
      getBaselineTimeline: (options?: {
        last?: number;
        windowMinutes?: number;
        minCycles?: number;
      }) => Promise<BaselineTimelineResult>;
      updateDeviceIntelligence: (options: {
        provider: 'smart' | 'codex' | 'claude';
        network: WindowsWifiNetwork;
        jobId?: string;
      }) => Promise<DeviceIntelligenceUpdateResult>;
      runDeviceVulnerabilityLookup: (options: {
        mode: 'passive';
        network: WindowsWifiNetwork;
        selectedCheckIds?: string[];
        operatorNote?: string | null;
      }) => Promise<DeviceVulnerabilityLookupResult>;
      getDeviceHistory: (options?: { newWindowHours?: number }) => Promise<DeviceHistoryResult>;
      getScanLocations?: () => Promise<ScanLocationsResult>;
      cancelDeviceIntelligenceUpdate: (options: { jobId: string }) => Promise<{ cancelled: boolean }>;
      getWifiProfileSecret: (options: { ssid: string }) => Promise<WifiProfileSecretResult>;
      runAiThreatReview: (options: {
        provider: 'codex' | 'claude';
        scope: AiThreatReviewScope;
        networks?: WindowsWifiNetwork[];
        snapshot?: WindowsWifiSnapshot | null;
        alerts?: DetectorAlert[];
      }) => Promise<AiThreatReviewResult>;
      exportReportPdf?: (options: {
        html: string;
        filename?: string | null;
      }) => Promise<{ saved: boolean; path: string | null; error: string | null }>;
    };
  }
}

export {};
