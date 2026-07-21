import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
  type MouseEvent as ReactMouseEvent,
  type PointerEvent as ReactPointerEvent,
  type ReactNode,
  type WheelEvent
} from 'react';
import { createPortal } from 'react-dom';
import accessPointVisualUrl from './assets/device-visuals/access-point.svg';
import hiddenNetworkVisualUrl from './assets/device-visuals/hidden-network.svg';
import hotspotVisualUrl from './assets/device-visuals/hotspot.svg';
import localMacVisualUrl from './assets/device-visuals/local-mac.svg';
import meshVisualUrl from './assets/device-visuals/mesh.svg';
import printerVisualUrl from './assets/device-visuals/printer.svg';
import routerVisualUrl from './assets/device-visuals/router.svg';
import speakerVisualUrl from './assets/device-visuals/speaker.svg';
import unknownDeviceVisualUrl from './assets/device-visuals/unknown-device.svg';
import wifiDirectVisualUrl from './assets/device-visuals/wifi-direct.svg';
import {
  applyDeviceIntelligenceOverrideToNetwork,
  patchNetworkListWithDeviceIntelligence,
  sameNetworkIdentity
} from './deviceIntelligencePatch';
import type {
  AiThreatReviewResult,
  AiThreatReviewScope,
  BaselineEventsResult,
  BaselineNetworksResult,
  BaselineRunAnalysisResult,
  BaselineRunComparisonResult,
  BaselineRunEvidenceReport,
  BaselineRunObservation,
  BaselineRunRecord,
  BaselineRunsResult,
  BaselineStatus,
  BaselineTimelineResult,
  BaselineDiagnosticsBundleResult,
  BaselineDiagnosticsBundleRecord,
  BaselineDiagnosticsBundlesResult,
  ClientTimelineEvent,
  CollectResult,
  ConnectivityCheckResult,
  CollectorSourceStatus,
  DeviceIntelligenceUpdateResult,
  DeviceHistoryResult,
  DeviceHistoryRecord,
  DeviceHistoryHourBucket,
  DeviceVulnerabilityLookupResult,
  DetectorAlert,
  DeviceIntelligenceOverride,
  LocalNetworkDevice,
  LocalNetworkScanMode,
  LocalNetworkScanResult,
  ScanIdentityChangeResult,
  ScanIdentityState,
  VulnerabilityScanPlan,
  VulnerabilityScanPlanCheck,
  NumericSummary,
  ScanLocationInput,
  ScanLocationRecord,
  ScanLocationsResult,
  VulnerabilityIntelAssessment,
  VulnerabilityLookupMode,
  WifiProfileSecretResult,
  WifiInformationElementSummary,
  WifiSecurityAssessment,
  WindowsWifiNetwork,
  WindowsWifiSnapshot,
  WindowsWifiEvent
} from '../../collector/types';

// Render modal overlays through a portal to document.body so their fixed-position
// backdrops escape ancestor stacking contexts (panels use clip-path, which both
// creates a stacking context and acts as the containing block for fixed children).
function ModalPortal({ children }: { children: ReactNode }) {
  return createPortal(children, document.body);
}

interface BaselineViewState {
  status: BaselineStatus | null;
  networks: BaselineNetworksResult | null;
  runs: BaselineRunsResult | null;
  events: BaselineEventsResult | null;
  timeline: BaselineTimelineResult | null;
  diagnostics: BaselineDiagnosticsBundlesResult | null;
  loading: boolean;
  error: string | null;
  lastUpdated: string | null;
}

interface RunAnalysisViewState {
  analysis: BaselineRunAnalysisResult | null;
  loading: boolean;
  error: string | null;
}

interface SampleCollectState {
  collecting: boolean;
  result: CollectResult | null;
  error: string | null;
  startedAtMs: number | null;
  durationSeconds: number | null;
  presetLabel: string | null;
  cancelRequested: boolean;
}

interface RunComparisonViewState {
  comparison: BaselineRunComparisonResult | null;
  loading: boolean;
  error: string | null;
}

interface DiagnosticsViewState {
  creating: boolean;
  result: BaselineDiagnosticsBundleResult | null;
  error: string | null;
}

interface ConnectivityCheckState {
  loading: boolean;
  result: ConnectivityCheckResult | null;
  error: string | null;
}

interface LocalNetworkScanState {
  loading: boolean;
  mode: LocalNetworkScanMode | null;
  result: LocalNetworkScanResult | null;
  error: string | null;
}

interface ScanIdentityViewState {
  loading: boolean;
  applying: boolean;
  restoring: boolean;
  state: ScanIdentityState | null;
  result: ScanIdentityChangeResult | null;
  error: string | null;
  computerNameInput: string;
  macAddressInput: string;
  restartAdapter: boolean;
}

interface ScanVisibilityProfile {
  mode: LocalNetworkScanMode;
  label: string;
  title: string;
  risk: 'low' | 'medium' | 'high';
  traffic: string;
  traces: string;
  operatorNote: string;
  buttonLabel: string;
  runningLabel: string;
}

interface ScanLocationState {
  latitudeInput: string;
  longitudeInput: string;
  labelInput: string;
  source: ScanLocationInput['source'] | null;
  locating: boolean;
  error: string | null;
}

interface CollectionPreset {
  label: string;
  durationSeconds: number;
  intervalSeconds: number;
  maxEvents: number;
}

interface LoadBaselineOptions {
  refreshScan?: boolean;
  persistInventory?: boolean;
}

interface NetworkFreshnessState {
  checkedAtUtc: string | null;
  acceptedAtUtc: string | null;
  latestScanAtUtc: string | null;
  retainedLastGood: boolean;
  narrowScanCount: number;
  latestScanSsidCount: number | null;
  latestScanBssidCount: number | null;
  retainedSsidCount: number | null;
  retainedBssidCount: number | null;
  latestError: string | null;
}

interface NetworkMergeResult {
  networks: BaselineNetworksResult | null;
  freshness: NetworkFreshnessState;
}

interface RememberedNetwork {
  key: string;
  network: WindowsWifiNetwork;
  firstSeenUtc: string;
  lastSeenUtc: string;
  seenCount: number;
  missedScans: number;
}

interface NetworkHistorySnapshot {
  id: string;
  tsUtc: string;
  items: RememberedNetwork[];
  ssidCount: number;
  bssidCount: number;
  liveCount: number;
  strongestSignal: number | null;
}

interface NetworkDeviceVisual {
  kind: string;
  label: string;
  image: string;
  alt: string;
}

interface MapPan {
  x: number;
  y: number;
}

interface MapPositionedItem {
  kind: 'item';
  id: string;
  item: RememberedNetwork & { ageSeconds: number | null; isStale: boolean };
  index: number;
  position: { x: number; y: number };
}

interface MapCluster {
  kind: 'cluster';
  id: string;
  items: Array<RememberedNetwork & { ageSeconds: number | null; isStale: boolean }>;
  position: { x: number; y: number };
  liveCount: number;
  reviewCount: number;
  strongestSignal: number | null;
}

type MapDrawable = MapPositionedItem | MapCluster;

interface MapConnectionLink {
  id: string;
  sourceKey: string | null;
  targetKey: string;
  kind: 'connected' | 'mesh' | 'memory' | 'mesh_peer';
  start: { x: number; y: number };
  end: { x: number; y: number };
  sourceRadiusPx: number;
  targetRadiusPx: number;
  avoidPoints?: Array<{ x: number; y: number }>;
  signal: number | null;
  label: string;
  detail: string;
}

interface MapViewportSize {
  width: number;
  height: number;
}

interface MapHoverTooltip {
  id: string;
  x: number;
  y: number;
  title: string;
  subtitle: string;
  facts: Array<{ label: string; value: string }>;
}

interface MapLayoutContext {
  groupCounts: Map<string, number>;
  connectedGroupKey: string | null;
  connectedNetwork: WindowsWifiNetwork | null;
}

type MapHistoryFilter = 'current' | '5m' | '15m' | '30m' | '1h' | '2h' | '6h' | '12h' | '24h' | 'today' | 'all' | 'old';
type MapSecurityVisualTone = 'wpa3' | 'enterprise' | 'wpa2' | 'legacy' | 'open' | 'unknown' | 'suspect';

interface ProfileSecretState {
  loading: boolean;
  revealed: boolean;
  result: WifiProfileSecretResult | null;
  error: string | null;
}

interface VulnerabilityLookupRunOptions {
  selectedCheckIds: string[];
  operatorNote: string | null;
}

type LeakLookupStatus = 'saved' | 'failed' | 'stopped';

interface PdfExportState {
  exporting: boolean;
  result: string | null;
  error: string | null;
}

type LeakLookupRecordAppender = (
  targetNetwork: WindowsWifiNetwork,
  result: DeviceVulnerabilityLookupResult | null,
  status: LeakLookupStatus,
  error?: string | null,
  fallbackMode?: VulnerabilityLookupMode,
  plannedScanPlan?: VulnerabilityScanPlan | null
) => void;

interface VulnerabilityScanCheckDefinition {
  id: string;
  modes: VulnerabilityLookupMode[];
  label: string;
  description: string;
  impact: 'none' | 'local_only' | 'low' | 'manual_disruptive';
  networkEffect: string;
  defaultSelected: boolean;
  available: boolean;
  blockedReason: string | null;
}

interface AiThreatReviewRequest {
  scope: AiThreatReviewScope;
  networks: WindowsWifiNetwork[];
  snapshot: WindowsWifiSnapshot | null;
  alerts: DetectorAlert[];
}

type ChannelBand = '2.4 GHz' | '5 GHz' | '6 GHz' | 'Other';
type ChannelChartMode = 'rows' | 'matrix';

interface ChannelCongestionBucket {
  id: string;
  band: ChannelBand;
  channel: number;
  items: Array<RememberedNetwork & { ageSeconds: number | null; isStale: boolean }>;
  liveCount: number;
  staleCount: number;
  strongCount: number;
  mediumCount: number;
  weakCount: number;
  strongestSignal: number | null;
  averageSignal: number | null;
  utilizationPercent: number | null;
  overlapScore: number;
  congestionScore: number;
  bssLoadCount: number;
}

interface SourceControls {
  wlanEvents: boolean;
  nearbyAps: boolean;
}

type AppTab = 'overview' | 'map' | 'network' | 'reports' | 'channels';

type SourceControlKey = keyof SourceControls;

type DeviceInsightKind = 'vendor' | 'exposure' | 'security' | 'radio';

type NetworkIntelFilterKind =
  | 'all'
  | 'live'
  | 'stale'
  | 'review'
  | 'source'
  | 'newDevice'
  | 'localNetwork'
  | 'knownVendor'
  | 'unknownVendor'
  | 'localMac'
  | 'highConfidence'
  | 'ssid'
  | 'vendor'
  | 'deviceHint'
  | 'unknownOui';

interface NetworkIntelFilter {
  kind: NetworkIntelFilterKind;
  label: string;
  value?: string;
}

type SourceDescriptorKey = 'wifiStatus' | SourceControlKey;

interface SourceDescriptor {
  key: SourceDescriptorKey;
  title: string;
  role: string;
  command: string;
  sourceNames: Array<CollectorSourceStatus['name']>;
  optionalSourceNames?: Array<CollectorSourceStatus['name']>;
}

const DEFAULT_SOURCE_CONTROLS: SourceControls = {
  wlanEvents: true,
  nearbyAps: true
};

const ALL_NETWORK_INTEL_FILTER: NetworkIntelFilter = {
  kind: 'all',
  label: 'All APs'
};

const LIVE_NETWORK_INTEL_FILTER: NetworkIntelFilter = {
  kind: 'live',
  label: 'Live APs'
};

const STALE_NETWORK_INTEL_FILTER: NetworkIntelFilter = {
  kind: 'stale',
  label: 'Stale APs'
};

const REVIEW_NETWORK_INTEL_FILTER: NetworkIntelFilter = {
  kind: 'review',
  label: 'Needs review'
};

const SOURCE_NETWORK_INTEL_FILTER: NetworkIntelFilter = {
  kind: 'source',
  label: 'Latest source scan'
};

const NEW_DEVICE_NETWORK_INTEL_FILTER: NetworkIntelFilter = {
  kind: 'newDevice',
  label: 'New devices'
};

const LOCAL_NETWORK_INTEL_FILTER: NetworkIntelFilter = {
  kind: 'localNetwork',
  label: 'Current local network'
};

const SOURCE_DESCRIPTORS: SourceDescriptor[] = [
  {
    key: 'wifiStatus',
    title: 'Wi-Fi status snapshot',
    role: 'Adapter, SSID, BSSID, channel, signal, rates',
    command: 'netsh wlan show interfaces',
    sourceNames: ['netsh_wlan_interfaces']
  },
  {
    key: 'wlanEvents',
    title: 'WLAN lifecycle events',
    role: 'Connect, reconnect, association and security evidence',
    command: 'Microsoft-Windows-WLAN-AutoConfig/Operational',
    sourceNames: ['windows_wlan_autoconfig_operational']
  },
  {
    key: 'nearbyAps',
    title: 'Nearby AP inventory',
    role: 'SSID, BSSID, channel, signal, security, BSS load',
    command: 'Native WlanScan + netsh wlan show networks mode=bssid',
    sourceNames: ['netsh_wlan_networks'],
    optionalSourceNames: ['windows_native_wifi_scan', 'windows_native_bss_list']
  }
];

const INITIAL_STATE: BaselineViewState = {
  status: null,
  networks: null,
  runs: null,
  events: null,
  timeline: null,
  diagnostics: null,
  loading: true,
  error: null,
  lastUpdated: null
};

const INITIAL_ANALYSIS_STATE: RunAnalysisViewState = {
  analysis: null,
  loading: false,
  error: null
};

const INITIAL_SAMPLE_STATE: SampleCollectState = {
  collecting: false,
  result: null,
  error: null,
  startedAtMs: null,
  durationSeconds: null,
  presetLabel: null,
  cancelRequested: false
};

const INITIAL_COMPARISON_STATE: RunComparisonViewState = {
  comparison: null,
  loading: false,
  error: null
};

const INITIAL_DIAGNOSTICS_STATE: DiagnosticsViewState = {
  creating: false,
  result: null,
  error: null
};

const INITIAL_CONNECTIVITY_CHECK_STATE: ConnectivityCheckState = {
  loading: false,
  result: null,
  error: null
};

const INITIAL_LOCAL_NETWORK_SCAN_STATE: LocalNetworkScanState = {
  loading: false,
  mode: null,
  result: null,
  error: null
};

const INITIAL_SCAN_IDENTITY_STATE: ScanIdentityViewState = {
  loading: false,
  applying: false,
  restoring: false,
  state: null,
  result: null,
  error: null,
  computerNameInput: '',
  macAddressInput: '',
  restartAdapter: true
};

const INITIAL_SCAN_LOCATION_STATE: ScanLocationState = {
  latitudeInput: '',
  longitudeInput: '',
  labelInput: '',
  source: null,
  locating: false,
  error: null
};

const COLLECTION_PRESETS: CollectionPreset[] = [
  { label: '1m', durationSeconds: 60, intervalSeconds: 5, maxEvents: 100 },
  { label: '5m', durationSeconds: 300, intervalSeconds: 5, maxEvents: 250 },
  { label: '10m', durationSeconds: 600, intervalSeconds: 5, maxEvents: 500 }
];
const APP_TABS: Array<{ key: AppTab; label: string }> = [
  { key: 'overview', label: 'Overview' },
  { key: 'map', label: 'Map' },
  { key: 'network', label: 'Network' },
  { key: 'reports', label: 'Reports' },
  { key: 'channels', label: 'Channels' }
];
const DEVICE_VISUALS = {
  access: {
    kind: 'access',
    label: 'AP',
    image: accessPointVisualUrl,
    alt: 'Enterprise access point'
  },
  router: {
    kind: 'router',
    label: 'RTR',
    image: routerVisualUrl,
    alt: 'Router or gateway'
  },
  mesh: {
    kind: 'mesh',
    label: 'MSH',
    image: meshVisualUrl,
    alt: 'Mesh node'
  },
  hotspot: {
    kind: 'hotspot',
    label: 'HOT',
    image: hotspotVisualUrl,
    alt: 'Mobile hotspot'
  },
  printer: {
    kind: 'printer',
    label: 'PRN',
    image: printerVisualUrl,
    alt: 'Printer'
  },
  direct: {
    kind: 'direct',
    label: 'DIR',
    image: wifiDirectVisualUrl,
    alt: 'Wi-Fi Direct device'
  },
  hidden: {
    kind: 'hidden',
    label: 'HID',
    image: hiddenNetworkVisualUrl,
    alt: 'Hidden network'
  },
  local: {
    kind: 'local',
    label: 'LOC',
    image: localMacVisualUrl,
    alt: 'Local randomized MAC'
  },
  speaker: {
    kind: 'speaker',
    label: 'SPK',
    image: speakerVisualUrl,
    alt: 'Speaker or soundbar'
  },
  unknown: {
    kind: 'unknown',
    label: 'UNK',
    image: unknownDeviceVisualUrl,
    alt: 'Unknown device'
  }
} satisfies Record<string, NetworkDeviceVisual>;

type SignalStrength = { tone: 'strong' | 'medium' | 'weak' | 'none'; level: number };

function networkSignalStrength(percent: number | null | undefined): SignalStrength {
  if (percent === null || percent === undefined || !Number.isFinite(percent)) {
    return { tone: 'none', level: 0 };
  }
  if (percent >= 66) {
    return { tone: 'strong', level: 3 };
  }
  if (percent >= 33) {
    return { tone: 'medium', level: 2 };
  }
  return { tone: 'weak', level: 1 };
}

// Compact 3-bar signal meter, colored green/orange/red by strength.
function SignalBars({ percent }: { percent: number | null | undefined }) {
  const { tone, level } = networkSignalStrength(percent);
  const title =
    percent === null || percent === undefined || !Number.isFinite(percent)
      ? 'Signal unknown'
      : `Signal ${Math.round(percent)}%`;
  return (
    <span className={`signal-bars signal-bars-${tone}`} title={title} aria-label={title}>
      {[1, 2, 3].map((bar) => (
        <span key={bar} className={`signal-bar${bar <= level ? ' signal-bar-on' : ''}`} aria-hidden="true" />
      ))}
    </span>
  );
}

// Human-readable SSID: real name, or a clear placeholder for hidden networks.
function formatNetworkSsidLabel(network: WindowsWifiNetwork): string {
  if (network.ssid && network.ssid.trim().length > 0) {
    return network.ssid;
  }
  return 'Hidden network';
}

// Human-readable vendor: real vendor (shortened), "Randomized MAC" for private addresses, else "Unknown vendor".
function formatNetworkVendorLabel(network: WindowsWifiNetwork): string {
  const vendor = network.mac_enrichment?.vendor;
  if (vendor && vendor.trim().length > 0) {
    return formatShortVendor(vendor);
  }
  if (network.mac_enrichment?.address_scope === 'local') {
    return 'Randomized MAC';
  }
  return 'Unknown vendor';
}

// Freshly-seen APs get a live ticking age (teal); stale ones stay muted.
function isFreshMapItem(ageSeconds: number | null): boolean {
  return ageSeconds !== null && ageSeconds <= 120;
}

// Short relative age for map nodes: ticking seconds when fresh, coarse (m/h/d) when old.
function formatCompactAge(ageSeconds: number | null): string {
  if (ageSeconds === null) {
    return 'unknown';
  }
  if (ageSeconds < 60) {
    return `${ageSeconds}s ago`;
  }
  if (ageSeconds < 3600) {
    return `${Math.floor(ageSeconds / 60)}m ago`;
  }
  if (ageSeconds < 86_400) {
    return `${Math.floor(ageSeconds / 3600)}h ago`;
  }
  return `${Math.floor(ageSeconds / 86_400)}d ago`;
}

const BASELINE_REFRESH_MS = 30_000;
const NETWORK_REFRESH_MS = 60_000;
const NETWORK_SCAN_SETTLE_MS = 5_500;
const NETWORK_STALE_MS = 90_000;
const NETWORK_LAST_GOOD_HOLD_MS = 5 * 60_000;
const NETWORK_MEMORY_HOLD_MS = 24 * 60 * 60_000;
const NETWORK_HISTORY_LIMIT = 96;
// Persist a recent window of snapshots so the history scrubber is populated the
// moment the map opens, instead of starting empty every session.
const NETWORK_HISTORY_STORAGE_KEY = 'monitor.network_history.v1';
const NETWORK_HISTORY_PERSIST_LIMIT = 30;
// Watchlist of local-network devices the operator wants to keep an eye on across
// scans and sessions. Keyed by MAC when known (survives DHCP lease changes),
// otherwise by IP.
const LOCAL_NETWORK_STARRED_STORAGE_KEY = 'monitor.local_network_starred.v1';
const LOCAL_NETWORK_STARRED_LIMIT = 200;
const SAMPLE_RESULT_VISIBLE_MS = 12_000;
const LOCAL_MAP_NODE_KEY = '__local_wifi_client__';
const MAP_VISIBLE_ITEM_LIMIT = 80;
const MAP_NODE_ENDPOINT_RADIUS_PX = 32;
const MAP_CLUSTER_ENDPOINT_RADIUS_PX = 32;
const MAP_RF_NODE_COLLISION_RADIUS_PX = 52;
const MAP_RF_CLUSTER_COLLISION_RADIUS_PX = 38;
const MAP_RF_CENTER_COLLISION_RADIUS_PX = 62;
const MAP_RF_COLLISION_ITERATIONS = 72;
const MAP_FAR_RING_RADIUS_PERCENT = 41;
const MAP_COORDINATE_FIX_OBSERVATIONS = 10;
const LEGACY_MAP_LAYOUT_STORAGE_KEYS = [
  'monitor.map_layout.v1',
  'monitor.map_layout.v2',
  'monitor.map_layout.v3',
  'monitor.map_layout.v4',
  'monitor.map_layout.v5',
  'monitor.map_layout.v6',
  'monitor.map_layout.v7'
];
const MAP_UNCLUSTER_ZOOM_RF = 2.5;
const MAP_DEFAULT_HISTORY_FILTER: MapHistoryFilter = 'all';
const MAP_HISTORY_FILTERS: Array<{ value: MapHistoryFilter; label: string }> = [
  { value: 'current', label: 'Current scan' },
  { value: '5m', label: '5m' },
  { value: '15m', label: '15m' },
  { value: '30m', label: '30m' },
  { value: '1h', label: '1h' },
  { value: '2h', label: '2h' },
  { value: '6h', label: '6h' },
  { value: '12h', label: '12h' },
  { value: '24h', label: '24h' },
  { value: 'today', label: 'Today' },
  { value: 'all', label: 'All history' },
  { value: 'old', label: 'Old' }
];
const GEO_LATITUDE_PLACEHOLDER = 'lat';
const GEO_LONGITUDE_PLACEHOLDER = 'lng';
const VULNERABILITY_SCAN_CHECK_DEFINITIONS: VulnerabilityScanCheckDefinition[] = [
  {
    id: 'inventory_correlation',
    modes: ['passive'],
    label: 'Saved inventory correlation',
    description: 'Compare BSSID, SSID, vendor, security, and history fingerprints against saved observations.',
    impact: 'local_only',
    networkEffect: 'No network traffic; reads local SQLite inventory.',
    defaultSelected: true,
    available: true,
    blockedReason: null
  },
  {
    id: 'radio_security_metadata',
    modes: ['passive'],
    label: 'Radio and security metadata',
    description: 'Use Windows scan metadata, advertised auth/cipher, band, channel, rates, and native BSS fields.',
    impact: 'none',
    networkEffect: 'No extra AP traffic beyond normal Windows telemetry already collected.',
    defaultSelected: true,
    available: true,
    blockedReason: null
  },
  {
    id: 'vendor_advisory_context',
    modes: ['passive'],
    label: 'Vendor advisory context',
    description: 'Save OUI/vendor/device-role evidence and advisory references for later CVE/CPE work.',
    impact: 'local_only',
    networkEffect: 'No packets sent to the AP.',
    defaultSelected: true,
    available: true,
    blockedReason: null
  },
  {
    id: 'identity_drift_review',
    modes: ['passive'],
    label: 'BSSID identity drift review',
    description: 'Flag same-looking AP identities that appear with changed BSSID/MAC fingerprints.',
    impact: 'local_only',
    networkEffect: 'No network traffic; compares saved AP observations.',
    defaultSelected: true,
    available: true,
    blockedReason: null
  },
  {
    id: 'pmf_wpa3_capability_review',
    modes: ['passive'],
    label: 'PMF / WPA3 upgrade gap review',
    description: 'Record whether metadata suggests WPA2-only operation, transition risk, or missing WPA3/PMF evidence.',
    impact: 'none',
    networkEffect: 'No traffic; uses advertised security metadata and native information elements when available.',
    defaultSelected: true,
    available: true,
    blockedReason: null
  },
  {
    id: 'wps_metadata_review',
    modes: ['passive'],
    label: 'WPS exposure metadata review',
    description: 'Save whether WPS-like metadata needs manual router-side confirmation.',
    impact: 'none',
    networkEffect: 'No WPS exchange; records that WPS must be checked from router configuration or authorized tooling.',
    defaultSelected: false,
    available: true,
    blockedReason: null
  }
];
const SCAN_VISIBILITY_PROFILES: ScanVisibilityProfile[] = [
  {
    mode: 'passive',
    label: 'Full passive',
    title: 'Lowest footprint',
    risk: 'low',
    traffic: 'Reads local Windows cache/inventory only.',
    traces: 'Monitor sends no LAN probe traffic; normal OS traffic can still be logged.',
    operatorNote: 'Use for quiet map updates and vulnerability triage from saved evidence.',
    buttonLabel: 'Run passive',
    runningLabel: 'Reading cache'
  },
  {
    mode: 'poll',
    label: 'Visible PC',
    title: 'Partial visibility',
    risk: 'medium',
    traffic: 'Checks reachability for already visible neighbor IPs.',
    traces: 'Network monitoring may see source IP/MAC as this client or the applied scan identity.',
    operatorNote: 'Use when you need to separate active and stale devices without broad scanning.',
    buttonLabel: 'Run visible',
    runningLabel: 'Polling visible'
  },
  {
    mode: 'active',
    label: 'Active direct',
    title: 'High visibility',
    risk: 'high',
    traffic: 'Sends direct reachability probes and asks for host names on visible IPs.',
    traces: 'Likely to appear in ICMP, DNS/name-resolution, endpoint, NAC, or SIEM logs.',
    operatorNote: 'Use only when the extra LAN evidence is worth being obviously visible.',
    buttonLabel: 'Run active',
    runningLabel: 'Active polling'
  }
];

let bodyScrollLockCount = 0;
let bodyScrollPreviousHtmlOverflow = '';
let bodyScrollPreviousHtmlOverscrollBehavior = '';
let bodyScrollPreviousOverflow = '';
let bodyScrollPreviousOverscrollBehavior = '';
let bodyScrollPreviousPosition = '';
let bodyScrollPreviousTop = '';
let bodyScrollPreviousWidth = '';
let bodyScrollPreviousPaddingRight = '';
let bodyScrollPreviousScrollY = 0;

function useBodyScrollLock(active: boolean): void {
  useEffect(() => {
    if (!active || typeof document === 'undefined' || typeof window === 'undefined') {
      return undefined;
    }

    bodyScrollLockCount += 1;
    if (bodyScrollLockCount === 1) {
      const scrollbarGap = Math.max(0, window.innerWidth - document.documentElement.clientWidth);
      bodyScrollPreviousScrollY = window.scrollY || document.documentElement.scrollTop || 0;
      bodyScrollPreviousHtmlOverflow = document.documentElement.style.overflow;
      bodyScrollPreviousHtmlOverscrollBehavior = document.documentElement.style.overscrollBehavior;
      bodyScrollPreviousOverflow = document.body.style.overflow;
      bodyScrollPreviousOverscrollBehavior = document.body.style.overscrollBehavior;
      bodyScrollPreviousPosition = document.body.style.position;
      bodyScrollPreviousTop = document.body.style.top;
      bodyScrollPreviousWidth = document.body.style.width;
      bodyScrollPreviousPaddingRight = document.body.style.paddingRight;
      document.documentElement.style.overflow = 'hidden';
      document.documentElement.style.overscrollBehavior = 'none';
      document.body.style.overflow = 'hidden';
      document.body.style.overscrollBehavior = 'none';
      document.body.style.position = 'fixed';
      document.body.style.top = `-${bodyScrollPreviousScrollY}px`;
      document.body.style.width = '100%';
      if (scrollbarGap > 0) {
        document.body.style.paddingRight = `${scrollbarGap}px`;
      }
    }

    return () => {
      bodyScrollLockCount = Math.max(0, bodyScrollLockCount - 1);
      if (bodyScrollLockCount === 0) {
        document.documentElement.style.overflow = bodyScrollPreviousHtmlOverflow;
        document.documentElement.style.overscrollBehavior = bodyScrollPreviousHtmlOverscrollBehavior;
        document.body.style.overflow = bodyScrollPreviousOverflow;
        document.body.style.overscrollBehavior = bodyScrollPreviousOverscrollBehavior;
        document.body.style.position = bodyScrollPreviousPosition;
        document.body.style.top = bodyScrollPreviousTop;
        document.body.style.width = bodyScrollPreviousWidth;
        document.body.style.paddingRight = bodyScrollPreviousPaddingRight;
        window.scrollTo(0, bodyScrollPreviousScrollY);
      }
    };
  }, [active]);
}

const INITIAL_NETWORK_FRESHNESS: NetworkFreshnessState = {
  checkedAtUtc: null,
  acceptedAtUtc: null,
  latestScanAtUtc: null,
  retainedLastGood: false,
  narrowScanCount: 0,
  latestScanSsidCount: null,
  latestScanBssidCount: null,
  retainedSsidCount: null,
  retainedBssidCount: null,
  latestError: null
};

export function App() {
  const [viewState, setViewState] = useState<BaselineViewState>(INITIAL_STATE);
  const [activeTab, setActiveTab] = useState<AppTab>('overview');
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const [analysisState, setAnalysisState] = useState<RunAnalysisViewState>(INITIAL_ANALYSIS_STATE);
  const [sampleState, setSampleState] = useState<SampleCollectState>(INITIAL_SAMPLE_STATE);
  const [comparisonState, setComparisonState] = useState<RunComparisonViewState>(INITIAL_COMPARISON_STATE);
  const [diagnosticsState, setDiagnosticsState] = useState<DiagnosticsViewState>(INITIAL_DIAGNOSTICS_STATE);
  const [connectivityCheckState, setConnectivityCheckState] = useState<ConnectivityCheckState>(INITIAL_CONNECTIVITY_CHECK_STATE);
  const [localNetworkScanState, setLocalNetworkScanState] = useState<LocalNetworkScanState>(INITIAL_LOCAL_NETWORK_SCAN_STATE);
  const [scanIdentityState, setScanIdentityState] = useState<ScanIdentityViewState>(INITIAL_SCAN_IDENTITY_STATE);
  const [scanLocationState, setScanLocationState] = useState<ScanLocationState>(INITIAL_SCAN_LOCATION_STATE);
  const [scanLocations, setScanLocations] = useState<ScanLocationsResult | null>(null);
  const [scanLocationsError, setScanLocationsError] = useState<string | null>(null);
  const [selectedScanLocationKey, setSelectedScanLocationKey] = useState<string | null>(null);
  const [baselineRunId, setBaselineRunId] = useState<string | null>(null);
  const [candidateRunId, setCandidateRunId] = useState<string | null>(null);
  const [collectionPresetIndex, setCollectionPresetIndex] = useState(0);
  const [sourceControls, setSourceControls] = useState<SourceControls>(DEFAULT_SOURCE_CONTROLS);
  const [nowMs, setNowMs] = useState(() => Date.now());
  const [networkFreshness, setNetworkFreshness] = useState<NetworkFreshnessState>(INITIAL_NETWORK_FRESHNESS);
  const [networkRefreshing, setNetworkRefreshing] = useState(false);
  const [rememberedNetworks, setRememberedNetworks] = useState<RememberedNetwork[]>([]);
  const [networkHistory, setNetworkHistory] = useState<NetworkHistorySnapshot[]>(loadPersistedNetworkHistory);
  const [deviceHistory, setDeviceHistory] = useState<DeviceHistoryResult | null>(null);
  const [deviceHistoryWindowHours] = useState(24);
  // "New" window is evaluated in the renderer against each record's first_seen_utc so sub-hour
  // windows (15/30 min) work; the backend floors newWindowHours to whole hours (min 1h).
  const [deviceHistoryNewWindowMinutes, setDeviceHistoryNewWindowMinutes] = useState(15);
  const [selectedHistoryId, setSelectedHistoryId] = useState<string | null>(null);
  const [networkIntelFilter, setNetworkIntelFilter] = useState<NetworkIntelFilter>(ALL_NETWORK_INTEL_FILTER);
  const [currentConnectionInsight, setCurrentConnectionInsight] = useState<DeviceInsightKind | null>(null);
  const [aiThreatReviewRequest, setAiThreatReviewRequest] = useState<AiThreatReviewRequest | null>(null);
  const networksRef = useRef<BaselineNetworksResult | null>(INITIAL_STATE.networks);
  const networkFreshnessRef = useRef<NetworkFreshnessState>(INITIAL_NETWORK_FRESHNESS);
  const networkRefreshInFlightRef = useRef(false);
  const lastHistorySnapshotKeyRef = useRef<string | null>(null);
  const collectionPreset = COLLECTION_PRESETS[collectionPresetIndex] ?? COLLECTION_PRESETS[0];

  useEffect(() => {
    clearLegacyMapLayoutStorage();
  }, []);

  const mergeNearbyNetworks = useCallback((nextNetworks: BaselineNetworksResult | null): BaselineNetworksResult | null => {
    const merged = mergeNearbyNetworkScan(
      networksRef.current,
      nextNetworks,
      networkFreshnessRef.current
    );

    networksRef.current = merged.networks;
    networkFreshnessRef.current = merged.freshness;
    setNetworkFreshness(merged.freshness);

    return merged.networks;
  }, []);

  const loadDeviceHistorySafely = useCallback(async (newWindowHours = deviceHistoryWindowHours): Promise<DeviceHistoryResult | null> => {
    // Device history feeds the per-AP enrichment (vendor/Watch/first-seen) shown across tabs.
    // On any failure we return null; callers keep their previous data.
    if (!window.monitor?.getDeviceHistory) {
      return null;
    }

    try {
      return await window.monitor.getDeviceHistory({ newWindowHours });
    } catch {
      return null;
    }
  }, [deviceHistoryWindowHours]);

  const currentScanLocationInput = useCallback((): ScanLocationInput | null => {
    const latitude = parseCoordinate(scanLocationState.latitudeInput, -90, 90);
    const longitude = parseCoordinate(scanLocationState.longitudeInput, -180, 180);
    if (latitude === null || longitude === null || !scanLocationState.source) {
      return null;
    }

    return {
      latitude,
      longitude,
      source: scanLocationState.source,
      label: scanLocationState.labelInput.trim() || null
    };
  }, [scanLocationState.labelInput, scanLocationState.latitudeInput, scanLocationState.longitudeInput, scanLocationState.source]);

  const loadScanLocationsSafely = useCallback(async (): Promise<ScanLocationsResult | null> => {
    if (!window.monitor?.getScanLocations) {
      setScanLocationsError('Scan locations are not available in this renderer bridge. Restart Monitor to load the latest preload.');
      return null;
    }

    try {
      const result = await window.monitor.getScanLocations();
      setScanLocationsError(null);
      return result;
    } catch (error: unknown) {
      setScanLocationsError(formatMonitorBridgeError(error, 'scan-locations:list'));
      return null;
    }
  }, []);

  const locateScanLocation = useCallback(() => {
    if (!navigator.geolocation) {
      setScanLocationState((current) => ({
        ...current,
        locating: false,
        error: 'Geolocation is not available in this Electron session.'
      }));
      return;
    }

    setScanLocationState((current) => ({ ...current, locating: true, error: null }));
    navigator.geolocation.getCurrentPosition(
      (position) => {
        setScanLocationState((current) => ({
          ...current,
          latitudeInput: position.coords.latitude.toFixed(6),
          longitudeInput: position.coords.longitude.toFixed(6),
          source: 'browser',
          locating: false,
          error: null
        }));
      },
      (error) => {
        setScanLocationState((current) => ({
          ...current,
          locating: false,
          error: error.message || 'Geolocation failed.'
        }));
      },
      {
        enableHighAccuracy: true,
        timeout: 12_000,
        maximumAge: 60_000
      }
    );
  }, []);

  const setManualScanCoordinates = useCallback((value: string, field: 'latitude' | 'longitude') => {
    const extracted = extractCoordinatesFromText(value);
    if (extracted) {
      setScanLocationState((current) => ({
        ...current,
        latitudeInput: extracted.latitude.toFixed(6),
        longitudeInput: extracted.longitude.toFixed(6),
        source: 'manual',
        error: null
      }));
      return;
    }

    setScanLocationState((current) => ({
      ...current,
      latitudeInput: field === 'latitude' ? value : current.latitudeInput,
      longitudeInput: field === 'longitude' ? value : current.longitudeInput,
      source: 'manual',
      error: null
    }));
  }, []);

  const loadBaseline = useCallback(async (options: LoadBaselineOptions = {}) => {
    setViewState((current) => ({ ...current, loading: true, error: null }));

    if (!window.monitor) {
      setViewState((current) => ({
        ...current,
        loading: false,
        error: 'Electron IPC bridge is not available in this renderer preview.'
      }));
      return;
    }

    try {
      const scanLocationInput = currentScanLocationInput();
      const [status, networks, runs, events, timeline, diagnostics, history, locations] = await Promise.all([
        window.monitor.getBaselineStatus(),
        sourceControls.nearbyAps
          ? window.monitor.getBaselineNetworks({
              refreshScan: options.refreshScan === true,
              persistInventory: options.persistInventory === true,
              location: scanLocationInput
            })
          : Promise.resolve(null),
        window.monitor.getBaselineRuns({ last: 6 }),
        sourceControls.wlanEvents ? window.monitor.getBaselineEvents({ last: 25 }) : Promise.resolve(null),
        sourceControls.wlanEvents
          ? window.monitor.getBaselineTimeline({ last: 60, windowMinutes: 10, minCycles: 2 })
          : Promise.resolve(null),
        window.monitor.getBaselineDiagnosticsBundles({ last: 6 }),
        loadDeviceHistorySafely(deviceHistoryWindowHours),
        loadScanLocationsSafely()
      ]);
      const mergedNetworks = mergeNearbyNetworks(networks);
      if (history) {
        setDeviceHistory(history);
      }
      if (locations) {
        setScanLocations(locations);
        setSelectedScanLocationKey((current) =>
          current && locations.locations.some((location) => location.location_key === current)
            ? current
            : networks?.scan_location?.location_key ?? locations.locations[0]?.location_key ?? null
        );
      }

      setViewState({
        status,
        networks: mergedNetworks,
        runs,
        events,
        timeline,
        diagnostics,
        loading: false,
        error: null,
        lastUpdated: new Date().toISOString()
      });
      setSelectedRunId((currentRunId) => {
        if (currentRunId && runs.runs.some((run) => run.run_id === currentRunId && run.status === 'complete')) {
          return currentRunId;
        }

        return runs.runs.find((run) => run.status === 'complete')?.run_id ?? null;
      });
    } catch (nextError: unknown) {
      setViewState((current) => ({
        ...current,
        loading: false,
        error: nextError instanceof Error ? nextError.message : String(nextError)
      }));
    }
  }, [currentScanLocationInput, deviceHistoryWindowHours, loadDeviceHistorySafely, loadScanLocationsSafely, mergeNearbyNetworks, sourceControls.nearbyAps, sourceControls.wlanEvents]);

  const runConnectivityCheck = useCallback(async () => {
    if (!window.monitor?.runConnectivityCheck) {
      setConnectivityCheckState({
        loading: false,
        result: null,
        error: 'Connectivity check is not available in this renderer bridge. Restart Monitor to load the latest preload.'
      });
      return;
    }

    setConnectivityCheckState((current) => ({ ...current, loading: true, error: null }));

    try {
      const result = await window.monitor.runConnectivityCheck({
        downloadBytes: 750_000,
        timeoutMs: 8_000
      });
      setConnectivityCheckState({
        loading: false,
        result,
        error: result.error
      });
    } catch (nextError: unknown) {
      setConnectivityCheckState({
        loading: false,
        result: null,
        error: formatMonitorBridgeError(nextError, 'connectivity:check')
      });
    }
  }, []);

  const refreshNetworks = useCallback(async (options: LoadBaselineOptions = {}) => {
    if (!sourceControls.nearbyAps || !window.monitor || networkRefreshInFlightRef.current) {
      return;
    }

    networkRefreshInFlightRef.current = true;
    setNetworkRefreshing(true);

    try {
      const networks = await window.monitor.getBaselineNetworks({
        refreshScan: options.refreshScan === true,
        scanSettleMs: NETWORK_SCAN_SETTLE_MS,
        persistInventory: options.persistInventory === true,
        location: currentScanLocationInput()
      });
      const mergedNetworks = mergeNearbyNetworks(networks);
      setViewState((current) => ({
        ...current,
        networks: mergedNetworks,
        lastUpdated: new Date().toISOString()
      }));
      const history = await loadDeviceHistorySafely(deviceHistoryWindowHours);
      if (history) {
        setDeviceHistory(history);
      }
      const locations = await loadScanLocationsSafely();
      if (locations) {
        setScanLocations(locations);
        setSelectedScanLocationKey((current) =>
          current && locations.locations.some((location) => location.location_key === current)
            ? current
            : networks.scan_location?.location_key ?? locations.locations[0]?.location_key ?? null
        );
      }
    } catch (nextError: unknown) {
      const nextFreshness = {
        ...networkFreshnessRef.current,
        checkedAtUtc: new Date().toISOString(),
        retainedLastGood: Boolean(networksRef.current),
        latestError: nextError instanceof Error ? nextError.message : String(nextError)
      };

      networkFreshnessRef.current = nextFreshness;
      setNetworkFreshness(nextFreshness);
    } finally {
      networkRefreshInFlightRef.current = false;
      setNetworkRefreshing(false);
    }
  }, [currentScanLocationInput, deviceHistoryWindowHours, loadDeviceHistorySafely, loadScanLocationsSafely, mergeNearbyNetworks, sourceControls.nearbyAps]);

  const applyDeviceIntelligenceUpdate = useCallback(
    (targetNetwork: WindowsWifiNetwork, override: DeviceIntelligenceOverride) => {
      setViewState((current) => {
        if (!current.networks) {
          return current;
        }

        const nextNetworks = patchNetworkListWithDeviceIntelligence(
          current.networks.networks,
          targetNetwork,
          override
        );
        const nextNetworkResult = {
          ...current.networks,
          networks: nextNetworks,
          mac_summary: summarizeNetworksForIntel(nextNetworks)
        };

        networksRef.current = nextNetworkResult;
        return {
          ...current,
          networks: nextNetworkResult,
          lastUpdated: new Date().toISOString()
        };
      });

      setRememberedNetworks((current) =>
        current.map((item) =>
          sameNetworkIdentity(item.network, targetNetwork)
            ? {
                ...item,
                network: applyDeviceIntelligenceOverrideToNetwork(item.network, override)
              }
            : item
        )
      );
      void loadDeviceHistorySafely(deviceHistoryWindowHours).then((history) => {
        if (history) {
          setDeviceHistory(history);
        }
      });
    },
    [deviceHistoryWindowHours, loadDeviceHistorySafely]
  );

  const recordVulnerabilityLookup = useCallback<LeakLookupRecordAppender>(() => {
    // Device-level lookup results are reflected directly into inventory and reports.
  }, []);

  const applyVulnerabilityLookupUpdate = useCallback(
    (targetNetwork: WindowsWifiNetwork, result: DeviceVulnerabilityLookupResult) => {
      if (!result.vulnerability_intel) {
        return;
      }

      const patchNetwork = (network: WindowsWifiNetwork): WindowsWifiNetwork =>
        sameNetworkIdentity(network, targetNetwork)
          ? {
              ...network,
              vulnerability_intel: result.vulnerability_intel ?? network.vulnerability_intel
            }
          : network;

      setViewState((current) => {
        if (!current.networks) {
          return current;
        }

        const nextNetworks = current.networks.networks.map(patchNetwork);
        const nextNetworkResult = {
          ...current.networks,
          networks: nextNetworks,
          mac_summary: summarizeNetworksForIntel(nextNetworks)
        };

        networksRef.current = nextNetworkResult;
        return {
          ...current,
          networks: nextNetworkResult,
          lastUpdated: new Date().toISOString()
        };
      });

      setRememberedNetworks((current) =>
        current.map((item) =>
          sameNetworkIdentity(item.network, targetNetwork)
            ? {
                ...item,
                network: patchNetwork(item.network)
              }
            : item
        )
      );
    },
    []
  );

  const toggleSourceControl = useCallback((key: SourceControlKey, enabled: boolean) => {
    setSourceControls((current) => ({ ...current, [key]: enabled }));
    if (!enabled) {
      if (key === 'nearbyAps') {
        networksRef.current = null;
        networkFreshnessRef.current = INITIAL_NETWORK_FRESHNESS;
        setNetworkFreshness(INITIAL_NETWORK_FRESHNESS);
        setRememberedNetworks([]);
        setNetworkHistory([]);
        setSelectedHistoryId(null);
        lastHistorySnapshotKeyRef.current = null;
      }

      setViewState((current) => ({
        ...current,
        networks: key === 'nearbyAps' ? null : current.networks,
        events: key === 'wlanEvents' ? null : current.events,
        timeline: key === 'wlanEvents' ? null : current.timeline
      }));
    }
  }, []);

  useEffect(() => {
    loadBaseline();
    const refreshTimer = window.setInterval(loadBaseline, BASELINE_REFRESH_MS);

    return () => {
      window.clearInterval(refreshTimer);
    };
  }, [loadBaseline]);

  useEffect(() => {
    if (!sourceControls.nearbyAps) {
      return;
    }

    const networkRefreshTimer = window.setInterval(() => {
      void refreshNetworks({ refreshScan: true });
    }, NETWORK_REFRESH_MS);

    return () => {
      window.clearInterval(networkRefreshTimer);
    };
  }, [refreshNetworks, sourceControls.nearbyAps]);

  useEffect(() => {
    if (!viewState.networks || networkFreshness.retainedLastGood) {
      return;
    }

    setRememberedNetworks((current) =>
      updateRememberedNetworks(current, viewState.networks?.networks ?? [], viewState.networks?.ts_utc ?? new Date().toISOString(), Date.now())
    );
  }, [viewState.networks, networkFreshness.retainedLastGood]);

  useEffect(() => {
    if (!viewState.networks || networkFreshness.retainedLastGood || rememberedNetworks.length === 0) {
      return;
    }

    const snapshotKey = networkHistorySnapshotKey(viewState.networks.ts_utc, rememberedNetworks);
    if (lastHistorySnapshotKeyRef.current === snapshotKey) {
      return;
    }

    lastHistorySnapshotKeyRef.current = snapshotKey;
    const snapshot = createNetworkHistorySnapshot(
      viewState.networks.ts_utc,
      rememberedNetworks,
      Date.now()
    );
    setNetworkHistory((current) => appendNetworkHistorySnapshot(current, snapshot));
  }, [rememberedNetworks, viewState.networks, networkFreshness.retainedLastGood]);

  useEffect(() => {
    savePersistedNetworkHistory(networkHistory);
  }, [networkHistory]);

  useEffect(() => {
    if (selectedHistoryId && !networkHistory.some((snapshot) => snapshot.id === selectedHistoryId)) {
      setSelectedHistoryId(null);
    }
  }, [networkHistory, selectedHistoryId]);

  useEffect(() => {
    let highlightTimer: number | null = null;

    const highlightTarget = (hash: string) => {
      const targetId = decodeURIComponent(hash.slice(1));
      const target = document.getElementById(targetId);
      if (!target) {
        return;
      }

      if (highlightTimer !== null) {
        window.clearTimeout(highlightTimer);
      }

      document.querySelectorAll('.jump-highlight').forEach((element) => {
        element.classList.remove('jump-highlight');
      });
      target.classList.remove('jump-highlight');
      void target.offsetWidth;
      target.classList.add('jump-highlight');
      highlightTimer = window.setTimeout(() => {
        target.classList.remove('jump-highlight');
        highlightTimer = null;
      }, 2600);
    };

    const onAnchorClick = (event: MouseEvent) => {
      const eventTarget = event.target;
      if (!(eventTarget instanceof Element)) {
        return;
      }

      const anchor = eventTarget.closest('a[href^="#"]');
      if (!(anchor instanceof HTMLAnchorElement) || anchor.hash.length <= 1) {
        return;
      }

      window.setTimeout(() => highlightTarget(anchor.hash), 80);
    };

    const onHashChange = () => {
      if (window.location.hash.length > 1) {
        highlightTarget(window.location.hash);
      }
    };

    document.addEventListener('click', onAnchorClick);
    window.addEventListener('hashchange', onHashChange);

    return () => {
      document.removeEventListener('click', onAnchorClick);
      window.removeEventListener('hashchange', onHashChange);
      if (highlightTimer !== null) {
        window.clearTimeout(highlightTimer);
      }
    };
  }, []);

  const collectSample = useCallback(async () => {
    if (!window.monitor) {
      setSampleState({
        collecting: false,
        result: null,
        error: 'Sample collection is available inside Electron.',
        startedAtMs: null,
        durationSeconds: null,
        presetLabel: null,
        cancelRequested: false
      });
      return;
    }

    setSampleState({
      collecting: true,
      result: null,
      error: null,
      startedAtMs: Date.now(),
      durationSeconds: collectionPreset.durationSeconds,
      presetLabel: collectionPreset.label,
      cancelRequested: false
    });

    try {
      const result = await window.monitor.collectBaselineSample({
        durationSeconds: collectionPreset.durationSeconds,
        intervalSeconds: collectionPreset.intervalSeconds,
        maxEvents: collectionPreset.maxEvents
      });
      await loadBaseline();
      setSelectedRunId(result.run_id);
      setCandidateRunId(result.run_id);
      setSampleState({
        collecting: false,
        result,
        error: null,
        startedAtMs: null,
        durationSeconds: null,
        presetLabel: null,
        cancelRequested: false
      });
    } catch (nextError: unknown) {
      setSampleState({
        collecting: false,
        result: null,
        error: nextError instanceof Error ? nextError.message : String(nextError),
        startedAtMs: null,
        durationSeconds: null,
        presetLabel: null,
        cancelRequested: false
      });
    }
  }, [collectionPreset, loadBaseline]);

  const cancelCollection = useCallback(async () => {
    if (!window.monitor) {
      setSampleState((current) => ({
        ...current,
        error: 'Sample collection cancellation is available inside Electron.'
      }));
      return;
    }

    setSampleState((current) => ({
      ...current,
      cancelRequested: true,
      error: null
    }));

    try {
      const result = await window.monitor.cancelBaselineCollection();
      if (!result.cancelled) {
        setSampleState((current) => ({
          ...current,
          cancelRequested: false,
          error: result.message
        }));
      }
    } catch (nextError: unknown) {
      setSampleState((current) => ({
        ...current,
        cancelRequested: false,
        error: nextError instanceof Error ? nextError.message : String(nextError)
      }));
    }
  }, []);

  const createDiagnosticsBundle = useCallback(async () => {
    if (!window.monitor) {
      setDiagnosticsState({
        creating: false,
        result: null,
        error: 'Diagnostics bundle is available inside Electron.'
      });
      return;
    }

    setDiagnosticsState({
      creating: true,
      result: null,
      error: null
    });

    try {
      const result = await window.monitor.createBaselineDiagnosticsBundle({
        lastRuns: 10,
        lastEvents: 100,
        windowMinutes: 10,
        minCycles: 2
      });
      await loadBaseline();
      setDiagnosticsState({
        creating: false,
        result,
        error: null
      });
    } catch (nextError: unknown) {
      setDiagnosticsState({
        creating: false,
        result: null,
        error: nextError instanceof Error ? nextError.message : String(nextError)
      });
    }
  }, [loadBaseline]);

  useEffect(() => {
    setNowMs(Date.now());
    const clockTimer = window.setInterval(() => setNowMs(Date.now()), 1_000);

    return () => {
      window.clearInterval(clockTimer);
    };
  }, []);

  useEffect(() => {
    if (!sampleState.result) {
      return;
    }

    const resultTimer = window.setTimeout(() => {
      setSampleState((current) => ({ ...current, result: null }));
    }, SAMPLE_RESULT_VISIBLE_MS);

    return () => {
      window.clearTimeout(resultTimer);
    };
  }, [sampleState.result]);

  useEffect(() => {
    let cancelled = false;

    if (!selectedRunId) {
      setAnalysisState(INITIAL_ANALYSIS_STATE);
      return () => {
        cancelled = true;
      };
    }

    if (!window.monitor) {
      setAnalysisState({
        analysis: null,
        loading: false,
        error: 'Saved run analysis is available inside Electron.'
      });
      return () => {
        cancelled = true;
      };
    }

    setAnalysisState((current) => ({ ...current, loading: true, error: null }));
    window.monitor
      .getBaselineRunAnalysis({ runId: selectedRunId, windowMinutes: 10, minCycles: 2 })
      .then((analysis) => {
        if (!cancelled) {
          setAnalysisState({ analysis, loading: false, error: null });
        }
      })
      .catch((nextError: unknown) => {
        if (!cancelled) {
          setAnalysisState({
            analysis: null,
            loading: false,
            error: nextError instanceof Error ? nextError.message : String(nextError)
          });
        }
      });

    return () => {
      cancelled = true;
    };
  }, [selectedRunId]);

  const { status, networks, runs, events, timeline, diagnostics, loading, error, lastUpdated } = viewState;
  const { analysis, loading: analysisLoading, error: analysisError } = analysisState;
  const completedRuns = useMemo(
    () => (runs?.runs ?? []).filter((run) => run.status === 'complete'),
    [runs?.runs]
  );
  const snapshots = status?.snapshots ?? [];
  const firstSnapshot = snapshots[0];
  const alerts = timeline?.alerts ?? [];

  const runLocalNetworkScan = useCallback(async (mode: LocalNetworkScanMode) => {
    if (!window.monitor?.scanLocalNetwork) {
      setLocalNetworkScanState({
        loading: false,
        mode,
        result: null,
        error: 'Local network scan is not available in this renderer bridge. Restart Monitor to load the latest preload.'
      });
      return;
    }

    setLocalNetworkScanState((current) => ({
      ...current,
      loading: true,
      mode,
      error: null
    }));

    try {
      const result = await window.monitor.scanLocalNetwork({
        mode,
        snapshot: firstSnapshot ?? null
      });
      setLocalNetworkScanState({
        loading: false,
        mode,
        result,
        error: result.error
      });
    } catch (nextError: unknown) {
      setLocalNetworkScanState({
        loading: false,
        mode,
        result: null,
        error: formatMonitorBridgeError(nextError, 'local-network:scan')
      });
    }
  }, [firstSnapshot]);

  const loadScanIdentityState = useCallback(async () => {
    if (!window.monitor?.getScanIdentityState) {
      setScanIdentityState((current) => ({
        ...current,
        loading: false,
        error: 'Scan identity controls are not available in this renderer bridge. Restart Monitor to load the latest preload.'
      }));
      return;
    }

    setScanIdentityState((current) => ({
      ...current,
      loading: true,
      error: null
    }));

    try {
      const state = await window.monitor.getScanIdentityState({
        interfaceName: firstSnapshot?.interface_name ?? null,
        adapterName: firstSnapshot?.adapter ?? null
      });
      setScanIdentityState((current) => ({
        ...current,
        loading: false,
        state,
        error: state.error,
        computerNameInput: current.computerNameInput || state.suggested_computer_name,
        macAddressInput: current.macAddressInput || state.suggested_mac_address || ''
      }));
    } catch (nextError: unknown) {
      setScanIdentityState((current) => ({
        ...current,
        loading: false,
        error: formatMonitorBridgeError(nextError, 'scan-identity:state')
      }));
    }
  }, [firstSnapshot?.adapter, firstSnapshot?.interface_name]);

  const applyScanIdentity = useCallback(async () => {
    if (!window.monitor?.applyScanIdentity) {
      setScanIdentityState((current) => ({
        ...current,
        applying: false,
        error: 'Scan identity controls are not available in this renderer bridge. Restart Monitor to load the latest preload.'
      }));
      return;
    }

    const computerName = scanIdentityState.computerNameInput.trim() || scanIdentityState.state?.suggested_computer_name || null;
    const macAddress = scanIdentityState.macAddressInput.trim() || scanIdentityState.state?.suggested_mac_address || null;
    setScanIdentityState((current) => ({
      ...current,
      applying: true,
      result: null,
      error: null
    }));

    try {
      const result = await window.monitor.applyScanIdentity({
        interfaceName: firstSnapshot?.interface_name ?? scanIdentityState.state?.interface_name ?? null,
        adapterName: firstSnapshot?.adapter ?? scanIdentityState.state?.adapter_name ?? null,
        computerName,
        macAddress,
        restartAdapter: scanIdentityState.restartAdapter
      });
      setScanIdentityState((current) => ({
        ...current,
        applying: false,
        state: result,
        result,
        error: result.error,
        computerNameInput: result.suggested_computer_name || current.computerNameInput,
        macAddressInput: result.suggested_mac_address || current.macAddressInput
      }));
    } catch (nextError: unknown) {
      setScanIdentityState((current) => ({
        ...current,
        applying: false,
        error: formatMonitorBridgeError(nextError, 'scan-identity:apply')
      }));
    }
  }, [
    firstSnapshot?.adapter,
    firstSnapshot?.interface_name,
    scanIdentityState.computerNameInput,
    scanIdentityState.macAddressInput,
    scanIdentityState.restartAdapter,
    scanIdentityState.state
  ]);

  const restoreScanIdentity = useCallback(async () => {
    if (!window.monitor?.restoreScanIdentity) {
      setScanIdentityState((current) => ({
        ...current,
        restoring: false,
        error: 'Scan identity controls are not available in this renderer bridge. Restart Monitor to load the latest preload.'
      }));
      return;
    }

    setScanIdentityState((current) => ({
      ...current,
      restoring: true,
      result: null,
      error: null
    }));

    try {
      const result = await window.monitor.restoreScanIdentity({
        interfaceName: firstSnapshot?.interface_name ?? scanIdentityState.state?.interface_name ?? null,
        adapterName: firstSnapshot?.adapter ?? scanIdentityState.state?.adapter_name ?? null,
        restartAdapter: scanIdentityState.restartAdapter
      });
      setScanIdentityState((current) => ({
        ...current,
        restoring: false,
        state: result,
        result,
        error: result.error,
        computerNameInput: result.suggested_computer_name || current.computerNameInput,
        macAddressInput: result.suggested_mac_address || current.macAddressInput
      }));
    } catch (nextError: unknown) {
      setScanIdentityState((current) => ({
        ...current,
        restoring: false,
        error: formatMonitorBridgeError(nextError, 'scan-identity:restore')
      }));
    }
  }, [
    firstSnapshot?.adapter,
    firstSnapshot?.interface_name,
    scanIdentityState.restartAdapter,
    scanIdentityState.state
  ]);

  useEffect(() => {
    void loadScanIdentityState();
  }, [loadScanIdentityState]);
  const recentTimeline = useMemo(
    () => [...(timeline?.timeline ?? [])].reverse().slice(0, 8),
    [timeline?.timeline]
  );
  const recentEvents = useMemo(
    () => [...(events?.events ?? [])].reverse().slice(0, 8),
    [events?.events]
  );
  const currentNetwork = useMemo(() => {
    const currentBssid = normalizeMacForCompare(firstSnapshot?.bssid ?? null);
    if (!currentBssid) {
      return null;
    }

    return (
      networks?.networks.find((network) => normalizeMacForCompare(network.bssid) === currentBssid) ?? null
    );
  }, [firstSnapshot?.bssid, networks?.networks]);
  const activeHistorySnapshot = useMemo(
    () => selectedHistoryId ? networkHistory.find((snapshot) => snapshot.id === selectedHistoryId) ?? null : null,
    [networkHistory, selectedHistoryId]
  );
  const liveRememberedNetworkItems = useMemo(
    () => deriveRememberedNetworkItems(rememberedNetworks, nowMs),
    [nowMs, rememberedNetworks]
  );
  const deviceHistoryByBssid = useMemo(
    () => buildDeviceHistoryByBssid(deviceHistory),
    [deviceHistory]
  );
  const rememberedSourceItems = activeHistorySnapshot?.items ?? rememberedNetworks;
  const rememberedViewNowMs = activeHistorySnapshot ? Date.parse(activeHistorySnapshot.tsUtc) : nowMs;
  const rememberedNetworkItems = useMemo(() => {
    const effectiveNowMs = Number.isFinite(rememberedViewNowMs) ? rememberedViewNowMs : nowMs;
    return annotateRememberedNetworkItemsWithHistory(
      deriveRememberedNetworkItems(rememberedSourceItems, effectiveNowMs),
      deviceHistoryByBssid,
      { nowMs: effectiveNowMs, windowMs: deviceHistoryNewWindowMinutes * 60 * 1000 }
    );
  }, [deviceHistoryByBssid, deviceHistoryNewWindowMinutes, nowMs, rememberedSourceItems, rememberedViewNowMs]);
  const rememberedNetworkIntelSummary = useMemo(
    () => summarizeNetworksForIntel(rememberedNetworkItems.map((item) => item.network)),
    [rememberedNetworkItems]
  );
  const rememberedSsidBuckets = useMemo(
    () => summarizeRememberedSsids(rememberedNetworkItems),
    [rememberedNetworkItems]
  );
  const filteredRememberedNetworkItems = useMemo(
    () =>
      rememberedNetworkItems.filter((item) =>
        rememberedNetworkMatchesIntelFilter(item, networkIntelFilter, firstSnapshot ?? null, rememberedNetworkItems)
      ),
    [firstSnapshot, networkIntelFilter, rememberedNetworkItems]
  );
  const selectedScanLocation = useMemo(
    () =>
      selectedScanLocationKey
        ? scanLocations?.locations.find((location) => location.location_key === selectedScanLocationKey) ?? null
        : scanLocations?.locations[0] ?? networks?.scan_location ?? null,
    [networks?.scan_location, scanLocations?.locations, selectedScanLocationKey]
  );
  const selectedLocationItems = useMemo(
    () =>
      buildRememberedItemsForScanLocation(
        selectedScanLocation,
        scanLocations,
        rememberedNetworkItems,
        Number.isFinite(rememberedViewNowMs) ? rememberedViewNowMs : nowMs
      ),
    [nowMs, rememberedNetworkItems, rememberedViewNowMs, scanLocations, selectedScanLocation]
  );
  const filteredSelectedLocationItems = useMemo(
    () =>
      selectedLocationItems.filter((item) =>
        rememberedNetworkMatchesIntelFilter(item, networkIntelFilter, firstSnapshot ?? null, selectedLocationItems)
      ),
    [firstSnapshot, networkIntelFilter, selectedLocationItems]
  );
  const selectedLocationIntelSummary = useMemo(
    () => summarizeNetworksForIntel(selectedLocationItems.map((item) => item.network)),
    [selectedLocationItems]
  );
  const selectedLocationSsidBuckets = useMemo(
    () => summarizeRememberedSsids(selectedLocationItems),
    [selectedLocationItems]
  );
  const networkListSource = useMemo(
    () =>
      networks?.sources.find((source) => source.name === 'netsh_wlan_networks') ??
      networks?.sources[0] ??
      null,
    [networks?.sources]
  );
  const sourceStatuses = useMemo(
    () => mergeSourceStatuses([...(status?.sources ?? []), ...(networks?.sources ?? [])]),
    [networks?.sources, status?.sources]
  );
  const exposureCounts = useMemo(
    () => summarizeVulnerabilityExposure(networks?.networks ?? []),
    [networks?.networks]
  );
  const liveRememberedCount = liveRememberedNetworkItems.filter((item) => !item.isStale).length;
  const historyViewLabel = activeHistorySnapshot ? `History ${formatDateTime(activeHistorySnapshot.tsUtc)}` : 'Live';
  const availableSourceCount = sourceStatuses.filter((source) => source.available).length;
  const latestRun = completedRuns[0] ?? null;
  const collectionProgress = useMemo(() => {
    if (!sampleState.collecting || sampleState.startedAtMs === null || sampleState.durationSeconds === null) {
      return null;
    }

    const elapsedSeconds = Math.max(0, Math.floor((nowMs - sampleState.startedAtMs) / 1000));
    const remainingSeconds = Math.max(0, sampleState.durationSeconds - elapsedSeconds);

    return {
      elapsedSeconds,
      remainingSeconds,
      percent: Math.min(100, Math.round((elapsedSeconds / sampleState.durationSeconds) * 100))
    };
  }, [nowMs, sampleState.collecting, sampleState.durationSeconds, sampleState.startedAtMs]);
  const connectedRememberedItem = useMemo(() => {
    const currentBssid = normalizeMacForCompare(firstSnapshot?.bssid ?? null);
    if (!currentBssid) {
      return null;
    }

    return rememberedNetworkItems.find((item) => normalizeMacForCompare(item.network.bssid) === currentBssid) ?? null;
  }, [firstSnapshot?.bssid, rememberedNetworkItems]);

  useEffect(() => {
    if (completedRuns.length === 0) {
      setBaselineRunId(null);
      setCandidateRunId(null);
      return;
    }

    setCandidateRunId((currentRunId) => {
      if (currentRunId && completedRuns.some((run) => run.run_id === currentRunId)) {
        return currentRunId;
      }

      return completedRuns[0].run_id;
    });
    setBaselineRunId((currentRunId) => {
      if (currentRunId && completedRuns.some((run) => run.run_id === currentRunId)) {
        return currentRunId;
      }

      return completedRuns[1]?.run_id ?? completedRuns[0].run_id;
    });
  }, [completedRuns]);

  const compareRuns = useCallback(async () => {
    if (!window.monitor) {
      setComparisonState({
        comparison: null,
        loading: false,
        error: 'Run comparison is available inside Electron.'
      });
      return;
    }

    if (!baselineRunId || !candidateRunId) {
      setComparisonState({
        comparison: null,
        loading: false,
        error: 'Select two complete saved runs to compare.'
      });
      return;
    }

    if (baselineRunId === candidateRunId) {
      setComparisonState({
        comparison: null,
        loading: false,
        error: 'Pick two different runs for comparison.'
      });
      return;
    }

    setComparisonState((current) => ({ ...current, loading: true, error: null }));

    try {
      const comparison = await window.monitor.getBaselineRunComparison({
        baselineRunId,
        candidateRunId,
        windowMinutes: 10,
        minCycles: 2
      });
      setComparisonState({ comparison, loading: false, error: null });
    } catch (nextError: unknown) {
      setComparisonState({
        comparison: null,
        loading: false,
        error: nextError instanceof Error ? nextError.message : String(nextError)
      });
    }
  }, [baselineRunId, candidateRunId]);

  return (
    <main className={activeTab === 'map' ? 'app-shell app-shell-fixed' : 'app-shell'}>
      <section className="header-band">
        <div className="header-main">
          <h1>Monitor</h1>
          <nav className="app-tabs" aria-label="Main sections">
            {APP_TABS.map((tab) => (
              <button
                key={tab.key}
                type="button"
                className={activeTab === tab.key ? 'app-tab app-tab-active' : 'app-tab'}
                onClick={() => setActiveTab(tab.key)}
              >
                {tab.label}
              </button>
            ))}
          </nav>
        </div>
        <div className="header-actions">
          <button
            type="button"
            className="primary-button"
            onClick={() => loadBaseline({ refreshScan: true, persistInventory: true })}
            disabled={loading}
          >
            {loading ? 'Refreshing' : 'Refresh'}
          </button>
          <button
            type="button"
            className="secondary-button"
            onClick={createDiagnosticsBundle}
            disabled={diagnosticsState.creating}
          >
            {diagnosticsState.creating ? 'Bundling' : 'Diagnostics'}
          </button>
        </div>
      </section>

      {error ? <p className="error banner">{error}</p> : null}
      {sampleState.error ? <p className="error banner">{sampleState.error}</p> : null}
      {diagnosticsState.error ? <p className="error banner">{diagnosticsState.error}</p> : null}
      {diagnosticsState.result ? (
        <div className="diagnostics-banner">
          <div>
            <strong>Saved diagnostics {diagnosticsState.result.bundle_id}</strong>
            <span>
              {diagnosticsState.result.counts.snapshots} snapshots, {diagnosticsState.result.counts.events} events,{' '}
              {diagnosticsState.result.counts.runs} runs, {diagnosticsState.result.counts.alerts} alerts.
            </span>
          </div>
          <small>{diagnosticsState.result.out_dir}</small>
          <button
            type="button"
            className="banner-close"
            aria-label="Dismiss saved diagnostics notification"
            onClick={() => setDiagnosticsState((current) => ({ ...current, result: null }))}
          >
            x
          </button>
        </div>
      ) : null}
      {sampleState.result ? (
        <div className="sample-banner">
          <span>
            {sampleState.result.cancelled ? 'Stopped' : 'Saved'} baseline {sampleState.result.run_id}:{' '}
            {sampleState.result.event_count} events,{' '}
            {sampleState.result.snapshot_count} snapshots, {sampleState.result.network_bssid_count} AP records.
          </span>
          <button
            type="button"
            className="banner-close"
            aria-label="Dismiss saved baseline notification"
            onClick={() => setSampleState((current) => ({ ...current, result: null }))}
          >
            x
          </button>
        </div>
      ) : null}
      {collectionProgress ? (
        <div className="collect-progress-banner">
          <div className="collect-progress-row">
            <strong>
              {sampleState.cancelRequested ? 'Stopping baseline' : 'Collecting baseline'} {sampleState.presetLabel}
            </strong>
            <span>
              {formatDuration(collectionProgress.elapsedSeconds)} elapsed /{' '}
              {formatDuration(collectionProgress.remainingSeconds)} remaining
            </span>
          </div>
          <div className="collect-progress-meter" aria-label="Collection progress">
            <span style={{ width: `${collectionProgress.percent}%` }} />
          </div>
        </div>
      ) : null}

      {activeTab === 'map' || activeTab === 'network' || activeTab === 'channels' ? (
        <NetworkHistoryScrubber
          history={networkHistory}
          selectedId={selectedHistoryId}
          onSelect={setSelectedHistoryId}
          onLive={() => setSelectedHistoryId(null)}
          liveStatus={
            activeHistorySnapshot ? (
              <HistorySnapshotStatus snapshot={activeHistorySnapshot} onLive={() => setSelectedHistoryId(null)} />
            ) : (
              <NearbyScanStatus
                networks={networks}
                freshness={networkFreshness}
                snapshot={firstSnapshot ?? null}
                connectivity={connectivityCheckState}
                nowMs={nowMs}
                enabled={sourceControls.nearbyAps}
                refreshing={networkRefreshing}
                clientRefreshing={loading}
                onRefresh={() => void refreshNetworks({ refreshScan: true, persistInventory: true })}
                onRefreshClient={() => void loadBaseline()}
                onConnectivityCheck={() => void runConnectivityCheck()}
              />
            )
          }
        />
      ) : null}

      {activeTab === 'overview' ? (
      <>
      <section className="overview-kpi-grid">
        <OverviewKpi
          label="Connection"
          value={valueOrUnknown(firstSnapshot?.ssid ?? null)}
          detail={`${valueOrUnknown(firstSnapshot?.state ?? null)} | ${formatBssidTail(firstSnapshot?.bssid ?? null)}`}
          tone={firstSnapshot?.state === 'connected' ? 'ok' : 'warn'}
          onActivate={() => setActiveTab('map')}
          activateHint="Open the RF map"
        />
        <OverviewKpi
          label="Signal"
          value={formatPercent(firstSnapshot?.signal_percent ?? null)}
          detail={`${formatRssi(firstSnapshot?.rssi_dbm ?? null)} | ch ${valueOrUnknown(firstSnapshot?.channel ?? null)}`}
          tone={(firstSnapshot?.signal_percent ?? 0) >= 60 ? 'ok' : 'warn'}
          onActivate={() => setActiveTab('map')}
          activateHint="Open the RF map"
        />
        <OverviewKpi
          label="Nearby"
          value={`${networks?.network_count ?? 0} SSIDs`}
          detail={`${networks?.bssid_count ?? rememberedNetworkItems.length} BSSIDs | ${liveRememberedCount} live`}
          onActivate={() => setActiveTab('network')}
          activateHint="Open Nearby APs"
        />
        <OverviewKpi
          label="Exposure"
          value={exposureCounts.priority > 0 ? `${exposureCounts.priority} priority` : `${exposureCounts.review} review`}
          detail={`${exposureCounts.watch} watch | ${exposureCounts.none} clean`}
          tone={exposureCounts.priority > 0 ? 'danger' : exposureCounts.review > 0 ? 'warn' : 'ok'}
          onActivate={() => {
            setActiveTab('network');
            setNetworkIntelFilter(REVIEW_NETWORK_INTEL_FILTER);
          }}
          activateHint="Show flagged APs in Nearby APs"
        />
        <OverviewKpi
          label="Sources"
          value={`${availableSourceCount}/${sourceStatuses.length || 3}`}
          detail={networkFreshness.retainedLastGood ? 'using retained scan' : `checked ${formatAge(secondsSince(networkFreshness.checkedAtUtc, nowMs))}`}
          tone={availableSourceCount >= 3 ? 'ok' : 'warn'}
          onActivate={() => setActiveTab('network')}
          activateHint="Open the Network tab"
        />
        <OverviewKpi
          label="Last Run"
          value={latestRun ? formatRunStorage(latestRun) : 'none'}
          detail={latestRun ? `${formatRunLabel(latestRun)} | ${valueOrUnknown(latestRun.network_bssid_count)} APs` : 'no saved baseline yet'}
          onActivate={() => setActiveTab('reports')}
          activateHint="Open Reports"
        />
      </section>

      <section className="overview-grid">
        <article className="panel">
          <h2>Wi-Fi Status</h2>
          {!error && !status ? <p className="muted">Reading Windows telemetry...</p> : null}
          {firstSnapshot ? (
            <>
              <div className="status-row">
                <strong>{valueOrUnknown(firstSnapshot.ssid)}</strong>
                <span className={firstSnapshot.state === 'connected' ? 'state-good' : 'state-warn'}>
                  {valueOrUnknown(firstSnapshot.state)}
                </span>
              </div>
              <SignalMeter signalPercent={firstSnapshot.signal_percent} />
              <ConnectionBadges
                snapshot={firstSnapshot}
                network={currentNetwork}
                onInspect={currentNetwork ? setCurrentConnectionInsight : undefined}
              />
              <dl className="fact-list">
                <dt>Interface</dt>
                <dd>{valueOrUnknown(firstSnapshot.interface_name)}</dd>
                <dt>Adapter</dt>
                <dd>{valueOrUnknown(firstSnapshot.adapter)}</dd>
                <dt>BSSID</dt>
                <dd>{valueOrUnknown(firstSnapshot.bssid)}</dd>
                <dt>Band</dt>
                <dd>{valueOrUnknown(firstSnapshot.band)}</dd>
                <dt>Channel</dt>
                <dd>{valueOrUnknown(firstSnapshot.channel)}</dd>
                <dt>RSSI</dt>
                <dd>{formatRssi(firstSnapshot.rssi_dbm)}</dd>
                <dt>Rates</dt>
                <dd>{formatRates(firstSnapshot.receive_mbps, firstSnapshot.transmit_mbps)}</dd>
                <dt>Security</dt>
                <dd>{formatSecurity(firstSnapshot.authentication, firstSnapshot.cipher)}</dd>
              </dl>
              {currentConnectionInsight && currentNetwork ? (
                <DeviceInsightModal
                  network={currentNetwork}
                  snapshot={firstSnapshot}
                  kind={currentConnectionInsight}
                  onClose={() => setCurrentConnectionInsight(null)}
                />
              ) : null}
            </>
          ) : null}
        </article>

        <article className="panel">
          <div className="panel-heading panel-heading-actions">
            <h2>Detector Signals</h2>
            <button
              type="button"
              className="ai-inline-action"
              onClick={() =>
                setAiThreatReviewRequest({
                  scope: 'detector',
                  networks: rememberedNetworkItems.map((item) => item.network),
                  snapshot: firstSnapshot ?? null,
                  alerts
                })
              }
            >
              AI review
            </button>
          </div>
          <div className="metric-grid">
            <Metric label="Alerts" value={alerts.length} tone={alerts.length > 0 ? 'warn' : 'ok'} href="#detector-alerts" />
            <Metric label="Timeline" value={timeline?.timeline_count ?? 0} href="#client-timeline" />
            <Metric label="Events" value={events?.events.length ?? 0} href="#wlan-events" />
          </div>
          <div id="detector-alerts" className="anchor-target">
            <AlertList alerts={alerts} targetHref="#client-timeline" />
          </div>
        </article>

        <article className="panel">
          <SourcesPanel
            sources={sourceStatuses}
            controls={sourceControls}
            onToggle={toggleSourceControl}
          />
          <p className="timestamp">Updated {formatDateTime(lastUpdated ?? status?.ts_utc ?? null)}</p>
        </article>
      </section>
      </>
      ) : null}

      {activeTab === 'map' ? (
      <section className="map-grid">
        <LocationRfMap
          location={selectedScanLocation}
          locationControl={
            <ScanLocationsMap
              locations={scanLocations?.locations ?? []}
              metrics={scanLocations?.metrics ?? []}
              selectedLocationKey={selectedScanLocation?.location_key ?? null}
              currentLocation={networks?.scan_location ?? null}
              locationState={scanLocationState}
              error={scanLocationsError}
              onSelectLocation={setSelectedScanLocationKey}
              onLocate={locateScanLocation}
              onManualCoordinateChange={setManualScanCoordinates}
              onLabelChange={(label) => setScanLocationState((current) => ({ ...current, labelInput: label }))}
              onRefresh={() => void refreshNetworks({ refreshScan: true, persistInventory: true })}
            />
          }
          items={filteredSelectedLocationItems}
          summaryItems={selectedLocationItems}
          intelSummary={selectedLocationIntelSummary}
          ssidBuckets={selectedLocationSsidBuckets}
          activeFilter={networkIntelFilter}
          currentSnapshot={firstSnapshot ?? null}
          nowMs={Number.isFinite(rememberedViewNowMs) ? rememberedViewNowMs : nowMs}
          source={networkListSource}
          onFilterChange={setNetworkIntelFilter}
          newWindowMinutes={deviceHistoryNewWindowMinutes}
          onNewWindowChange={setDeviceHistoryNewWindowMinutes}
          onThreatReview={() =>
            setAiThreatReviewRequest({
              scope: 'map',
              networks: filteredRememberedNetworkItems.map((item) => item.network),
              snapshot: firstSnapshot ?? null,
              alerts
            })
          }
          onIntelligenceUpdated={applyDeviceIntelligenceUpdate}
          onVulnerabilityLookupUpdated={applyVulnerabilityLookupUpdate}
          onVulnerabilityLookupRecorded={recordVulnerabilityLookup}
        />
      </section>
      ) : null}

      {activeTab === 'network' ? (
      <>
      <LocalNetworkPanel
        snapshot={firstSnapshot ?? null}
        state={localNetworkScanState}
        scanIdentity={scanIdentityState}
        onScan={(mode) => void runLocalNetworkScan(mode)}
        onRefreshScanIdentity={() => void loadScanIdentityState()}
        onApplyScanIdentity={() => void applyScanIdentity()}
        onRestoreScanIdentity={() => void restoreScanIdentity()}
        onScanIdentityComputerNameChange={(computerNameInput) =>
          setScanIdentityState((current) => ({ ...current, computerNameInput }))
        }
        onScanIdentityMacAddressChange={(macAddressInput) =>
          setScanIdentityState((current) => ({ ...current, macAddressInput }))
        }
        onScanIdentityRestartAdapterChange={(restartAdapter) =>
          setScanIdentityState((current) => ({ ...current, restartAdapter }))
        }
      />
      <section className="network-grid">
        <article className="panel">
          <div className="panel-heading">
            <h2>{selectedScanLocation ? `APs at ${formatScanLocationLabel(selectedScanLocation)}` : 'Nearby APs'}</h2>
            <div className="nearby-heading-meta">
              <span>
                {countUniqueNetworkSsids(selectedLocationItems)} SSIDs / {selectedLocationItems.length} BSSIDs
                {` | ${historyViewLabel}`}
              </span>
              <label className="new-window-control">
                <span>New =</span>
                <select
                  value={deviceHistoryNewWindowMinutes}
                  onChange={(event) => setDeviceHistoryNewWindowMinutes(Number(event.target.value))}
                  aria-label="New device window"
                >
                  <option value={15}>15 min</option>
                  <option value={30}>30 min</option>
                  <option value={60}>1 hour</option>
                  <option value={360}>6 hours</option>
                  <option value={1440}>24 hours</option>
                </select>
              </label>
            </div>
          </div>
          <NetworkList
            items={filteredSelectedLocationItems}
            currentSnapshot={firstSnapshot ?? null}
            source={networkListSource}
            onIntelligenceUpdated={applyDeviceIntelligenceUpdate}
            onVulnerabilityLookupUpdated={applyVulnerabilityLookupUpdate}
            onVulnerabilityLookupRecorded={recordVulnerabilityLookup}
          />
        </article>
      </section>
      </>
      ) : null}

      {activeTab === 'reports' ? (
      <section className="reports-grid">
        <LeakReportsPanel
          location={selectedScanLocation}
          locationItems={selectedLocationItems}
          connectedItem={connectedRememberedItem}
          currentSnapshot={firstSnapshot ?? null}
          localNetworkState={localNetworkScanState}
          onScanLocalNetwork={() => void runLocalNetworkScan('passive')}
          onIntelligenceUpdated={applyDeviceIntelligenceUpdate}
          onVulnerabilityLookupUpdated={applyVulnerabilityLookupUpdate}
          onVulnerabilityLookupRecorded={recordVulnerabilityLookup}
        />
      </section>
      ) : null}

      {activeTab === 'channels' ? (
      <section className="channels-grid">
        <ChannelView
          items={rememberedNetworkItems}
          currentSnapshot={firstSnapshot ?? null}
          currentChannel={firstSnapshot?.channel ?? null}
          currentBand={firstSnapshot?.band ?? null}
          nowMs={nowMs}
          refreshing={networkRefreshing}
          source={networkListSource}
          freshness={networkFreshness}
          onRefresh={() => void refreshNetworks({ refreshScan: true, persistInventory: true })}
          onIntelligenceUpdated={applyDeviceIntelligenceUpdate}
          onVulnerabilityLookupUpdated={applyVulnerabilityLookupUpdate}
          onVulnerabilityLookupRecorded={recordVulnerabilityLookup}
        />
      </section>
      ) : null}

      {aiThreatReviewRequest ? (
        <AiThreatReviewModal
          request={aiThreatReviewRequest}
          onClose={() => setAiThreatReviewRequest(null)}
        />
      ) : null}
    </main>
  );
}

interface StarredLocalDevice {
  key: string;
  ip_address: string | null;
  mac_address: string | null;
  hostname: string | null;
  label: string;
  starred_at_utc: string;
}

function localDeviceKey(device: Pick<LocalNetworkDevice, 'mac_address' | 'ip_address'>): string {
  return device.mac_address ? `mac:${device.mac_address}` : `ip:${device.ip_address}`;
}

function macOuiLabel(mac: string | null): string {
  if (!mac) {
    return 'unknown';
  }
  const hex = mac.replace(/[^a-fA-F0-9]/g, '');
  if (hex.length < 6) {
    return 'unknown';
  }
  return (hex.slice(0, 6).match(/.{2}/g)?.join(':') ?? 'unknown').toUpperCase();
}

function starredEntryToDevice(entry: StarredLocalDevice): LocalNetworkDevice {
  return {
    ip_address: entry.ip_address ?? 'unknown',
    mac_address: entry.mac_address,
    hostname: entry.hostname,
    latency_ms: null,
    state: 'unknown',
    interface_alias: null,
    is_gateway: false,
    source: 'net_neighbor',
    notes: ['Not seen in the latest scan. Details shown are from when this device was last starred.']
  };
}

function loadStarredLocalDevices(): StarredLocalDevice[] {
  try {
    const raw = window.localStorage?.getItem(LOCAL_NETWORK_STARRED_STORAGE_KEY);
    if (!raw) {
      return [];
    }
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as StarredLocalDevice[]) : [];
  } catch {
    return [];
  }
}

function saveStarredLocalDevices(items: StarredLocalDevice[]): void {
  try {
    window.localStorage?.setItem(
      LOCAL_NETWORK_STARRED_STORAGE_KEY,
      JSON.stringify(items.slice(0, LOCAL_NETWORK_STARRED_LIMIT))
    );
  } catch {
    // Best-effort: quota or serialization failures should not break the scan view.
  }
}

function useStarredLocalDevices() {
  const [starred, setStarred] = useState<StarredLocalDevice[]>(() => loadStarredLocalDevices());

  const commit = useCallback((updater: (current: StarredLocalDevice[]) => StarredLocalDevice[]) => {
    setStarred((current) => {
      const next = updater(current);
      saveStarredLocalDevices(next);
      return next;
    });
  }, []);

  const toggleStar = useCallback(
    (device: LocalNetworkDevice) => {
      const key = localDeviceKey(device);
      commit((current) =>
        current.some((item) => item.key === key)
          ? current.filter((item) => item.key !== key)
          : [
              ...current,
              {
                key,
                ip_address: device.ip_address,
                mac_address: device.mac_address,
                hostname: device.hostname,
                label: '',
                starred_at_utc: new Date().toISOString()
              }
            ]
      );
    },
    [commit]
  );

  const removeStar = useCallback(
    (key: string) => commit((current) => current.filter((item) => item.key !== key)),
    [commit]
  );

  const updateLabel = useCallback(
    (key: string, label: string) =>
      commit((current) => current.map((item) => (item.key === key ? { ...item, label } : item))),
    [commit]
  );

  return { starred, toggleStar, removeStar, updateLabel };
}

function LocalNetworkPanel({
  snapshot,
  state,
  scanIdentity,
  onScan,
  onRefreshScanIdentity,
  onApplyScanIdentity,
  onRestoreScanIdentity,
  onScanIdentityComputerNameChange,
  onScanIdentityMacAddressChange,
  onScanIdentityRestartAdapterChange
}: {
  snapshot: WindowsWifiSnapshot | null;
  state: LocalNetworkScanState;
  scanIdentity: ScanIdentityViewState;
  onScan: (mode: LocalNetworkScanMode) => void;
  onRefreshScanIdentity: () => void;
  onApplyScanIdentity: () => void;
  onRestoreScanIdentity: () => void;
  onScanIdentityComputerNameChange: (value: string) => void;
  onScanIdentityMacAddressChange: (value: string) => void;
  onScanIdentityRestartAdapterChange: (value: boolean) => void;
}) {
  const result = state.result;
  const runningMode = state.loading ? state.mode : null;
  const selectedProfile = SCAN_VISIBILITY_PROFILES.find((profile) => profile.mode === (runningMode ?? result?.mode));

  const { starred, toggleStar, removeStar, updateLabel } = useStarredLocalDevices();
  const [selectedDevice, setSelectedDevice] = useState<LocalNetworkDevice | null>(null);
  const devices = result?.devices ?? [];
  const deviceByKey = new Map(devices.map((device) => [localDeviceKey(device), device] as const));
  const starredKeys = new Set(starred.map((item) => item.key));
  const selectedKey = selectedDevice ? localDeviceKey(selectedDevice) : null;
  const selectedStarred = selectedKey ? starred.find((item) => item.key === selectedKey) ?? null : null;

  return (
    <section className="panel local-network-panel" aria-label="Local network scan">
      <div className="panel-heading panel-heading-actions">
        <div>
          <h2>Local Network</h2>
          <span>
            {result
              ? `${result.active_count} active / ${result.stale_count} stale / ${result.device_count} seen`
              : `${valueOrUnknown(snapshot?.default_gateway ?? null)} gateway | ${formatList(snapshot?.ipv4_addresses ?? [])}`}
          </span>
        </div>
        {selectedProfile ? (
          <div className={`scan-visibility-current scan-visibility-risk-${selectedProfile.risk}`}>
            <strong>{selectedProfile.label}</strong>
            <span>{selectedProfile.title}</span>
          </div>
        ) : null}
      </div>
      <p className="local-network-note">
        Choose how visible Monitor should be for this scan. No mode guarantees invisibility; the passive profile only means Monitor sends no LAN probe traffic.
      </p>
      <ScanVisibilityProfiles state={state} onScan={onScan} />
      <ScanIdentityPanel
        identity={scanIdentity}
        onRefresh={onRefreshScanIdentity}
        onApply={onApplyScanIdentity}
        onRestore={onRestoreScanIdentity}
        onComputerNameChange={onScanIdentityComputerNameChange}
        onMacAddressChange={onScanIdentityMacAddressChange}
        onRestartAdapterChange={onScanIdentityRestartAdapterChange}
      />
      {state.error ? <p className="device-history-error">{state.error}</p> : null}
      {result ? (
        <div className="local-network-body">
          <dl className="local-network-facts">
            <div>
              <dt>Local IP</dt>
              <dd>{valueOrUnknown(result.local_ip)}</dd>
            </div>
            <div>
              <dt>Local MAC</dt>
              <dd>{valueOrUnknown(result.local_mac)}</dd>
            </div>
            <div>
              <dt>Gateway</dt>
              <dd>{valueOrUnknown(result.gateway)}</dd>
            </div>
            <div>
              <dt>Prefix</dt>
              <dd>{result.prefix ? `${result.prefix}.0/24` : 'unknown'}</dd>
            </div>
          </dl>
          {starred.length > 0 ? (
            <div className="local-network-watchlist">
              <strong>Watchlist ({starred.length})</strong>
              <ol>
                {starred.map((entry) => {
                  const live = deviceByKey.get(entry.key) ?? null;
                  return (
                    <li
                      key={entry.key}
                      className={live ? `local-network-device-row local-network-device-${live.state}` : 'local-network-device-row local-network-device-absent'}
                    >
                      <button
                        type="button"
                        className="local-network-device-open"
                        onClick={() => setSelectedDevice(live ?? starredEntryToDevice(entry))}
                      >
                        <span className="local-network-device-id">
                          <strong>{entry.label || entry.hostname || entry.ip_address || 'unknown device'}</strong>
                          <small>
                            {entry.ip_address ? `${entry.ip_address} | ` : ''}
                            {valueOrUnknown(entry.mac_address)}
                          </small>
                        </span>
                        <span className="local-network-device-badge">{live ? live.state : 'not seen'}</span>
                      </button>
                      <button
                        type="button"
                        className="local-network-star local-network-star-on"
                        onClick={() => removeStar(entry.key)}
                        aria-label="Remove from watchlist"
                      >
                        {'★'}
                      </button>
                    </li>
                  );
                })}
              </ol>
            </div>
          ) : null}
          <div className="local-network-columns">
            <div className="local-network-device-list">
              <strong>Visible devices</strong>
              {devices.length === 0 ? (
                <p className="muted compact">No local devices were visible from this client.</p>
              ) : (
                <ol>
                  {devices.slice(0, 48).map((device) => {
                    const key = localDeviceKey(device);
                    const isStarred = starredKeys.has(key);
                    return (
                      <li key={device.ip_address} className={`local-network-device-row local-network-device-${device.state}`}>
                        <button
                          type="button"
                          className="local-network-device-open"
                          onClick={() => setSelectedDevice(device)}
                          aria-label={`Inspect ${device.ip_address}`}
                        >
                          <span className="local-network-device-id">
                            <strong>{device.ip_address}</strong>
                            <small>
                              {device.hostname ? `${device.hostname} | ` : ''}
                              {device.is_gateway ? 'gateway | ' : ''}
                              {valueOrUnknown(device.mac_address)} | {valueOrUnknown(device.interface_alias)}
                              {device.latency_ms !== null ? ` | ${device.latency_ms} ms` : ''}
                              {` | ${formatLocalDeviceSource(device.source)}`}
                            </small>
                          </span>
                          <span className="local-network-device-badge">{device.state}</span>
                        </button>
                        <button
                          type="button"
                          className={isStarred ? 'local-network-star local-network-star-on' : 'local-network-star'}
                          onClick={() => toggleStar(device)}
                          aria-pressed={isStarred}
                          aria-label={isStarred ? `Unstar ${device.ip_address}` : `Star ${device.ip_address}`}
                        >
                          {isStarred ? '★' : '☆'}
                        </button>
                      </li>
                    );
                  })}
                </ol>
              )}
            </div>
            <div className="local-network-checks">
              <strong>Exposure checks</strong>
              <ol>
                {result.exposure_checks.map((check) => (
                  <li key={check.id} className={`local-network-check-${check.status}`}>
                    <span>
                      <strong>{check.label}</strong>
                      <small>{check.summary}</small>
                    </span>
                    <em>{check.status}</em>
                  </li>
                ))}
              </ol>
            </div>
          </div>
        </div>
      ) : null}
      {selectedDevice ? (
        <LocalNetworkDeviceModal
          device={selectedDevice}
          starredEntry={selectedStarred}
          onClose={() => setSelectedDevice(null)}
          onToggleStar={() => toggleStar(selectedDevice)}
          onLabelChange={(label) => updateLabel(localDeviceKey(selectedDevice), label)}
        />
      ) : null}
    </section>
  );
}

function LocalNetworkDeviceModal({
  device,
  starredEntry,
  onClose,
  onToggleStar,
  onLabelChange
}: {
  device: LocalNetworkDevice;
  starredEntry: StarredLocalDevice | null;
  onClose: () => void;
  onToggleStar: () => void;
  onLabelChange: (label: string) => void;
}) {
  useBodyScrollLock(true);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        onClose();
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [onClose]);

  const starred = starredEntry !== null;

  return (
    <ModalPortal>
      <div className="device-modal-backdrop insight-modal-backdrop" role="presentation" onMouseDown={onClose}>
        <section
          className="device-modal insight-modal local-device-modal"
          role="dialog"
          aria-modal="true"
          aria-labelledby="local-device-modal-title"
          onMouseDown={(event) => event.stopPropagation()}
        >
          <div className="insight-modal-heading">
            <div>
              <h2 id="local-device-modal-title">{device.hostname ?? device.ip_address}</h2>
              <p>
                {device.is_gateway ? 'gateway | ' : ''}
                {valueOrUnknown(device.mac_address)} | {device.state}
              </p>
            </div>
            <button type="button" className="device-modal-close" onClick={onClose} aria-label="Close device details">
              x
            </button>
          </div>
          <dl className="local-device-facts">
            <div>
              <dt>IP address</dt>
              <dd>{valueOrUnknown(device.ip_address)}</dd>
            </div>
            <div>
              <dt>MAC address</dt>
              <dd>{valueOrUnknown(device.mac_address)}</dd>
            </div>
            <div>
              <dt>OUI (vendor prefix)</dt>
              <dd>{macOuiLabel(device.mac_address)}</dd>
            </div>
            <div>
              <dt>Hostname</dt>
              <dd>{valueOrUnknown(device.hostname)}</dd>
            </div>
            <div>
              <dt>State</dt>
              <dd>{device.state}</dd>
            </div>
            <div>
              <dt>Role</dt>
              <dd>{device.is_gateway ? 'gateway' : 'host'}</dd>
            </div>
            <div>
              <dt>Interface</dt>
              <dd>{valueOrUnknown(device.interface_alias)}</dd>
            </div>
            <div>
              <dt>Latency</dt>
              <dd>{device.latency_ms !== null ? `${device.latency_ms} ms` : 'not measured'}</dd>
            </div>
            <div>
              <dt>Evidence</dt>
              <dd>{formatLocalDeviceSource(device.source)}</dd>
            </div>
          </dl>
          {device.notes.length > 0 ? (
            <div className="local-device-notes">
              <strong>Notes</strong>
              <ul>
                {device.notes.map((note, index) => (
                  <li key={index}>{note}</li>
                ))}
              </ul>
            </div>
          ) : null}
          <div className="local-device-watch">
            <button
              type="button"
              className={starred ? 'local-device-watch-toggle local-device-watch-toggle-on' : 'local-device-watch-toggle'}
              onClick={onToggleStar}
            >
              {starred ? '★ On watchlist — remove' : '☆ Add to watchlist'}
            </button>
            {starred ? (
              <label className="local-device-watch-label">
                <span>Watchlist note</span>
                <input
                  type="text"
                  value={starredEntry.label}
                  placeholder="e.g. office printer, or: unknown — investigate"
                  onChange={(event) => onLabelChange(event.target.value)}
                  maxLength={120}
                />
              </label>
            ) : null}
          </div>
        </section>
      </div>
    </ModalPortal>
  );
}

function ScanVisibilityProfiles({
  state,
  onScan
}: {
  state: LocalNetworkScanState;
  onScan: (mode: LocalNetworkScanMode) => void;
}) {
  const currentMode = state.loading ? state.mode : state.result?.mode ?? null;

  return (
    <div className="scan-visibility-grid" aria-label="Scan visibility profiles">
      {SCAN_VISIBILITY_PROFILES.map((profile) => {
        const isCurrent = currentMode === profile.mode;
        const isRunning = state.loading && state.mode === profile.mode;
        return (
          <article
            key={profile.mode}
            className={`scan-visibility-card scan-visibility-risk-${profile.risk}${isCurrent ? ' active' : ''}`}
          >
            <div className="scan-visibility-card-heading">
              <div>
                <strong>{profile.label}</strong>
                <span>{profile.title}</span>
              </div>
              <em>{profile.risk}</em>
            </div>
            <dl>
              <div>
                <dt>Traffic</dt>
                <dd>{profile.traffic}</dd>
              </div>
              <div>
                <dt>Trace</dt>
                <dd>{profile.traces}</dd>
              </div>
            </dl>
            <p>{profile.operatorNote}</p>
            <button
              type="button"
              className={profile.risk === 'high' ? 'secondary-button' : 'primary-button'}
              onClick={() => onScan(profile.mode)}
              disabled={state.loading}
            >
              {isRunning ? profile.runningLabel : profile.buttonLabel}
            </button>
          </article>
        );
      })}
    </div>
  );
}

function ScanIdentityPanel({
  identity,
  onRefresh,
  onApply,
  onRestore,
  onComputerNameChange,
  onMacAddressChange,
  onRestartAdapterChange
}: {
  identity: ScanIdentityViewState;
  onRefresh: () => void;
  onApply: () => void;
  onRestore: () => void;
  onComputerNameChange: (value: string) => void;
  onMacAddressChange: (value: string) => void;
  onRestartAdapterChange: (value: boolean) => void;
}) {
  const state = identity.state;
  const busy = identity.loading || identity.applying || identity.restoring;
  const resultMessage = identity.result
    ? identity.result.error
      ? identity.result.error
      : identity.result.action === 'restore'
        ? 'Original scan identity restored.'
        : 'Scan identity applied.'
    : null;

  return (
    <div className="scan-identity-panel">
      <div className="scan-identity-heading">
        <div>
          <strong>Scan identity</strong>
          <span>{valueOrUnknown(state?.interface_name ?? null)} | default {state?.suggested_computer_name ?? 'MONITOR-SCOUT'}</span>
        </div>
        <button type="button" className="secondary-button" onClick={onRefresh} disabled={busy}>
          {identity.loading ? 'Refreshing' : 'Refresh'}
        </button>
      </div>
      <dl className="scan-identity-facts">
        <div>
          <dt>Current PC</dt>
          <dd>{valueOrUnknown(state?.current_computer_name ?? null)}</dd>
        </div>
        <div>
          <dt>Current MAC</dt>
          <dd>{valueOrUnknown(state?.current_mac_address ?? null)}</dd>
        </div>
        <div>
          <dt>Stored PC</dt>
          <dd>{valueOrUnknown(state?.stored_original_computer_name ?? null)}</dd>
        </div>
        <div>
          <dt>Stored MAC</dt>
          <dd>{valueOrUnknown(state?.stored_original_mac_address ?? null)}</dd>
        </div>
      </dl>
      <div className="scan-identity-controls">
        <label>
          <span>Scan PC name</span>
          <input
            type="text"
            value={identity.computerNameInput}
            placeholder={state?.suggested_computer_name ?? 'MONITOR-SCOUT'}
            maxLength={15}
            spellCheck={false}
            onChange={(event) => onComputerNameChange(event.target.value.toUpperCase())}
          />
        </label>
        <label>
          <span>Scan MAC</span>
          <input
            type="text"
            value={identity.macAddressInput}
            placeholder={state?.suggested_mac_address ?? '02:00:00:00:00:00'}
            spellCheck={false}
            onChange={(event) => onMacAddressChange(event.target.value)}
          />
        </label>
        <label className="scan-identity-toggle">
          <input
            type="checkbox"
            checked={identity.restartAdapter}
            onChange={(event) => onRestartAdapterChange(event.target.checked)}
          />
          <span>Restart adapter</span>
        </label>
      </div>
      <div className="scan-identity-actions">
        <button type="button" className="primary-button" onClick={onApply} disabled={busy || state?.requires_admin === true}>
          {identity.applying ? 'Applying' : 'Apply for scans'}
        </button>
        <button type="button" className="secondary-button" onClick={onRestore} disabled={busy || state?.requires_admin === true}>
          {identity.restoring ? 'Restoring' : 'Restore original'}
        </button>
        {state?.requires_admin ? <span className="scan-identity-warning">Administrator rights required</span> : null}
        {state?.pending_reboot ? <span className="scan-identity-warning">PC name pending reboot</span> : null}
      </div>
      {identity.error ? <p className="error compact">{identity.error}</p> : null}
      {resultMessage ? (
        <p className={identity.result?.error ? 'error compact' : 'success compact'}>
          {resultMessage}
        </p>
      ) : null}
    </div>
  );
}

function LeakReportsPanel({
  location,
  locationItems,
  connectedItem,
  currentSnapshot,
  localNetworkState,
  onScanLocalNetwork,
  onIntelligenceUpdated,
  onVulnerabilityLookupUpdated,
  onVulnerabilityLookupRecorded
}: {
  location: ScanLocationRecord | null;
  locationItems: Array<RememberedNetwork & { ageSeconds: number | null; isStale: boolean }>;
  connectedItem: (RememberedNetwork & { ageSeconds: number | null; isStale: boolean }) | null;
  currentSnapshot: WindowsWifiSnapshot | null;
  localNetworkState: LocalNetworkScanState;
  onScanLocalNetwork: () => void;
  onIntelligenceUpdated: (network: WindowsWifiNetwork, override: DeviceIntelligenceOverride) => void;
  onVulnerabilityLookupUpdated: (network: WindowsWifiNetwork, result: DeviceVulnerabilityLookupResult) => void;
  onVulnerabilityLookupRecorded: LeakLookupRecordAppender;
}) {
  const [scope, setScope] = useState<'location' | 'connected'>('location');
  const [pdfState, setPdfState] = useState<PdfExportState>({ exporting: false, result: null, error: null });
  const [selectedItemKey, setSelectedItemKey] = useState<string | null>(null);
  const scopedItems = scope === 'connected' ? (connectedItem ? [connectedItem] : []) : locationItems;
  const vulnerableItems = scopedItems.filter(isLeakRelevantNetworkItem);
  const selectedItem = scopedItems.find((item) => item.key === selectedItemKey) ?? null;
  const connectedDevices = localNetworkState.result?.devices ?? [];
  const localChecks = localNetworkState.result?.exposure_checks ?? [];
  const scopeTitle = scope === 'connected'
    ? `Connected AP: ${valueOrUnknown(connectedItem?.network.ssid ?? currentSnapshot?.ssid ?? null)}`
    : `Scan location: ${location ? formatScanLocationLabel(location) : 'not selected'}`;

  const exportPdf = useCallback(async () => {
    if (!window.monitor?.exportReportPdf) {
      setPdfState({
        exporting: false,
        result: null,
        error: 'PDF export is available inside Electron after the latest preload is loaded.'
      });
      return;
    }

    setPdfState({ exporting: true, result: null, error: null });
    try {
      const result = await window.monitor.exportReportPdf({
        filename: leakReportFilename(scope, location, connectedItem),
        html: buildLeakReportHtml({
          scopeTitle,
          location,
          items: scopedItems,
          vulnerableItems,
          currentSnapshot,
          connectedDevices,
          localChecks
        })
      });
      setPdfState({
        exporting: false,
        result: result.saved ? result.path : null,
        error: result.error
      });
    } catch (error) {
      setPdfState({
        exporting: false,
        result: null,
        error: formatMonitorBridgeError(error, 'report:export-pdf')
      });
    }
  }, [connectedDevices, connectedItem, currentSnapshot, localChecks, location, scope, scopeTitle, scopedItems, vulnerableItems]);

  return (
    <article className="panel leak-report-panel">
      <div className="panel-heading panel-heading-actions">
        <div>
          <h2>Leak Reports</h2>
          <span>{scopeTitle}</span>
        </div>
        <div className="leak-report-actions">
          <button
            type="button"
            className={scope === 'location' ? 'secondary-button active' : 'secondary-button'}
            onClick={() => setScope('location')}
          >
            Location
          </button>
          <button
            type="button"
            className={scope === 'connected' ? 'secondary-button active' : 'secondary-button'}
            onClick={() => setScope('connected')}
            disabled={!connectedItem}
          >
            Connected AP
          </button>
          <button type="button" className="secondary-button" onClick={onScanLocalNetwork} disabled={localNetworkState.loading}>
            {localNetworkState.loading ? 'Scanning LAN' : 'Scan LAN'}
          </button>
          <button type="button" className="primary-button" onClick={() => void exportPdf()} disabled={pdfState.exporting || scopedItems.length === 0}>
            {pdfState.exporting ? 'Exporting' : 'Export PDF'}
          </button>
        </div>
      </div>
      {pdfState.error ? <p className="error compact">{pdfState.error}</p> : null}
      {pdfState.result ? <p className="success compact">Saved report: {pdfState.result}</p> : null}
      <div className="leak-report-summary-grid">
        <Metric label="APs" value={scopedItems.length} />
        <Metric label="Needs review" value={vulnerableItems.length} tone={vulnerableItems.length > 0 ? 'warn' : 'ok'} />
        <Metric label="LAN devices" value={connectedDevices.length} />
        <Metric label="LAN checks" value={localChecks.length} tone={localChecks.some((check) => check.status === 'review') ? 'warn' : 'ok'} />
      </div>
      <div className="leak-report-columns">
        <section className="leak-report-list">
          <strong>APs needing review</strong>
          {vulnerableItems.length === 0 ? (
            <p className="muted compact">No review or priority APs in this scope.</p>
          ) : (
            <ol>
              {vulnerableItems.map((item) => (
                <li key={item.key} className={`leak-report-item vulnerability-${item.network.vulnerability_intel?.exposure_level ?? 'none'}`}>
                  <button
                    type="button"
                    className="leak-report-open"
                    onClick={() => setSelectedItemKey(item.key)}
                    aria-label={`Inspect ${formatNetworkSsidLabel(item.network)}`}
                  >
                    <span>
                      <strong>{formatNetworkSsidLabel(item.network)}</strong>
                      <small>{valueOrUnknown(item.network.bssid)} | {formatVulnerabilityBadge(item.network.vulnerability_intel)} | {formatNetworkSecurityBadge(item.network)}</small>
                    </span>
                    <em>{item.isStale ? 'stale' : 'live'}</em>
                  </button>
                </li>
              ))}
            </ol>
          )}
        </section>
        <section className="leak-report-list">
          <strong>Connected LAN Devices</strong>
          {!localNetworkState.result ? (
            <p className="muted compact">Run LAN scan to include devices visible from the current Wi-Fi client.</p>
          ) : connectedDevices.length === 0 ? (
            <p className="muted compact">No local devices are visible from this client.</p>
          ) : (
            <ol>
              {connectedDevices.slice(0, 48).map((device) => (
                <li key={device.ip_address} className={`leak-report-item local-network-device-${device.state}`}>
                  <span>
                    <strong>{device.ip_address}</strong>
                    <small>
                      {device.hostname ? `${device.hostname} | ` : ''}
                      {device.is_gateway ? 'gateway | ' : ''}
                      {valueOrUnknown(device.mac_address)} | {valueOrUnknown(device.interface_alias)}
                      {device.latency_ms !== null ? ` | ${device.latency_ms} ms` : ''}
                    </small>
                  </span>
                  <em>{device.state}</em>
                </li>
              ))}
            </ol>
          )}
        </section>
      </div>
      {localChecks.length ? (
        <section className="leak-report-checks">
          <strong>Local Exposure Checks</strong>
          <ol>
            {localChecks.map((check) => (
              <li key={check.id} className={`local-network-check-${check.status}`}>
                <span>{check.label}</span>
                <small>{check.summary}</small>
              </li>
            ))}
          </ol>
        </section>
      ) : null}
      {selectedItem ? (
        <DeviceModal
          item={selectedItem}
          currentSnapshot={currentSnapshot}
          onClose={() => setSelectedItemKey(null)}
          onIntelligenceUpdated={onIntelligenceUpdated}
          onVulnerabilityLookupUpdated={onVulnerabilityLookupUpdated}
          onVulnerabilityLookupRecorded={onVulnerabilityLookupRecorded}
        />
      ) : null}
    </article>
  );
}

function VulnerabilityScanPlanMini({ plan, title }: { plan: VulnerabilityScanPlan | null; title: string }) {
  if (!plan) {
    return null;
  }

  const selectedChecks = plan.checks.filter((check) => check.selected);
  return (
    <div className="vulnerability-plan-mini">
      <div>
        <strong>{title}</strong>
        <span>{selectedChecks.length} selected</span>
      </div>
      <ul>
        {selectedChecks.map((check) => (
          <li key={check.id}>
            <span>{check.label}</span>
            <small>{formatScanImpact(check.impact)} | {check.network_effect}</small>
          </li>
        ))}
      </ul>
      {plan.operator_note ? <p>{plan.operator_note}</p> : null}
    </div>
  );
}

function buildLeakReportHtml(input: {
  scopeTitle: string;
  location: ScanLocationRecord | null;
  items: Array<RememberedNetwork & { ageSeconds: number | null; isStale: boolean }>;
  vulnerableItems: Array<RememberedNetwork & { ageSeconds: number | null; isStale: boolean }>;
  currentSnapshot: WindowsWifiSnapshot | null;
  connectedDevices: NonNullable<LocalNetworkScanResult['devices']>;
  localChecks: NonNullable<LocalNetworkScanResult['exposure_checks']>;
}): string {
  const apRows = input.items.map((item) => `
    <tr>
      <td>${escapeHtml(formatNetworkSsidLabel(item.network))}</td>
      <td>${escapeHtml(valueOrUnknown(item.network.bssid))}</td>
      <td>${escapeHtml(formatVulnerabilityBadge(item.network.vulnerability_intel))}</td>
      <td>${escapeHtml(formatNetworkSecurityBadge(item.network))}</td>
      <td>${escapeHtml(item.isStale ? 'stale' : 'live')}</td>
    </tr>
  `).join('');
  const lanRows = input.connectedDevices.map((device) => `
    <tr>
      <td>${escapeHtml(device.ip_address)}</td>
      <td>${escapeHtml(valueOrUnknown(device.hostname))}</td>
      <td>${escapeHtml(valueOrUnknown(device.mac_address))}</td>
      <td>${escapeHtml(device.is_gateway ? 'gateway' : device.state)}</td>
      <td>${escapeHtml(valueOrUnknown(device.interface_alias))}</td>
      <td>${escapeHtml(device.latency_ms === null ? 'unknown' : `${device.latency_ms} ms`)}</td>
    </tr>
  `).join('');
  const checkList = input.localChecks.length
    ? `<ul>${input.localChecks.map((check) => `<li><strong>${escapeHtml(check.label)}</strong>: ${escapeHtml(check.summary)}</li>`).join('')}</ul>`
    : '<p>No local exposure checks saved.</p>';

  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>${escapeHtml(input.scopeTitle)} leak report</title>
  <style>
    body { margin: 0; padding: 28px; color: #17232b; font: 12px/1.45 Arial, sans-serif; }
    h1, h2 { margin: 0 0 10px; }
    h1 { font-size: 22px; }
    h2 { margin-top: 20px; padding-top: 12px; border-top: 1px solid #d9e3e8; font-size: 16px; }
    .meta { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; margin: 14px 0; }
    .box { border: 1px solid #d5dee4; border-radius: 8px; padding: 10px; background: #fbfdfe; }
    .muted { color: #60717a; }
    table { width: 100%; border-collapse: collapse; margin-top: 8px; }
    th, td { padding: 6px; border-bottom: 1px solid #e5edf1; text-align: left; vertical-align: top; }
    th { color: #536872; font-size: 10px; text-transform: uppercase; }
    ul { margin: 6px 0 0 18px; padding: 0; }
  </style>
</head>
<body>
  <h1>Monitor Leak Report</h1>
  <p class="muted">Generated ${escapeHtml(formatDateTime(new Date().toISOString()))}. Defensive report only; Monitor did not change adapters, disconnect clients, or send exploitation traffic.</p>
  <div class="meta">
    <div class="box"><span class="muted">Scope</span><strong>${escapeHtml(input.scopeTitle)}</strong></div>
    <div class="box"><span class="muted">APs</span><strong>${input.items.length}</strong></div>
    <div class="box"><span class="muted">APs needing review</span><strong>${input.vulnerableItems.length}</strong></div>
    <div class="box"><span class="muted">LAN devices</span><strong>${input.connectedDevices.length}</strong></div>
  </div>
  <p>Connected SSID: ${escapeHtml(valueOrUnknown(input.currentSnapshot?.ssid ?? null))}. Current BSSID: ${escapeHtml(valueOrUnknown(input.currentSnapshot?.bssid ?? null))}.</p>
  ${input.location ? `<p>Location: ${escapeHtml(formatScanLocationLabel(input.location))} (${input.location.latitude.toFixed(5)}, ${input.location.longitude.toFixed(5)}).</p>` : ''}
  <h2>Access Points</h2>
  <table><thead><tr><th>SSID</th><th>BSSID</th><th>Exposure</th><th>Security</th><th>State</th></tr></thead><tbody>${apRows || '<tr><td colspan="5">No APs in scope.</td></tr>'}</tbody></table>
  <h2>Connected LAN Devices</h2>
  <table><thead><tr><th>IP</th><th>Host</th><th>MAC</th><th>Role/state</th><th>Interface</th><th>Latency</th></tr></thead><tbody>${lanRows || '<tr><td colspan="6">No LAN scan result.</td></tr>'}</tbody></table>
  <h2>Local Exposure Checks</h2>
  ${checkList}
</body>
</html>`;
}

function isLeakRelevantNetworkItem(item: RememberedNetwork & { ageSeconds: number | null; isStale: boolean }): boolean {
  const exposure = item.network.vulnerability_intel?.exposure_level;
  const danger = item.network.security_assessment?.danger_level;
  return exposure === 'review' || exposure === 'priority' || danger === 'high';
}

function leakReportFilename(
  scope: 'location' | 'connected',
  location: ScanLocationRecord | null,
  connectedItem: (RememberedNetwork & { ageSeconds: number | null; isStale: boolean }) | null
): string {
  const label = scope === 'connected'
    ? connectedItem?.network.ssid ?? connectedItem?.network.bssid ?? 'connected-ap'
    : location?.label ?? location?.location_key ?? 'scan-location';
  const safeLabel = label.replace(/[^a-z0-9_.-]+/gi, '-').replace(/^-+|-+$/g, '') || scope;
  const stamp = new Date().toISOString().replace(/[:.]/g, '').slice(0, 15);
  return `monitor-leak-${scope}-${safeLabel}-${stamp}.pdf`;
}

function escapeHtml(value: string | number | null | undefined): string {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function formatLocalDeviceSource(source: LocalNetworkScanResult['devices'][number]['source']): string {
  if (source === 'direct_probe') {
    return 'direct';
  }
  if (source === 'reachability_probe') {
    return 'poll';
  }
  return 'cache';
}

function RunComparisonPanel({
  runs,
  baselineRunId,
  candidateRunId,
  onBaselineChange,
  onCandidateChange,
  onCompare,
  comparisonState
}: {
  runs: BaselineRunRecord[];
  baselineRunId: string | null;
  candidateRunId: string | null;
  onBaselineChange: (runId: string) => void;
  onCandidateChange: (runId: string) => void;
  onCompare: () => void;
  comparisonState: RunComparisonViewState;
}) {
  if (runs.length < 2) {
    return <p className="muted compact">Create at least two complete saved runs to compare baseline windows.</p>;
  }

  return (
    <>
      <div className="compare-controls">
        <label>
          <span>Baseline</span>
          <select value={baselineRunId ?? ''} onChange={(event) => onBaselineChange(event.target.value)}>
            {runs.map((run) => (
              <option key={run.run_id} value={run.run_id}>
                {formatRunOption(run)}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span>Candidate</span>
          <select value={candidateRunId ?? ''} onChange={(event) => onCandidateChange(event.target.value)}>
            {runs.map((run) => (
              <option key={run.run_id} value={run.run_id}>
                {formatRunOption(run)}
              </option>
            ))}
          </select>
        </label>
        <button type="button" className="primary-button" onClick={onCompare} disabled={comparisonState.loading}>
          {comparisonState.loading ? 'Comparing' : 'Compare'}
        </button>
      </div>
      {comparisonState.error ? <p className="error compact">{comparisonState.error}</p> : null}
      {comparisonState.comparison ? <ComparisonResult comparison={comparisonState.comparison} /> : null}
    </>
  );
}

function ComparisonResult({ comparison }: { comparison: BaselineRunComparisonResult }) {
  const observationDeltas = Object.entries(comparison.observation_types).filter(
    ([_name, value]) => value.delta !== 0
  );

  return (
    <div className="comparison-result">
      <div className="comparison-summary">
        <div className="comparison-verdicts">
          <div className={`report-verdict report-verdict-${comparison.baseline_report.verdict}`}>
            <strong>{comparison.baseline_report.verdict}</strong>
            <span>baseline | score {comparison.baseline_report.score}</span>
          </div>
          <div className={`report-verdict report-verdict-${comparison.candidate_report.verdict}`}>
            <strong>{comparison.candidate_report.verdict}</strong>
            <span>candidate | score {comparison.candidate_report.score}</span>
          </div>
        </div>
        <p>{comparison.summary}</p>
      </div>
      <div className="comparison-metrics">
        <Metric label="Score" value={comparison.score_delta} tone={comparison.score_delta > 0 ? 'warn' : 'ok'} />
        <Metric label="Alerts" value={comparison.metrics.alerts.delta} tone={comparison.metrics.alerts.delta > 0 ? 'warn' : 'ok'} />
        <Metric
          label="Observ."
          value={comparison.metrics.observations.delta}
          tone={comparison.metrics.observations.delta > 0 ? 'warn' : 'ok'}
        />
        <Metric label="APs" value={comparison.metrics.nearby_bssids.delta} />
        <Metric label="Vendors" value={comparison.metrics.nearby_vendors.delta} />
      </div>
      <div className="comparison-details">
        <section>
          <h3>Evidence</h3>
          <ul className="report-list">
            {comparison.evidence.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </section>
        <section>
          <h3>Nearby Delta</h3>
          <dl className="analysis-facts delta-facts">
            <div>
              <dt>SSID</dt>
              <dd>
                <DeltaParts
                  added={comparison.nearby.ssids.added}
                  removed={comparison.nearby.ssids.removed}
                  shared={comparison.nearby.ssids.shared}
                />
              </dd>
            </div>
            <div>
              <dt>BSSID</dt>
              <dd>
                <DeltaParts
                  added={comparison.nearby.bssids.added}
                  removed={comparison.nearby.bssids.removed}
                  shared={comparison.nearby.bssids.shared}
                />
              </dd>
            </div>
            <div>
              <dt>Channel</dt>
              <dd>
                <DeltaParts
                  added={comparison.nearby.channels.added.map(String)}
                  removed={comparison.nearby.channels.removed.map(String)}
                  shared={comparison.nearby.channels.shared.map(String)}
                />
              </dd>
            </div>
            <div>
              <dt>Vendor</dt>
              <dd>
                <DeltaParts
                  added={comparison.nearby.vendors.added}
                  removed={comparison.nearby.vendors.removed}
                  shared={comparison.nearby.vendors.shared}
                />
              </dd>
            </div>
            <div>
              <dt>Device hint</dt>
              <dd>
                <DeltaParts
                  added={comparison.nearby.device_hints.added}
                  removed={comparison.nearby.device_hints.removed}
                  shared={comparison.nearby.device_hints.shared}
                />
              </dd>
            </div>
            <div>
              <dt>Unknown OUI</dt>
              <dd>
                <DeltaParts
                  added={comparison.nearby.unknown_ouis.added}
                  removed={comparison.nearby.unknown_ouis.removed}
                  shared={comparison.nearby.unknown_ouis.shared}
                />
              </dd>
            </div>
          </dl>
        </section>
        <section>
          <h3>Observation Delta</h3>
          {observationDeltas.length === 0 ? (
            <p className="muted compact">No observation-type deltas.</p>
          ) : (
            <dl className="analysis-facts compact-facts">
              {observationDeltas.map(([name, delta]) => (
                <div key={name}>
                  <dt>{name}</dt>
                  <dd>{formatSigned(delta.delta)}</dd>
                </div>
              ))}
            </dl>
          )}
        </section>
      </div>
    </div>
  );
}

function ScanLocationsMap({
  locations,
  metrics,
  selectedLocationKey,
  currentLocation,
  locationState,
  error,
  onSelectLocation,
  onLocate,
  onManualCoordinateChange,
  onLabelChange,
  onRefresh
}: {
  locations: ScanLocationRecord[];
  metrics: ScanLocationsResult['metrics'];
  selectedLocationKey: string | null;
  currentLocation: ScanLocationRecord | null;
  locationState: ScanLocationState;
  error: string | null;
  onSelectLocation: (locationKey: string | null) => void;
  onLocate: () => void;
  onManualCoordinateChange: (value: string, field: 'latitude' | 'longitude') => void;
  onLabelChange: (label: string) => void;
  onRefresh: () => void;
}) {
  const locationSummaries = useMemo(
    () => locations.map((location) => scanLocationSummary(location, metrics)),
    [locations, metrics]
  );
  const [modalOpen, setModalOpen] = useState(false);
  const latitude = parseCoordinate(locationState.latitudeInput, -90, 90);
  const longitude = parseCoordinate(locationState.longitudeInput, -180, 180);
  const canScanHere = latitude !== null && longitude !== null && !locationState.locating;
  const selectedSummary = locationSummaries.find((summary) => summary.location.location_key === selectedLocationKey) ?? null;
  const currentSummary = currentLocation
    ? locationSummaries.find((summary) => summary.location.location_key === currentLocation.location_key) ?? null
    : null;
  const activeSummary = selectedSummary ?? currentSummary ?? locationSummaries[0] ?? null;

  return (
    <div className="scan-locations-panel">
      <div className="scan-location-compact">
        <div className="scan-location-compact-main">
          <strong>Location</strong>
          <span>
            {activeSummary
              ? `${formatScanLocationLabel(activeSummary.location)} | ${activeSummary.apCount} APs | ${activeSummary.reviewCount} review`
              : `${locations.length} saved | radius 50 m`}
          </span>
        </div>
        <div className="scan-location-compact-actions">
          {locationSummaries.length > 0 ? (
            <select
              value={selectedLocationKey ?? currentLocation?.location_key ?? ''}
              onChange={(event) => onSelectLocation(event.target.value || null)}
              aria-label="Select scan location"
            >
              {locationSummaries.map((summary) => (
                <option key={summary.location.location_key} value={summary.location.location_key}>
                  {formatScanLocationLabel(summary.location)} | {summary.apCount} APs
                </option>
              ))}
            </select>
          ) : null}
          <button type="button" className="secondary-button" onClick={() => setModalOpen(true)}>
            Location
          </button>
        </div>
      </div>
      {locationState.error || error ? <p className="error compact">{locationState.error ?? error}</p> : null}
      {modalOpen ? (
        <ScanLocationSettingsModal
          locationSummaries={locationSummaries}
          selectedLocationKey={selectedLocationKey}
          currentLocation={currentLocation}
          locationState={locationState}
          canScanHere={canScanHere}
          onClose={() => setModalOpen(false)}
          onSelectLocation={onSelectLocation}
          onLocate={onLocate}
          onManualCoordinateChange={onManualCoordinateChange}
          onLabelChange={onLabelChange}
          onRefresh={onRefresh}
        />
      ) : null}
    </div>
  );
}

function ScanLocationSettingsModal({
  locationSummaries,
  selectedLocationKey,
  currentLocation,
  locationState,
  canScanHere,
  onClose,
  onSelectLocation,
  onLocate,
  onManualCoordinateChange,
  onLabelChange,
  onRefresh
}: {
  locationSummaries: Array<{
    location: ScanLocationRecord;
    apCount: number;
    reviewCount: number;
    scanCount: number;
  }>;
  selectedLocationKey: string | null;
  currentLocation: ScanLocationRecord | null;
  locationState: ScanLocationState;
  canScanHere: boolean;
  onClose: () => void;
  onSelectLocation: (locationKey: string | null) => void;
  onLocate: () => void;
  onManualCoordinateChange: (value: string, field: 'latitude' | 'longitude') => void;
  onLabelChange: (label: string) => void;
  onRefresh: () => void;
}) {
  useBodyScrollLock(true);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        onClose();
      }
    };

    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [onClose]);

  return (
    <ModalPortal>
    <div className="device-modal-backdrop scan-location-modal-backdrop" role="presentation" onMouseDown={onClose}>
      <section
        className="device-modal scan-location-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="scan-location-modal-title"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <div className="insight-modal-heading">
          <div>
            <h2 id="scan-location-modal-title">Scan Location Settings</h2>
            <p>{locationSummaries.length} saved | radius 50 m</p>
          </div>
          <button type="button" className="device-modal-close" onClick={onClose} aria-label="Close scan location settings">
            x
          </button>
        </div>
        <div className="scan-location-controls">
          <button type="button" className="secondary-button" onClick={onLocate} disabled={locationState.locating}>
            {locationState.locating ? 'Locating' : 'Locate'}
          </button>
          <label>
            <span>Lat</span>
            <input
              value={locationState.latitudeInput}
              onChange={(event) => onManualCoordinateChange(event.target.value, 'latitude')}
              placeholder={GEO_LATITUDE_PLACEHOLDER}
              inputMode="decimal"
            />
          </label>
          <label>
            <span>Lng</span>
            <input
              value={locationState.longitudeInput}
              onChange={(event) => onManualCoordinateChange(event.target.value, 'longitude')}
              placeholder={GEO_LONGITUDE_PLACEHOLDER}
              inputMode="decimal"
            />
          </label>
          <label className="scan-location-label-field">
            <span>Label</span>
            <input
              value={locationState.labelInput}
              onChange={(event) => onLabelChange(event.target.value)}
              placeholder="Office, home, rack..."
            />
          </label>
          <button type="button" className="primary-button" onClick={onRefresh} disabled={!canScanHere}>
            Scan here
          </button>
        </div>
        {locationState.error ? <p className="error compact">{locationState.error}</p> : null}
        <div className="scan-location-map" aria-label="Saved scan locations">
          {locationSummaries.length === 0 ? (
            <p className="muted compact">No saved scan locations yet. Set browser or manual coordinates, then run a scan.</p>
          ) : (
            <ol>
              {locationSummaries.map((summary, index) => {
                const selected = selectedLocationKey === summary.location.location_key;
                const current = currentLocation?.location_key === summary.location.location_key;
                return (
                  <li key={summary.location.location_key}>
                    <button
                      type="button"
                      className={`scan-location-card ${selected ? 'scan-location-selected' : ''} ${current ? 'scan-location-current' : ''} ${summary.reviewCount > 0 ? 'scan-location-review' : ''}`}
                      style={scanLocationCardStyle(index, locationSummaries.length)}
                      onClick={() => onSelectLocation(summary.location.location_key)}
                    >
                      <strong>{formatScanLocationLabel(summary.location)}</strong>
                      <span>{summary.apCount} APs | {summary.reviewCount} review | {summary.scanCount} scans</span>
                      <small>
                        {summary.location.latitude.toFixed(5)}, {summary.location.longitude.toFixed(5)} | last {formatDateTime(summary.location.last_seen_utc)}
                      </small>
                    </button>
                  </li>
                );
              })}
            </ol>
          )}
        </div>
      </section>
    </div>
    </ModalPortal>
  );
}

function LocationRfMap({
  location,
  locationControl,
  items,
  summaryItems,
  intelSummary,
  ssidBuckets,
  activeFilter,
  currentSnapshot,
  nowMs,
  source,
  onFilterChange,
  onThreatReview,
  newWindowMinutes,
  onNewWindowChange,
  onIntelligenceUpdated,
  onVulnerabilityLookupUpdated,
  onVulnerabilityLookupRecorded
}: {
  location: ScanLocationRecord | null;
  locationControl?: ReactNode;
  items: Array<RememberedNetwork & { ageSeconds: number | null; isStale: boolean }>;
  summaryItems: Array<RememberedNetwork & { ageSeconds: number | null; isStale: boolean }>;
  intelSummary: BaselineNetworksResult['mac_summary'];
  ssidBuckets: Array<{ value: string; count: number }>;
  activeFilter: NetworkIntelFilter;
  currentSnapshot: WindowsWifiSnapshot | null;
  nowMs: number;
  source: CollectorSourceStatus | null;
  onFilterChange: (filter: NetworkIntelFilter) => void;
  onThreatReview: () => void;
  newWindowMinutes: number;
  onNewWindowChange: (value: number) => void;
  onIntelligenceUpdated: (network: WindowsWifiNetwork, override: DeviceIntelligenceOverride) => void;
  onVulnerabilityLookupUpdated: (network: WindowsWifiNetwork, result: DeviceVulnerabilityLookupResult) => void;
  onVulnerabilityLookupRecorded: LeakLookupRecordAppender;
}) {
  const [showAllMapItems, setShowAllMapItems] = useState(false);
  const [mapRangeKm, setMapRangeKm] = useState(0.08);
  const [mapHistoryFilter, setMapHistoryFilter] = useState<MapHistoryFilter>(MAP_DEFAULT_HISTORY_FILTER);
  const exactConnectedItem = useMemo(
    () => findExactConnectedMapItem(items, currentSnapshot),
    [currentSnapshot, items]
  );
  const historyFilteredItems = useMemo(
    () => ensureMapItemIncluded(filterMapItemsByHistory(items, mapHistoryFilter, nowMs), exactConnectedItem),
    [exactConnectedItem, items, mapHistoryFilter, nowMs]
  );
  const visibleItems = useMemo(
    () =>
      ensureMapItemIncluded(
        showAllMapItems ? historyFilteredItems : historyFilteredItems.slice(0, MAP_VISIBLE_ITEM_LIMIT),
        exactConnectedItem,
        showAllMapItems ? undefined : MAP_VISIBLE_ITEM_LIMIT
      ),
    [exactConnectedItem, historyFilteredItems, showAllMapItems]
  );
  const mapDisplayItems = useMemo(
    () => compactMapItemsForMeshProfiles(visibleItems, currentSnapshot),
    [currentSnapshot, visibleItems]
  );
  const hiddenByMeshGroupingCount = Math.max(0, visibleItems.length - mapDisplayItems.length);
  const hiddenByHistoryCount = Math.max(0, items.length - historyFilteredItems.length);
  const liveCount = historyFilteredItems.filter((item) => !item.isStale).length;
  const staleCount = Math.max(0, historyFilteredItems.length - liveCount);
  const reviewCount = historyFilteredItems.filter((item) => {
    const level = item.network.vulnerability_intel?.exposure_level;
    return level === 'review' || level === 'priority';
  }).length;
  const totalLiveCount = summaryItems.filter((item) => !item.isStale).length;
  const totalStaleCount = Math.max(0, summaryItems.length - totalLiveCount);
  const totalReviewCount = summaryItems.filter((item) => {
    const level = item.network.vulnerability_intel?.exposure_level;
    return level === 'review' || level === 'priority';
  }).length;
  const totalSourceCount = summaryItems.filter(isRememberedNetworkFromLatestSource).length;
  const totalNewCount = summaryItems.filter(isRememberedNetworkNewInInventory).length;
  const totalLocalNetworkCount = summaryItems.filter((item) =>
    rememberedNetworkInCurrentLocalNetwork(item, currentSnapshot, summaryItems)
  ).length;
  const strongest = historyFilteredItems.find((item) => !item.isStale) ?? historyFilteredItems[0] ?? null;
  const isFiltered = activeFilter.kind !== 'all';
  const [zoom, setZoom] = useState(1);
  // layoutZoom only jumps when zoom has changed by >=50% since the last layout, so
  // the expensive node layout / clustering re-solves at 50% boundaries (no per-tick
  // jitter). Between boundaries the canvas scales smoothly via CSS (scale = zoom /
  // layoutZoom), so zoom feels continuous but positions stay fixed.
  const [layoutZoom, setLayoutZoom] = useState(1);
  const [pan, setPan] = useState<MapPan>({ x: 0, y: 0 });
  const [isPanning, setIsPanning] = useState(false);
  const [fullscreen, setFullscreen] = useState(false);
  const [highlightedItemKey, setHighlightedItemKey] = useState<string | null>(null);
  const [highlightedClusterKey, setHighlightedClusterKey] = useState<string | null>(null);
  const [selectedItemKey, setSelectedItemKey] = useState<string | null>(null);
  const [selectedClusterKey, setSelectedClusterKey] = useState<string | null>(null);
  const [selectedLinkId, setSelectedLinkId] = useState<string | null>(null);
  const [mapTooltip, setMapTooltip] = useState<MapHoverTooltip | null>(null);
  const [localDetailsOpen, setLocalDetailsOpen] = useState(false);
  const [mapViewportSize, setMapViewportSize] = useState<MapViewportSize>({ width: 0, height: 0 });
  const mapStageRef = useRef<HTMLDivElement | null>(null);
  useBodyScrollLock(fullscreen);
  const dragStateRef = useRef<{
    pointerId: number;
    startX: number;
    startY: number;
    originX: number;
    originY: number;
  } | null>(null);
  const suppressNextMapClickRef = useRef(false);
  // Re-solve the layout only when zoom has moved >=50% from the last layout zoom.
  useEffect(() => {
    setLayoutZoom((prev) => {
      const ratio = zoom / prev;
      return ratio >= 1.5 || ratio <= 1 / 1.5 ? zoom : prev;
    });
  }, [zoom]);
  const mapDrawables = useMemo(
    () => clusterMapItems(mapDisplayItems, layoutZoom, currentSnapshot, mapRangeKm),
    [currentSnapshot, mapDisplayItems, mapRangeKm, layoutZoom]
  );
  const mapDrawablePositions = useMemo(
    () => layoutMapDrawables(mapDrawables, layoutZoom, mapViewportSize),
    [mapDrawables, mapViewportSize, layoutZoom]
  );
  const mapItemPositions = useMemo(
    () => mapItemPositionsFromDrawables(mapDrawables, mapDrawablePositions, layoutZoom),
    [mapDrawables, mapDrawablePositions, layoutZoom]
  );
  const mapItemEndpointRadii = useMemo(
    () => mapItemEndpointRadiiFromDrawables(mapDrawables),
    [mapDrawables]
  );
  const mapLinks = useMemo(
    () => buildMapConnectionLinks(mapDisplayItems, currentSnapshot, mapItemPositions, mapItemEndpointRadii),
    [mapDisplayItems, currentSnapshot, mapItemPositions, mapItemEndpointRadii]
  );
  const connectedMapItem = useMemo(
    () => findConnectedMapItem(mapDisplayItems, currentSnapshot),
    [mapDisplayItems, currentSnapshot]
  );
  const selectedItem = selectedItemKey ? items.find((item) => item.key === selectedItemKey) ?? null : null;
  const selectedCluster = selectedClusterKey
    ? mapDrawables.find((drawable): drawable is MapCluster => drawable.kind === 'cluster' && drawable.id === selectedClusterKey) ?? null
    : null;
  const highlightedCluster = highlightedClusterKey
    ? mapDrawables.find((drawable): drawable is MapCluster => drawable.kind === 'cluster' && drawable.id === highlightedClusterKey) ?? null
    : null;
  const highlightedItemKeys = useMemo(() => {
    const keys = new Set<string>();
    if (highlightedItemKey && highlightedItemKey !== LOCAL_MAP_NODE_KEY) {
      keys.add(highlightedItemKey);
    }
    for (const item of highlightedCluster?.items ?? []) {
      keys.add(item.key);
    }
    return keys;
  }, [highlightedCluster, highlightedItemKey]);
  const canPanMap = zoom > 0.42;
  const displayMapLinks = useMemo(
    () => mapLinks.map((link) => mapConnectionLinkToViewport(link, mapViewportSize)),
    [mapLinks, mapViewportSize]
  );

  const mapStageStyle = useMemo(
    () =>
      ({
        '--map-grid-size': `${Math.max(14, Math.round(48 * zoom))}px`,
        '--map-grid-pan-x': `${Math.round(pan.x)}px`,
        '--map-grid-pan-y': `${Math.round(pan.y)}px`
      }) as CSSProperties,
    [pan.x, pan.y, zoom]
  );

  // Smooth zoom toward the cursor. The canvas is CSS-scaled by zoom/layoutZoom, so
  // this standard anchored-zoom pan keeps the point under the cursor fixed.
  const applyZoomDelta = useCallback((delta: number, anchor?: { clientX: number; clientY: number }) => {
    setZoom((current) => {
      const next = clampMapZoom(current + delta);
      if (next === current) {
        return current;
      }

      const stageRect = mapStageRef.current?.getBoundingClientRect() ?? null;
      setPan((currentPan) => adjustMapPanForZoom(currentPan, current, next, stageRect, anchor));
      return next;
    });
  }, []);
  const zoomIn = useCallback(() => {
    applyZoomDelta(0.18);
  }, [applyZoomDelta]);
  const zoomOut = useCallback(() => {
    applyZoomDelta(-0.18);
  }, [applyZoomDelta]);
  const resetZoom = useCallback(() => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
  }, []);
  const handleMapWheel = useCallback(
    (event: WheelEvent<HTMLDivElement>) => {
      if (!event.ctrlKey) {
        return;
      }

      event.preventDefault();
      applyZoomDelta(event.deltaY < 0 ? 0.12 : -0.12, { clientX: event.clientX, clientY: event.clientY });
    },
    [applyZoomDelta]
  );
  const handleMapPointerDown = useCallback(
    (event: ReactPointerEvent<HTMLDivElement>) => {
      const target = event.target as HTMLElement;
      if (
        event.button !== 0 ||
        !canPanMap ||
        target.closest('.map-toolbar, .map-location-toolbar, .map-connection-layer, .map-center, .map-node, .map-cluster')
      ) {
        return;
      }

      dragStateRef.current = {
        pointerId: event.pointerId,
        startX: event.clientX,
        startY: event.clientY,
        originX: pan.x,
        originY: pan.y
      };
      setIsPanning(true);
    },
    [canPanMap, pan.x, pan.y]
  );
  const handleMapClickCapture = useCallback((event: ReactMouseEvent<HTMLDivElement>) => {
    if (!suppressNextMapClickRef.current) {
      return;
    }

    event.preventDefault();
    event.stopPropagation();
    suppressNextMapClickRef.current = false;
  }, []);
  const closeModal = useCallback(() => setSelectedItemKey(null), []);
  const closeCluster = useCallback(() => setSelectedClusterKey(null), []);
  const clearMapSelection = useCallback((event: ReactMouseEvent<HTMLDivElement>) => {
    const target = event.target as HTMLElement;
    if (target.closest('.map-toolbar, .map-location-toolbar, .map-node, .map-center, .map-cluster, .map-cluster-panel')) {
      return;
    }

    setHighlightedItemKey(null);
    setHighlightedClusterKey(null);
    setSelectedLinkId(null);
    setMapTooltip(null);
  }, []);
  const clearMapTooltip = useCallback((tooltipId: string) => {
    setMapTooltip((current) => (current?.id === tooltipId ? null : current));
  }, []);

  useEffect(() => {
    if (!canPanMap) {
      setPan({ x: 0, y: 0 });
      setIsPanning(false);
      dragStateRef.current = null;
    }
  }, [canPanMap]);

  useEffect(() => {
    const stage = mapStageRef.current;
    if (!stage) {
      return undefined;
    }

    const updateSize = () => {
      const rect = stage.getBoundingClientRect();
      const width = Math.round(rect.width);
      const height = Math.round(rect.height);
      setMapViewportSize((current) => (current.width === width && current.height === height ? current : { width, height }));
    };

    updateSize();
    if (typeof ResizeObserver === 'undefined') {
      window.addEventListener('resize', updateSize);
      return () => window.removeEventListener('resize', updateSize);
    }

    const observer = new ResizeObserver(updateSize);
    observer.observe(stage);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    if (!fullscreen) {
      return undefined;
    }

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') {
        return;
      }
      if (selectedItemKey || selectedClusterKey || localDetailsOpen) {
        return;
      }

      setFullscreen(false);
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [fullscreen, localDetailsOpen, selectedClusterKey, selectedItemKey]);

  useEffect(() => {
    if (!fullscreen) {
      return undefined;
    }

    const handleWheel = (event: globalThis.WheelEvent) => {
      if (shouldPreventFullscreenScrollLeak(event.target, event.deltaY)) {
        event.preventDefault();
      }
    };
    const handleTouchMove = (event: TouchEvent) => {
      if (!(event.target instanceof Element) || !event.target.closest('.map-panel-fullscreen')) {
        event.preventDefault();
      }
    };

    window.addEventListener('wheel', handleWheel, { capture: true, passive: false });
    window.addEventListener('touchmove', handleTouchMove, { capture: true, passive: false });
    return () => {
      window.removeEventListener('wheel', handleWheel, { capture: true });
      window.removeEventListener('touchmove', handleTouchMove, { capture: true });
    };
  }, [fullscreen]);

  useEffect(() => {
    if (!isPanning) {
      return undefined;
    }

    const handleWindowPointerMove = (event: PointerEvent) => {
      const dragState = dragStateRef.current;
      if (!dragState || dragState.pointerId !== event.pointerId) {
        return;
      }

      event.preventDefault();
      const deltaX = event.clientX - dragState.startX;
      const deltaY = event.clientY - dragState.startY;
      if (Math.abs(deltaX) > 4 || Math.abs(deltaY) > 4) {
        suppressNextMapClickRef.current = true;
      }

      setPan({
        x: clampMapPan(dragState.originX + deltaX, zoom),
        y: clampMapPan(dragState.originY + deltaY, zoom)
      });
    };

    const stopWindowPan = (event: PointerEvent) => {
      const dragState = dragStateRef.current;
      if (!dragState || dragState.pointerId !== event.pointerId) {
        return;
      }

      dragStateRef.current = null;
      setIsPanning(false);
    };

    window.addEventListener('pointermove', handleWindowPointerMove);
    window.addEventListener('pointerup', stopWindowPan);
    window.addEventListener('pointercancel', stopWindowPan);

    return () => {
      window.removeEventListener('pointermove', handleWindowPointerMove);
      window.removeEventListener('pointerup', stopWindowPan);
      window.removeEventListener('pointercancel', stopWindowPan);
    };
  }, [isPanning, zoom]);

  useEffect(() => {
    if (
      selectedClusterKey &&
      !mapDrawables.some((drawable) => drawable.kind === 'cluster' && drawable.id === selectedClusterKey)
    ) {
      setSelectedClusterKey(null);
    }
  }, [mapDrawables, selectedClusterKey]);

  useEffect(() => {
    if (
      highlightedClusterKey &&
      !mapDrawables.some((drawable) => drawable.kind === 'cluster' && drawable.id === highlightedClusterKey)
    ) {
      setHighlightedClusterKey(null);
    }
  }, [highlightedClusterKey, mapDrawables]);

  useEffect(() => {
    if (selectedLinkId && !mapLinks.some((link) => link.id === selectedLinkId)) {
      setSelectedLinkId(null);
    }
  }, [mapLinks, selectedLinkId]);

  const rangeSelectLabel = 'Spread';
  const rangeLabels = {
    near: 'near',
    mid: 'mid',
    far: 'far'
  };
  const rangeStatusLabel = 'relative RF layout';
  const mapStatusLabel = [
    showAllMapItems ? `${visibleItems.length} APs shown` : `${visibleItems.length} of ${historyFilteredItems.length} APs shown`,
    isWifiSnapshotConnected(currentSnapshot)
      ? exactConnectedItem
        ? `connected ${formatBssidTail(currentSnapshot.bssid ?? null)}`
        : 'connected BSSID not in AP scan'
      : null,
    rangeStatusLabel,
    'RF relative',
    location ? `location ${formatScanLocationLabel(location)}` : null,
    hiddenByHistoryCount > 0 ? `${hiddenByHistoryCount} hidden by time` : null,
    hiddenByMeshGroupingCount > 0 ? `${hiddenByMeshGroupingCount} mesh radio BSSIDs grouped` : null
  ].filter(Boolean).join(' | ');

  return (
    <article
      className={`panel map-panel ${fullscreen ? 'map-panel-fullscreen' : ''}`}
      role={fullscreen ? 'dialog' : undefined}
      aria-modal={fullscreen ? true : undefined}
    >
      <div className="panel-heading">
        <h2>{location ? `Relative RF View: ${formatScanLocationLabel(location)}` : 'Relative RF View'}</h2>
        <div className="map-heading-actions">
          {locationControl}
          <span>
            {liveCount} live / {staleCount} stale
            {strongest ? ` | strongest ${formatPercent(strongest.network.signal_percent)}` : ''}
          </span>
          <button type="button" className="ai-inline-action" onClick={onThreatReview}>
            AI review
          </button>
        </div>
      </div>
      <MapFilterToolbar
        summary={intelSummary}
        ssidBuckets={ssidBuckets}
        activeFilter={activeFilter}
        shownCount={historyFilteredItems.length}
        totalCount={summaryItems.length}
        counts={{
          live: totalLiveCount,
          stale: totalStaleCount,
          review: totalReviewCount,
          source: totalSourceCount,
          newDevice: totalNewCount,
          localNetwork: totalLocalNetworkCount
        }}
        sourceReady={Boolean(source?.available)}
        onFilterChange={onFilterChange}
      />
      <div className="map-inline-controls" aria-label="RF map filters">
        <label className="new-window-control">
          <span>New =</span>
          <select
            value={newWindowMinutes}
            onChange={(event) => onNewWindowChange(Number(event.target.value))}
            aria-label="New device window"
          >
            <option value={15}>15 min</option>
            <option value={30}>30 min</option>
            <option value={60}>1 hour</option>
            <option value={360}>6 hours</option>
            <option value={1440}>24 hours</option>
          </select>
        </label>
        <button
          type="button"
          className={showAllMapItems ? 'map-location-toggle map-location-toggle-active' : 'map-location-toggle'}
          onClick={() => setShowAllMapItems((current) => !current)}
        >
          {showAllMapItems ? `All ${items.length}` : `Top ${Math.min(MAP_VISIBLE_ITEM_LIMIT, items.length)}`}
        </button>
        <label>
          <span>{rangeSelectLabel}</span>
          <select value={mapRangeKm} onChange={(event) => setMapRangeKm(Number(event.target.value))}>
            <option value={0.03}>tight</option>
            <option value={0.05}>compact</option>
            <option value={0.08}>normal</option>
            <option value={0.12}>wide</option>
            <option value={0.25}>wide+</option>
            <option value={0.5}>far</option>
            <option value={1}>far+</option>
          </select>
        </label>
        <label>
          <span>Seen</span>
          <select value={mapHistoryFilter} onChange={(event) => setMapHistoryFilter(event.target.value as MapHistoryFilter)}>
            {MAP_HISTORY_FILTERS.map((filter) => (
              <option key={filter.value} value={filter.value}>
                {filter.label}
              </option>
            ))}
          </select>
        </label>
      </div>
      <div className="ap-map-layout">
        <div
          ref={mapStageRef}
          className={`ap-map-stage ${canPanMap ? 'ap-map-stage-pannable' : ''} ${isPanning ? 'ap-map-stage-panning' : ''}`}
          style={mapStageStyle}
          aria-label="Nearby AP signal map"
          onWheel={handleMapWheel}
          onPointerDown={handleMapPointerDown}
          onClickCapture={handleMapClickCapture}
          onClick={clearMapSelection}
        >
          <div className="map-toolbar map-viewport-toolbar" aria-label="Map controls">
            <button type="button" onClick={zoomOut} aria-label="Zoom out">-</button>
            <span>{Math.round(zoom * 100)}%</span>
            <button type="button" onClick={zoomIn} aria-label="Zoom in">+</button>
            <button type="button" onClick={resetZoom}>Reset</button>
            <button type="button" onClick={() => setFullscreen((current) => !current)}>
              {fullscreen ? 'Exit full' : 'Full map'}
            </button>
          </div>
          <div className="ap-map-canvas" style={{ transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom / layoutZoom})` }}>
            <div className="map-ring map-ring-near" style={mapRingStyle(26, layoutZoom, mapViewportSize)}><span>{rangeLabels.near}</span></div>
            <div className="map-ring map-ring-mid" style={mapRingStyle(54, layoutZoom, mapViewportSize)}><span>{rangeLabels.mid}</span></div>
            <div className="map-ring map-ring-far" style={mapRingStyle(82, layoutZoom, mapViewportSize)}><span>{rangeLabels.far}</span></div>
            <MapConnectionLayer
              links={displayMapLinks}
              selectedLinkId={selectedLinkId}
              highlightedItemKey={highlightedItemKey}
              highlightedItemKeys={highlightedItemKeys}
              onSelect={setSelectedLinkId}
              onHighlight={(itemKey) => {
                setHighlightedItemKey(itemKey);
                setHighlightedClusterKey(null);
              }}
            />
            <button
              type="button"
              className={`map-center map-center-button ${highlightedItemKey === LOCAL_MAP_NODE_KEY ? 'map-center-selected' : ''}`}
              onMouseEnter={() => setMapTooltip(buildLocalMapTooltip(currentSnapshot, { x: 50, y: 50 }, mapLinks.filter((link) => link.sourceKey === null).length))}
              onMouseLeave={() => clearMapTooltip(LOCAL_MAP_NODE_KEY)}
              onFocus={() => setMapTooltip(buildLocalMapTooltip(currentSnapshot, { x: 50, y: 50 }, mapLinks.filter((link) => link.sourceKey === null).length))}
              onBlur={() => clearMapTooltip(LOCAL_MAP_NODE_KEY)}
              onClick={(event) => {
                event.stopPropagation();
                setHighlightedItemKey(LOCAL_MAP_NODE_KEY);
                setHighlightedClusterKey(null);
                setSelectedLinkId(null);
              }}
              onDoubleClick={(event) => {
                event.stopPropagation();
                setLocalDetailsOpen(true);
              }}
              aria-label="Local Wi-Fi client. Click to highlight local Wi-Fi links. Double-click for local adapter details."
            >
              <strong>You</strong>
              <span>{formatDateTime(new Date(nowMs).toISOString())}</span>
            </button>
            {mapDrawables.map((drawable) => {
              const metricPosition = mapDrawablePositions.get(drawable.id) ?? zoomMapPosition(drawable.position, layoutZoom);
              const displayPosition = mapMetricPointToViewport(metricPosition, mapViewportSize);

              if (drawable.kind === 'cluster') {
                const topItem = drawable.items[0];
                const strongestSsid = valueOrUnknown(topItem?.network.ssid ?? null);
                const clusterItemKeys = new Set(drawable.items.map((item) => item.key));
                const clusterHasLinks = mapLinks.some(
                  (link) =>
                    clusterItemKeys.has(link.targetKey) ||
                    (link.sourceKey !== null && clusterItemKeys.has(link.sourceKey))
                );
                const isHighlightedCluster = highlightedClusterKey === drawable.id;
                const clusterDistance = mapDistanceForPosition(metricPosition, mapRangeKm, zoom);
                const clusterDistanceLabel = '';
                const clusterTitleDistance = ' Relative RF group position.';
                const clusterLastVisible = formatMapClusterLastVisible(drawable.items);
                const clusterTooltip = buildMapClusterTooltip(
                  drawable,
                  displayPosition,
                  false,
                  clusterDistance,
                  clusterLastVisible
                );
                return (
                  <button
                    key={drawable.id}
                    type="button"
                    className={`map-cluster ${drawable.reviewCount > 0 ? 'map-cluster-review' : ''} ${isHighlightedCluster ? 'map-cluster-selected' : ''}`}
                    style={{ left: `${displayPosition.x}%`, top: `${displayPosition.y}%` }}
                    aria-label={
                      clusterHasLinks && !isHighlightedCluster
                        ? `${drawable.items.length} APs grouped here. Click to highlight links. Strongest: ${strongestSsid}. ${clusterLastVisible}.${clusterTitleDistance}`
                        : `${drawable.items.length} APs grouped here. Click to expand. Strongest: ${strongestSsid}. ${clusterLastVisible}.${clusterTitleDistance}`
                    }
                    onMouseEnter={() => setMapTooltip(clusterTooltip)}
                    onMouseLeave={() => clearMapTooltip(clusterTooltip.id)}
                    onFocus={() => setMapTooltip(clusterTooltip)}
                    onBlur={() => clearMapTooltip(clusterTooltip.id)}
                    onClick={(event) => {
                      event.stopPropagation();
                      if (!clusterHasLinks || isHighlightedCluster) {
                        setSelectedClusterKey(drawable.id);
                        return;
                      }

                      setHighlightedItemKey(null);
                      setHighlightedClusterKey(drawable.id);
                      setSelectedLinkId(null);
                      setSelectedClusterKey(null);
                    }}
                    onDoubleClick={(event) => {
                      event.stopPropagation();
                      setSelectedClusterKey(drawable.id);
                    }}
                  >
                    <strong>{drawable.items.length}</strong>
                    <span>APs</span>
                    <small>{formatPercent(drawable.strongestSignal)}{clusterDistanceLabel}</small>
                  </button>
                );
              }

              const { item } = drawable;
              const linkKind = mapLinkKindForItem(mapLinks, item.key);
              const visual = mapNodeDeviceVisual(item.network, linkKind);
              const risk = item.network.security_assessment?.danger_level ?? 'medium';
              const exposure = item.network.vulnerability_intel?.exposure_level ?? 'none';
              const securityTone = mapSecurityVisualTone(item.network);
              const vendor = formatNetworkVendorLabel(item.network);
              const isNewDevice = isRememberedNetworkNewInInventory(item);
              const isOldMapItem = isMapItemOld(item);
              const isHighlighted = highlightedItemKey === item.key;
              const outsideCurrentNetwork =
                Boolean(connectedMapItem) && !sameWifiProfile(item.network, connectedMapItem?.network ?? item.network);
              const nodeDistance = mapDistanceForPosition(metricPosition, mapRangeKm, zoom);
              const nodeTitle = formatMapItemTitle({
                item,
                vendor,
                rfOnly: true,
                distanceKm: nodeDistance,
                connected: connectedMapItem?.key === item.key
              });
              const nodeTooltip = buildMapItemTooltip({
                item,
                vendor,
                visual,
                rfOnly: true,
                distanceKm: nodeDistance,
                connected: connectedMapItem?.key === item.key,
                position: displayPosition
              });
              const nodeStyle = {
                left: `${displayPosition.x}%`,
                top: `${displayPosition.y}%`
              } as CSSProperties;

              return (
                <button
                  key={item.key}
                  type="button"
                  className={`map-node map-node-${visual.kind} map-node-risk-${risk} map-node-security-${securityTone} map-node-exposure-${exposure} ${linkKind ? `map-node-link-${linkKind}` : ''} ${isHighlighted ? 'map-node-selected' : ''} ${outsideCurrentNetwork ? 'map-node-outside-network' : ''} ${item.isStale ? 'map-node-stale' : ''} ${isOldMapItem ? 'map-node-old' : ''} ${isNewDevice ? 'map-node-new' : ''}`}
                  style={nodeStyle}
                  aria-label={nodeTitle}
                  onMouseEnter={() => setMapTooltip(nodeTooltip)}
                  onMouseLeave={() => clearMapTooltip(nodeTooltip.id)}
                  onFocus={() => setMapTooltip(nodeTooltip)}
                  onBlur={() => clearMapTooltip(nodeTooltip.id)}
                  onClick={(event) => {
                    event.stopPropagation();
                    setHighlightedItemKey(item.key);
                    setHighlightedClusterKey(null);
                    setSelectedLinkId(null);
                  }}
                  onDoubleClick={(event) => {
                    event.stopPropagation();
                    setSelectedItemKey(item.key);
                  }}
                >
                  <span className="map-node-orb">
                    <span className="map-node-avatar">
                      <img src={visual.image} alt={visual.alt} />
                    </span>
                    <SignalBars percent={item.network.signal_percent} />
                  </span>
                  <span className="map-node-label">
                    <strong>{formatNetworkSsidLabel(item.network)}</strong>
                    <small className={`map-node-age${isFreshMapItem(item.ageSeconds) ? ' map-node-age-live' : ''}`}>
                      {formatCompactAge(item.ageSeconds)}
                    </small>
                  </span>
                </button>
              );
            })}
          </div>
          {mapTooltip ? <MapHoverTooltipView tooltip={mapTooltip} pan={pan} /> : null}
          {selectedCluster ? (
            <MapClusterOverlay
              cluster={selectedCluster}
              onClose={closeCluster}
              onSelectItem={(itemKey) => {
                setSelectedItemKey(itemKey);
                setSelectedClusterKey(null);
              }}
            />
          ) : null}
        </div>
        <div className="map-side-list">
          <div className="map-side-heading">
            <div>
              <strong>AP Memory</strong>
              <small>{mapStatusLabel}</small>
            </div>
          </div>
          <ol>
            {mapDisplayItems.slice(0, 10).map((item) => {
              const visual = networkDeviceVisual(item.network);
              const vendor = formatNetworkVendorLabel(item.network);
              const isNewDevice = isRememberedNetworkNewInInventory(item);
              const isOldMapItem = isMapItemOld(item);
              return (
                <li key={item.key} className={`${item.isStale ? 'map-memory-stale' : ''} ${isOldMapItem ? 'map-memory-old' : ''} ${isNewDevice ? 'map-memory-new' : ''}`}>
                  <span className={`map-memory-avatar map-memory-${visual.kind}`}>
                    <img src={visual.image} alt={visual.alt} />
                  </span>
                  <button
                    type="button"
                    className={`map-memory-button ${highlightedItemKey === item.key ? 'map-memory-button-selected' : ''}`}
                    onClick={() => {
                      setHighlightedItemKey(item.key);
                      setHighlightedClusterKey(null);
                      setSelectedLinkId(null);
                    }}
                    onDoubleClick={() => setSelectedItemKey(item.key)}
                  >
                    <strong>{formatNetworkSsidLabel(item.network)}</strong>
                    <small>
                      {vendor} | {formatVulnerabilityBadge(item.network.vulnerability_intel)}
                    </small>
                    <small>
                      {visual.label} | {valueOrUnknown(item.network.bssid)} | {formatPercent(item.network.signal_percent)} | {formatMapLastVisible(item)}
                    </small>
                  </button>
                </li>
              );
            })}
          </ol>
        </div>
      </div>
      {selectedItem ? (
        <DeviceModal
          item={selectedItem}
          currentSnapshot={currentSnapshot}
          onClose={closeModal}
          onIntelligenceUpdated={onIntelligenceUpdated}
          onVulnerabilityLookupUpdated={onVulnerabilityLookupUpdated}
          onVulnerabilityLookupRecorded={onVulnerabilityLookupRecorded}
        />
      ) : null}
      {localDetailsOpen ? (
        <LocalDeviceModal
          snapshot={currentSnapshot}
          linkCount={mapLinks.filter((link) => link.sourceKey === null).length}
          onClose={() => setLocalDetailsOpen(false)}
        />
      ) : null}
    </article>
  );
}

function MapFilterToolbar({
  summary,
  ssidBuckets,
  activeFilter,
  shownCount,
  totalCount,
  counts,
  sourceReady,
  onFilterChange
}: {
  summary: BaselineNetworksResult['mac_summary'];
  ssidBuckets: Array<{ value: string; count: number }>;
  activeFilter: NetworkIntelFilter;
  shownCount: number;
  totalCount: number;
  counts: {
    live: number;
    stale: number;
    review: number;
    source: number;
    newDevice: number;
    localNetwork: number;
  };
  sourceReady: boolean;
  onFilterChange: (filter: NetworkIntelFilter) => void;
}) {
  const quickFilters: Array<{
    label: string;
    value: number | string;
    filter: NetworkIntelFilter;
    tone?: 'review' | 'source' | 'down';
  }> = [
    { label: 'All', value: totalCount, filter: ALL_NETWORK_INTEL_FILTER },
    { label: 'Live', value: counts.live, filter: LIVE_NETWORK_INTEL_FILTER },
    { label: 'Stale', value: counts.stale, filter: STALE_NETWORK_INTEL_FILTER },
    { label: 'Review', value: counts.review, filter: REVIEW_NETWORK_INTEL_FILTER, tone: 'review' as const },
    {
      label: 'Latest',
      value: counts.source,
      filter: SOURCE_NETWORK_INTEL_FILTER,
      tone: sourceReady ? ('source' as const) : ('down' as const)
    },
    { label: 'New', value: counts.newDevice, filter: NEW_DEVICE_NETWORK_INTEL_FILTER, tone: 'review' as const },
    { label: 'LAN', value: counts.localNetwork, filter: LOCAL_NETWORK_INTEL_FILTER, tone: 'source' as const },
    { label: 'Known', value: summary.known_vendor_count, filter: { kind: 'knownVendor', label: 'Known vendors' } },
    { label: 'Unk', value: summary.unknown_vendor_count, filter: { kind: 'unknownVendor', label: 'Unknown vendor' } },
    { label: 'Local', value: summary.local_mac_count, filter: { kind: 'localMac', label: 'Local MAC' } }
  ];
  const vendorValue = activeFilter.kind === 'vendor' ? activeFilter.value ?? '' : '';
  const ssidValue = activeFilter.kind === 'ssid' ? activeFilter.value ?? '' : '';
  const hintValue = activeFilter.kind === 'deviceHint' ? activeFilter.value ?? '' : '';
  const ouiValue = activeFilter.kind === 'unknownOui' ? activeFilter.value ?? '' : '';
  const isFiltered = activeFilter.kind !== 'all';
  const advancedActive =
    activeFilter.kind === 'ssid' ||
    activeFilter.kind === 'vendor' ||
    activeFilter.kind === 'deviceHint' ||
    activeFilter.kind === 'unknownOui';
  const [showAdvanced, setShowAdvanced] = useState(false);
  const selectsVisible = showAdvanced || advancedActive;

  return (
    <div className="map-filter-toolbar">
      <div className="map-filter-summary">
        <strong>{shownCount}</strong>
        <span>shown / {totalCount}</span>
      </div>
      <div className="map-filter-chips" aria-label="Map quick filters">
        {quickFilters.map((item) => (
          <MapFilterChip
            key={item.filter.kind}
            label={item.label}
            value={item.value}
            filter={item.filter}
            activeFilter={activeFilter}
            onFilterChange={onFilterChange}
            tone={item.tone}
          />
        ))}
      </div>
      <button
        type="button"
        className={`map-filter-more${selectsVisible ? ' map-filter-more-open' : ''}`}
        aria-expanded={selectsVisible}
        onClick={() => setShowAdvanced((prev) => !prev)}
      >
        Filters {selectsVisible ? '▴' : '▾'}
      </button>
      {isFiltered ? (
        <button type="button" className="map-filter-clear" onClick={() => onFilterChange(ALL_NETWORK_INTEL_FILTER)}>
          Clear
        </button>
      ) : null}
      {selectsVisible ? (
        <div className="map-filter-selects">
          <MapFilterSelect
            label="SSID"
            value={ssidValue}
            values={ssidBuckets}
            placeholder="Any SSID"
            onChange={(value) => onFilterChange(value ? buildNetworkIntelBucketFilter('ssid', value) : ALL_NETWORK_INTEL_FILTER)}
          />
          <MapFilterSelect
            label="Vendor"
            value={vendorValue}
            values={summary.vendors}
            placeholder="Any vendor"
            onChange={(value) => onFilterChange(value ? buildNetworkIntelBucketFilter('vendor', value) : ALL_NETWORK_INTEL_FILTER)}
          />
          <MapFilterSelect
            label="Hint"
            value={hintValue}
            values={summary.device_hints}
            placeholder="Any device"
            onChange={(value) => onFilterChange(value ? buildNetworkIntelBucketFilter('deviceHint', value) : ALL_NETWORK_INTEL_FILTER)}
          />
          <MapFilterSelect
            label="OUI"
            value={ouiValue}
            values={summary.unknown_ouis}
            placeholder="Unknown OUI"
            onChange={(value) => onFilterChange(value ? buildNetworkIntelBucketFilter('unknownOui', value) : ALL_NETWORK_INTEL_FILTER)}
          />
        </div>
      ) : null}
    </div>
  );
}

function MapFilterChip({
  label,
  value,
  filter,
  activeFilter,
  onFilterChange,
  tone
}: {
  label: string;
  value: number | string;
  filter: NetworkIntelFilter;
  activeFilter: NetworkIntelFilter;
  onFilterChange: (filter: NetworkIntelFilter) => void;
  tone?: 'review' | 'source' | 'down';
}) {
  const active = isSameNetworkIntelFilter(activeFilter, filter);

  return (
    <button
      type="button"
      className={`map-filter-chip ${tone ? `map-filter-chip-${tone}` : ''} ${active ? 'map-filter-chip-active' : ''}`}
      onClick={() => onFilterChange(filter)}
      title={`Filter map and Nearby APs by ${filter.label}`}
      aria-pressed={active}
    >
      <span>{label}</span>
      <strong>{value}</strong>
    </button>
  );
}

function MapFilterSelect({
  label,
  value,
  values,
  placeholder,
  onChange
}: {
  label: string;
  value: string;
  values: Array<{ value: string; count: number }>;
  placeholder: string;
  onChange: (value: string) => void;
}) {
  return (
    <label className="map-filter-select">
      <span>{label}</span>
      <select value={value} onChange={(event) => onChange(event.target.value)}>
        <option value="">{placeholder}</option>
        {values.map((item) => (
          <option key={item.value} value={item.value}>
            {item.value} ({item.count})
          </option>
        ))}
      </select>
    </label>
  );
}

function MapConnectionLayer({
  links,
  selectedLinkId,
  highlightedItemKey,
  highlightedItemKeys,
  onSelect,
  onHighlight
}: {
  links: MapConnectionLink[];
  selectedLinkId: string | null;
  highlightedItemKey: string | null;
  highlightedItemKeys: Set<string>;
  onSelect: (linkId: string | null) => void;
  onHighlight: (itemKey: string | null) => void;
}) {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const [viewportSize, setViewportSize] = useState<MapViewportSize>({ width: 0, height: 0 });

  useEffect(() => {
    const svg = svgRef.current;
    if (!svg) {
      return undefined;
    }

    const updateSize = () => {
      const rect = svg.getBoundingClientRect();
      setViewportSize((current) => {
        const width = Math.round(rect.width);
        const height = Math.round(rect.height);
        return current.width === width && current.height === height ? current : { width, height };
      });
    };

    updateSize();
    if (typeof ResizeObserver === 'undefined') {
      window.addEventListener('resize', updateSize);
      return () => window.removeEventListener('resize', updateSize);
    }

    const observer = new ResizeObserver(updateSize);
    observer.observe(svg);
    return () => observer.disconnect();
  }, []);

  if (links.length === 0) {
    return null;
  }

  return (
    <svg ref={svgRef} className="map-connection-layer" viewBox="0 0 100 100" preserveAspectRatio="none" aria-label="Map links">
      {links.map((link, index) => {
        const path = mapConnectionPath(link, index, viewportSize);
        const width = mapConnectionWidth(link);
        const isSelected = link.id === selectedLinkId;
        const hasHighlightedItems = highlightedItemKeys.size > 0;
        const isHighlighted =
          highlightedItemKey === LOCAL_MAP_NODE_KEY
            ? link.sourceKey === null
            : hasHighlightedItems &&
              (highlightedItemKeys.has(link.targetKey) ||
                (link.sourceKey !== null && highlightedItemKeys.has(link.sourceKey)));
        const hasHighlight = highlightedItemKey === LOCAL_MAP_NODE_KEY || hasHighlightedItems;
        const isDefaultVisible = !hasHighlight && selectedLinkId === null;
        if (!isDefaultVisible && !isSelected && !isHighlighted) {
          return null;
        }

        const isDimmed = (selectedLinkId !== null && !isSelected) || (selectedLinkId === null && hasHighlight && !isHighlighted);
        const style = {
          '--map-link-edge-width': width.edge,
          '--map-link-core-width': width.core
        } as CSSProperties;
        return (
          <g
            key={link.id}
            className={`map-connection map-connection-${link.kind} ${isSelected ? 'map-connection-selected' : ''} ${isHighlighted ? 'map-connection-highlighted' : ''} ${isDimmed ? 'map-connection-dimmed' : ''}`}
            style={style}
            role="button"
            tabIndex={0}
            aria-label={`${link.label}: ${link.detail}`}
            onClick={(event) => {
              event.stopPropagation();
              onHighlight(null);
              onSelect(isSelected ? null : link.id);
            }}
            onKeyDown={(event) => {
              if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault();
                onHighlight(null);
                onSelect(isSelected ? null : link.id);
              }
            }}
          >
            <path className="map-connection-hit" d={path} vectorEffect="non-scaling-stroke" />
            <path className="map-connection-edge" d={path} vectorEffect="non-scaling-stroke" />
            <path className="map-connection-core" d={path} vectorEffect="non-scaling-stroke" />
          </g>
        );
      })}
    </svg>
  );
}

function MapHoverTooltipView({ tooltip, pan }: { tooltip: MapHoverTooltip; pan?: MapPan }) {
  const x = clampLayoutValue(tooltip.x, 4, 96);
  const y = clampLayoutValue(tooltip.y, 6, 94);
  const sideClass = x > 72 ? 'map-hover-tooltip-left' : '';
  const verticalClass = y < 24 ? 'map-hover-tooltip-below' : '';
  const style = {
    left: `${x}%`,
    top: `${y}%`,
    '--map-tooltip-pan-x': `${pan?.x ?? 0}px`,
    '--map-tooltip-pan-y': `${pan?.y ?? 0}px`
  } as CSSProperties;

  return (
    <div
      className={`map-hover-tooltip ${sideClass} ${verticalClass}`}
      style={style}
      role="tooltip"
    >
      <strong>{tooltip.title}</strong>
      <span>{tooltip.subtitle}</span>
      <dl>
        {tooltip.facts.map((fact) => (
          <div key={fact.label}>
            <dt>{fact.label}</dt>
            <dd>{fact.value}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

function MapConnectionLabel({ link }: { link: MapConnectionLink }) {
  const position = mapConnectionLabelPosition(link);
  return (
    <g className={`map-connection-label map-connection-label-${link.kind}`} transform={`translate(${position.x} ${position.y})`}>
      <rect x="0" y="0" width="28" height="8.8" rx="1.5" />
      <text x="1.5" y="3.3">
        <tspan>{link.label}</tspan>
        <tspan x="1.5" dy="3.4">{link.detail}</tspan>
      </text>
    </g>
  );
}

function MapClusterOverlay({
  cluster,
  onClose,
  onSelectItem
}: {
  cluster: MapCluster;
  onClose: () => void;
  onSelectItem: (itemKey: string) => void;
}) {
  useBodyScrollLock(true);

  return (
    <div className="map-cluster-overlay" role="presentation" onPointerDown={(event) => event.stopPropagation()}>
      <div className="map-cluster-scrim" onClick={onClose} />
      <section className="map-cluster-panel" role="dialog" aria-modal="true" aria-label="Grouped APs">
        <div className="map-cluster-heading">
          <div>
            <h3>{cluster.items.length} grouped APs</h3>
            <p>
              {cluster.liveCount} live | {cluster.reviewCount} review | strongest {formatPercent(cluster.strongestSignal)}
            </p>
          </div>
          <button type="button" className="device-modal-close" onClick={onClose} aria-label="Close grouped APs">
            x
          </button>
        </div>
        <ol className="map-cluster-list">
          {cluster.items.map((item) => {
            const visual = networkDeviceVisual(item.network);
            const vendor = formatNetworkVendorLabel(item.network);
            return (
              <li key={item.key}>
                <button type="button" onClick={() => onSelectItem(item.key)}>
                  <span className={`map-memory-avatar map-memory-${visual.kind}`}>
                    <img src={visual.image} alt={visual.alt} />
                  </span>
                  <span>
                    <strong>{formatNetworkSsidLabel(item.network)}</strong>
                    <small>
                      {vendor} | {valueOrUnknown(item.network.bssid)}
                    </small>
                    <small>
                      {visual.label} | {formatPercent(item.network.signal_percent)} | ch {valueOrUnknown(item.network.channel)} | {formatAge(item.ageSeconds)}
                    </small>
                  </span>
                </button>
              </li>
            );
          })}
        </ol>
      </section>
    </div>
  );
}

function LocalDeviceModal({
  snapshot,
  linkCount,
  onClose
}: {
  snapshot: WindowsWifiSnapshot | null;
  linkCount: number;
  onClose: () => void;
}) {
  useBodyScrollLock(true);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        onClose();
      }
    };

    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [onClose]);

  return (
    <ModalPortal>
    <div className="device-modal-backdrop" role="presentation" onMouseDown={onClose}>
      <section
        className="device-modal local-device-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="local-device-modal-title"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <div className="insight-modal-heading">
          <div>
            <h2 id="local-device-modal-title">Local Wi-Fi Client</h2>
            <p>
              {valueOrUnknown(snapshot?.ssid ?? null)} | {valueOrUnknown(snapshot?.state ?? null)} | {linkCount} visible map links
            </p>
          </div>
          <button type="button" className="device-modal-close" onClick={onClose} aria-label="Close local client details">
            x
          </button>
        </div>
        <dl className="network-detail-grid local-device-grid">
          <DetailFact label="Adapter MAC" value={valueOrUnknown(snapshot?.physical_address ?? null)} />
          <DetailFact label="IPv4" value={formatList(snapshot?.ipv4_addresses ?? [])} />
          <DetailFact label="IPv6" value={formatList(snapshot?.ipv6_addresses ?? [])} />
          <DetailFact label="Gateway" value={valueOrUnknown(snapshot?.default_gateway ?? null)} />
          <DetailFact label="DNS" value={formatList(snapshot?.dns_servers ?? [])} />
          <DetailFact label="SSID" value={valueOrUnknown(snapshot?.ssid ?? null)} />
          <DetailFact label="BSSID" value={valueOrUnknown(snapshot?.bssid ?? null)} />
          <DetailFact label="Interface" value={valueOrUnknown(snapshot?.interface_name ?? null)} />
          <DetailFact label="Interface GUID" value={valueOrUnknown(snapshot?.interface_guid ?? null)} />
          <DetailFact label="Adapter" value={valueOrUnknown(snapshot?.adapter ?? null)} />
          <DetailFact label="Band" value={valueOrUnknown(snapshot?.band ?? null)} />
          <DetailFact label="Channel" value={valueOrUnknown(snapshot?.channel ?? null)} />
          <DetailFact label="Signal" value={`${formatPercent(snapshot?.signal_percent ?? null)} / ${formatRssi(snapshot?.rssi_dbm ?? null)}`} />
          <DetailFact label="Rates" value={formatRates(snapshot?.receive_mbps ?? null, snapshot?.transmit_mbps ?? null)} />
          <DetailFact label="Security" value={formatSecurity(snapshot?.authentication ?? null, snapshot?.cipher ?? null)} />
        </dl>
      </section>
    </div>
    </ModalPortal>
  );
}

function DeviceModal({
  item,
  currentSnapshot,
  onClose,
  onIntelligenceUpdated,
  onVulnerabilityLookupUpdated,
  onVulnerabilityLookupRecorded
}: {
  item: RememberedNetwork & { ageSeconds: number | null; isStale: boolean };
  currentSnapshot: WindowsWifiSnapshot | null;
  onClose: () => void;
  onIntelligenceUpdated: (network: WindowsWifiNetwork, override: DeviceIntelligenceOverride) => void;
  onVulnerabilityLookupUpdated: (network: WindowsWifiNetwork, result: DeviceVulnerabilityLookupResult) => void;
  onVulnerabilityLookupRecorded: LeakLookupRecordAppender;
}) {
  useBodyScrollLock(true);

  const visual = networkDeviceVisual(item.network);
  const vendor = formatNetworkVendorLabel(item.network);
  const [insightKind, setInsightKind] = useState<DeviceInsightKind | null>(null);
  const [aiResearchOpen, setAiResearchOpen] = useState(false);
  const [vulnerabilityLookupState, setVulnerabilityLookupState] = useState<{
    mode: VulnerabilityLookupMode | null;
    loading: boolean;
    scanPlan: VulnerabilityScanPlan | null;
    result: DeviceVulnerabilityLookupResult | null;
    error: string | null;
  }>({
    mode: null,
    loading: false,
    scanPlan: null,
    result: null,
    error: null
  });
  const [profileSecret, setProfileSecret] = useState<ProfileSecretState>({
    loading: false,
    revealed: false,
    result: null,
    error: null
  });
  const vulnerabilityRunTokenRef = useRef<string | null>(null);
  const canRevealSecret = canRevealProfileSecret(item.network, currentSnapshot);
  const profileSecretScopeKey = `${normalizeSsid(item.network.ssid)}|${item.network.bssid?.trim().toLowerCase() ?? ''}`;
  const scopedProfileSecretResult = profileSecretMatchesNetwork(profileSecret.result, item.network)
    ? profileSecret.result
    : null;

  useEffect(() => {
    setProfileSecret({
      loading: false,
      revealed: false,
      result: null,
      error: null
    });
  }, [profileSecretScopeKey]);

  const revealProfileSecret = useCallback(async () => {
    if (scopedProfileSecretResult && !profileSecret.error) {
      setProfileSecret((current) => ({
        ...current,
        loading: false,
        revealed: true,
        error: null
      }));
      return;
    }

    const ssid = item.network.ssid?.trim();
    if (!ssid || !window.monitor?.getWifiProfileSecret) {
      setProfileSecret({
        loading: false,
        revealed: false,
        result: null,
        error: 'Saved Wi-Fi profile secret lookup is not available.'
      });
      return;
    }

    setProfileSecret((current) => ({ ...current, loading: true, error: null }));
    try {
      const result = await window.monitor.getWifiProfileSecret({ ssid });
      setProfileSecret({
        loading: false,
        revealed: true,
        result,
        error: result.error
      });
    } catch (error) {
      setProfileSecret({
        loading: false,
        revealed: false,
        result: null,
        error: error instanceof Error ? error.message : String(error)
      });
    }
  }, [item.network.ssid, profileSecret.error, scopedProfileSecretResult]);

  const openInsight = useCallback((kind: DeviceInsightKind) => {
    setInsightKind(kind);
  }, []);

  const runVulnerabilityLookup = useCallback(async (
    mode: VulnerabilityLookupMode,
    options: VulnerabilityLookupRunOptions
  ) => {
    const plannedScanPlan = buildVulnerabilityScanPlanFromOptions(mode, options);
    if (!window.monitor?.runDeviceVulnerabilityLookup) {
      const message = 'Vulnerability lookup is available inside Electron.';
      setVulnerabilityLookupState({
        mode,
        loading: false,
        scanPlan: plannedScanPlan,
        result: null,
        error: message
      });
      onVulnerabilityLookupRecorded(item.network, null, 'failed', message, mode, plannedScanPlan);
      return;
    }

    const runToken = `${mode}:${Date.now()}:${Math.random().toString(36).slice(2)}`;
    vulnerabilityRunTokenRef.current = runToken;
    setVulnerabilityLookupState((current) => ({
      mode,
      loading: true,
      scanPlan: plannedScanPlan,
      result: current.result,
      error: null
    }));

    try {
      const capabilities = await readMonitorBridgeCapabilities();
      if (capabilities && !capabilities.ipc.device_vulnerability_lookup) {
        throw new Error(missingBridgeHandlerMessage('device:vulnerability:lookup'));
      }

      const result = await window.monitor.runDeviceVulnerabilityLookup({
        mode,
        network: item.network,
        selectedCheckIds: options.selectedCheckIds,
        operatorNote: options.operatorNote
      });
      if (vulnerabilityRunTokenRef.current !== runToken) {
        return;
      }
      vulnerabilityRunTokenRef.current = null;
      setVulnerabilityLookupState({
        mode,
        loading: false,
        scanPlan: result.scan_plan ?? plannedScanPlan,
        result,
        error: result.error
      });
      onVulnerabilityLookupUpdated(item.network, result);
    } catch (error) {
      if (vulnerabilityRunTokenRef.current !== runToken) {
        return;
      }
      const message = formatMonitorBridgeError(error, 'device:vulnerability:lookup');
      vulnerabilityRunTokenRef.current = null;
      setVulnerabilityLookupState({
        mode,
        loading: false,
        scanPlan: plannedScanPlan,
        result: null,
        error: message
      });
      onVulnerabilityLookupRecorded(item.network, null, 'failed', message, mode, plannedScanPlan);
    }
  }, [item.network, onVulnerabilityLookupRecorded, onVulnerabilityLookupUpdated]);

  const cancelVulnerabilityLookup = useCallback(() => {
    const mode = vulnerabilityLookupState.mode ?? 'passive';
    const plannedScanPlan = vulnerabilityLookupState.scanPlan;
    vulnerabilityRunTokenRef.current = null;
    setVulnerabilityLookupState((current) => ({
      ...current,
      loading: false,
      error: 'Lookup launch stopped in the UI. If the backend request was already dispatched, a saved result may appear after refresh.'
    }));
    onVulnerabilityLookupRecorded(
      item.network,
      null,
      'stopped',
      'Stopped from AP modal before a visible result was saved.',
      mode,
      plannedScanPlan
    );
  }, [item.network, onVulnerabilityLookupRecorded, vulnerabilityLookupState.mode, vulnerabilityLookupState.scanPlan]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        onClose();
      }
    };

    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [onClose]);

  return (
    <ModalPortal>
    <div className="device-modal-backdrop" role="presentation" onMouseDown={onClose}>
      <section
        className="device-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="device-modal-title"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <div className="device-modal-heading">
          <span className={`device-modal-avatar map-memory-${visual.kind}`}>
            <img src={visual.image} alt={visual.alt} />
          </span>
          <div>
            <h2 id="device-modal-title">{formatNetworkSsidLabel(item.network)}</h2>
            <p>
              {vendor} | {valueOrUnknown(item.network.bssid)} | {formatAge(item.ageSeconds)}
              {item.isStale ? ' | stale' : ' | live'}
            </p>
          </div>
          <button
            type="button"
            className="ai-research-button"
            onClick={() => setAiResearchOpen(true)}
            title="Run AI device intelligence update"
            aria-label="Run AI device intelligence update"
          >
            AI
          </button>
          <button type="button" className="device-modal-close" onClick={onClose} aria-label="Close device details">
            x
          </button>
        </div>
        <div className="device-modal-summary">
          <div className="device-modal-pill">
            <span>Signal</span>
            <strong>{formatPercent(item.network.signal_percent)}</strong>
          </div>
          <div className="device-modal-pill">
            <span>Channel</span>
            <strong>{valueOrUnknown(item.network.channel)}</strong>
          </div>
          <button
            type="button"
            className={`device-modal-pill device-modal-pill-button vulnerability-${item.network.vulnerability_intel?.exposure_level ?? 'none'}`}
            onClick={() => openInsight('exposure')}
          >
            <span>Exposure</span>
            <strong>{formatVulnerabilityBadge(item.network.vulnerability_intel)}</strong>
          </button>
          <button
            type="button"
            className={`device-modal-pill device-modal-pill-button security-risk-${item.network.security_assessment?.danger_level ?? 'medium'}`}
            onClick={() => openInsight('security')}
          >
            <span>Security</span>
            <strong>{formatNetworkSecurityBadge(item.network)}</strong>
          </button>
        </div>
        <VulnerabilityLookupPanel
          network={item.network}
          currentSnapshot={currentSnapshot}
          state={vulnerabilityLookupState}
          onRun={runVulnerabilityLookup}
          onCancel={cancelVulnerabilityLookup}
        />
        <WifiProfileSecretPanel
          network={item.network}
          currentSnapshot={currentSnapshot}
          canReveal={canRevealSecret}
          state={{ ...profileSecret, result: scopedProfileSecretResult }}
          onReveal={() => void revealProfileSecret()}
          onHide={() =>
            setProfileSecret((current) => ({
              ...current,
              loading: false,
              revealed: false,
              error: null
            }))
          }
        />
        <NetworkDetails
          network={item.network}
          id={`map-device-details-${toDomId(item.key)}`}
          onInspect={openInsight}
        />
        {insightKind ? (
          <DeviceInsightModal
            network={item.network}
            snapshot={currentSnapshot ?? undefined}
            profileSecret={scopedProfileSecretResult}
            profileSecretLoading={profileSecret.loading}
            profileSecretError={profileSecret.error}
            kind={insightKind}
            onClose={() => setInsightKind(null)}
          />
        ) : null}
        {aiResearchOpen ? (
          <AiResearchModal
            network={item.network}
            onClose={() => setAiResearchOpen(false)}
            onUpdated={onIntelligenceUpdated}
          />
        ) : null}
      </section>
    </div>
    </ModalPortal>
  );
}

function WifiProfileSecretPanel({
  network,
  currentSnapshot,
  canReveal,
  state,
  onReveal,
  onHide
}: {
  network: WindowsWifiNetwork;
  currentSnapshot: WindowsWifiSnapshot | null;
  canReveal: boolean;
  state: ProfileSecretState;
  onReveal: () => void;
  onHide: () => void;
}) {
  const sameProfile = normalizeSsid(network.ssid) === normalizeSsid(currentSnapshot?.ssid ?? null);
  const openNetwork = isOpenWifiNetwork(network);
  const strength = state.result?.strength ?? null;
  const passwordRisk = state.revealed && state.result ? buildKnownPasswordRisk(network, state.result) : null;

  return (
    <section className={`profile-secret-panel ${state.revealed ? 'profile-secret-revealed' : ''}`}>
      <div>
        <strong>Saved Wi-Fi profile</strong>
        <p>
          {openNetwork
            ? 'Windows reports this as an open network, so there is no saved Wi-Fi password to reveal.'
            : sameProfile
              ? 'Local Windows profile for this SSID. The password is read only on demand and is not saved by Monitor.'
              : 'Password reveal is limited to the currently connected SSID or its remembered mesh peers.'}
        </p>
      </div>
      <div className="profile-secret-actions">
        {canReveal ? (
          <button type="button" onClick={state.revealed ? onHide : onReveal} disabled={state.loading}>
            {state.loading ? 'Reading...' : state.revealed ? 'Hide password' : 'Reveal saved password'}
          </button>
        ) : null}
      </div>
      {state.error ? <p className="profile-secret-error">{state.error}</p> : null}
      {state.revealed && state.result ? (
        <div className="profile-secret-result">
          {passwordRisk ? (
            <div className={`profile-secret-warning profile-secret-warning-${passwordRisk.level}`}>
              <strong>
                {passwordRisk.level === 'high'
                  ? 'Weak saved password'
                  : passwordRisk.level === 'medium'
                    ? 'Password needs review'
                    : 'Password check'}
              </strong>
              <p>{passwordRisk.summary}</p>
              {passwordRisk.notes.length ? (
                <ul>
                  {passwordRisk.notes.map((note) => (
                    <li key={note}>{note}</li>
                  ))}
                </ul>
              ) : null}
            </div>
          ) : null}
          <dl>
            <div>
              <dt>Password</dt>
              <dd>
                {state.result.password ? <code>{state.result.password}</code> : valueOrUnknown(state.result.password)}
              </dd>
            </div>
            <div>
              <dt>Strength</dt>
              <dd>{strength ? `${strength.label} | ${strength.score}/100` : 'unknown'}</dd>
            </div>
            <div>
              <dt>Break-in difficulty</dt>
              <dd>{strength?.break_in_difficulty ?? 'unknown'}</dd>
            </div>
            <div>
              <dt>Length</dt>
              <dd>{strength?.length ?? 'unknown'}</dd>
            </div>
          </dl>
          {strength?.notes.length ? (
            <ul>
              {strength.notes.map((note) => (
                <li key={note}>{note}</li>
              ))}
            </ul>
          ) : null}
        </div>
      ) : null}
    </section>
  );
}

function VulnerabilityLookupPanel({
  network,
  currentSnapshot,
  state,
  onRun,
  onCancel
}: {
  network: WindowsWifiNetwork;
  currentSnapshot: WindowsWifiSnapshot | null;
  state: {
    mode: VulnerabilityLookupMode | null;
    loading: boolean;
    scanPlan: VulnerabilityScanPlan | null;
    result: DeviceVulnerabilityLookupResult | null;
    error: string | null;
  };
  onRun: (mode: VulnerabilityLookupMode, options: VulnerabilityLookupRunOptions) => void;
  onCancel: () => void;
}) {
  const [planMode, setPlanMode] = useState<VulnerabilityLookupMode | null>(null);
  const runningMode = state.loading ? state.mode : null;
  const result = state.result;
  const intel = result?.vulnerability_intel ?? null;
  const activeScanPlan = result?.scan_plan ?? state.scanPlan;
  const selectedPlanChecks = activeScanPlan?.checks.filter((check) => check.selected) ?? [];

  return (
    <section className="vulnerability-lookup-panel">
      <div>
        <strong>Vulnerability lookup</strong>
        <p>
          Choose the checks first. Monitor records impact and does not run exploit traffic, packet injection, forced disconnects, or MAC changes.
        </p>
      </div>
      <div className="vulnerability-lookup-actions">
        <button type="button" onClick={() => setPlanMode('passive')} disabled={state.loading}>
          {runningMode === 'passive' ? 'Saving passive...' : 'Plan passive'}
        </button>
        {state.loading ? (
          <button type="button" className="danger-button" onClick={onCancel}>
            Stop lookup
          </button>
        ) : null}
      </div>
      {state.loading ? (
        <p className="vulnerability-lookup-running">
          Running {state.mode} lookup for {formatNetworkSsidLabel(network)} / {valueOrUnknown(network.bssid)}.
          {' '}
          Saving {selectedPlanChecks.length} selected checks and waiting for backend result...
        </p>
      ) : null}
      {state.error ? <p className="vulnerability-lookup-error">{state.error}</p> : null}
      {!result && activeScanPlan ? (
        <VulnerabilityScanPlanMini
          plan={activeScanPlan}
          title={state.loading ? 'Running plan' : 'Attempted plan'}
        />
      ) : null}
      {result ? (
        <div className={`vulnerability-lookup-result vulnerability-${intel?.exposure_level ?? 'none'}`}>
          <div className="vulnerability-lookup-result-heading">
            <strong>{result.saved ? 'Lookup Result: saved' : 'Lookup Result: failed'}</strong>
            <span>{result.mode} | {result.scan_id}</span>
          </div>
          <p>{result.summary}</p>
          <dl className="network-detail-grid insight-detail-grid">
            <div>
              <dt>Exposure</dt>
              <dd>{formatVulnerabilityBadge(intel ?? undefined)}</dd>
            </div>
            <div>
              <dt>Confidence</dt>
              <dd>{valueOrUnknown(intel?.confidence)}</dd>
            </div>
            <div>
              <dt>Inventory alerts</dt>
              <dd>{result.alerts.length}</dd>
            </div>
            <div>
              <dt>Database</dt>
              <dd>{valueOrUnknown(result.database_file)}</dd>
            </div>
            <div>
              <dt>Selected checks</dt>
              <dd>{selectedPlanChecks.length}</dd>
            </div>
          </dl>
          {result.scan_plan ? (
            <div className="vulnerability-plan-summary">
              <strong>Executed Plan</strong>
              <ul>
                {selectedPlanChecks.map((check) => (
                  <li key={check.id}>
                    <span>{check.label}</span>
                    <small>{formatScanImpact(check.impact)} | {check.network_effect}</small>
                  </li>
                ))}
              </ul>
              {result.scan_plan.operator_note ? (
                <p>
                  {result.scan_plan.operator_note ? `Note: ${result.scan_plan.operator_note}` : ''}
                </p>
              ) : null}
            </div>
          ) : null}
          {result.alerts.length ? (
            <div className="insight-block">
              <strong>Inventory Alerts</strong>
              <ul className="insight-list">
                {result.alerts.map((alert) => (
                  <li key={`${alert.alert_type}-${alert.current_bssid}-${alert.previous_bssid}`}>
                    <strong>{alert.alert_type.replace(/_/g, ' ')}</strong>
                    <span>{alert.severity}</span>
                    <p>{alert.summary}</p>
                    <small>{formatList(alert.evidence)}</small>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
          {intel?.signals.length ? (
            <div className="insight-block">
              <strong>Saved Signals</strong>
              <ul className="insight-list">
                {intel.signals.slice(0, 6).map((signal) => (
                  <li key={signal.id}>
                    <strong>{signal.label}</strong>
                    <span>{signal.severity} | {signal.confidence}</span>
                    <p>{signal.summary}</p>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </div>
      ) : null}
      {planMode ? (
        <VulnerabilityScanPlanModal
          mode={planMode}
          network={network}
          onClose={() => setPlanMode(null)}
          onRun={(options) => {
            setPlanMode(null);
            onRun(planMode, options);
          }}
        />
      ) : null}
    </section>
  );
}

function VulnerabilityScanPlanModal({
  mode,
  network,
  onClose,
  onRun
}: {
  mode: VulnerabilityLookupMode;
  network: WindowsWifiNetwork;
  onClose: () => void;
  onRun: (options: VulnerabilityLookupRunOptions) => void;
}) {
  useBodyScrollLock(true);

  const checks = useMemo(
    () => sortVulnerabilityChecksForMode(mode, VULNERABILITY_SCAN_CHECK_DEFINITIONS.filter((check) => check.modes.includes(mode))),
    [mode]
  );
  const [selectedIds, setSelectedIds] = useState<Set<string>>(
    () => new Set(checks.filter((check) => check.available && check.defaultSelected).map((check) => check.id))
  );
  const [operatorNote, setOperatorNote] = useState('');
  const selectedCount = checks.filter((check) => check.available && selectedIds.has(check.id)).length;
  const safeCheckCount = checks.filter((check) => check.available).length;

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        onClose();
      }
    };

    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [onClose]);

  const toggleCheck = (check: VulnerabilityScanCheckDefinition) => {
    if (!check.available) {
      return;
    }

    setSelectedIds((current) => {
      const next = new Set(current);
      if (next.has(check.id)) {
        next.delete(check.id);
      } else {
        next.add(check.id);
      }
      return next;
    });
  };

  return (
    <ModalPortal>
    <div className="device-modal-backdrop insight-modal-backdrop" role="presentation" onMouseDown={onClose}>
      <section
        className="device-modal vulnerability-plan-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="vulnerability-plan-title"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <div className="insight-modal-heading">
          <div>
            <h2 id="vulnerability-plan-title">Passive Lookup Plan</h2>
            <p>{formatNetworkSsidLabel(network)} | {valueOrUnknown(network.bssid)}</p>
          </div>
          <button type="button" className="device-modal-close" onClick={onClose} aria-label="Close vulnerability lookup plan">
            x
          </button>
        </div>
        <p className="insight-summary">
          Select passive evidence to save from existing telemetry. Passive lookup sends no AP traffic and does not make the client newly visible.
        </p>
        <div className="vulnerability-plan-mode-summary">
          <span><strong>{safeCheckCount}</strong> runnable checks</span>
          <span><strong>{selectedCount}</strong> selected</span>
        </div>
        <div className="vulnerability-plan-table-wrap">
          <table className="vulnerability-plan-table">
            <thead>
              <tr>
                <th>Run</th>
                <th>Check</th>
                <th>Impact</th>
                <th>Network effect</th>
              </tr>
            </thead>
            <tbody>
              {checks.map((check) => (
                <tr
                  key={check.id}
                  className={!check.available ? 'vulnerability-plan-disabled' : ''}
                >
                  <td>
                    <input
                      type="checkbox"
                      checked={check.available && selectedIds.has(check.id)}
                      disabled={!check.available}
                      onChange={() => toggleCheck(check)}
                      aria-label={`Select ${check.label}`}
                    />
                  </td>
                  <td>
                    <strong>{check.label}</strong>
                    <small>{check.description}</small>
                    {check.blockedReason ? <em>{check.blockedReason}</em> : null}
                  </td>
                  <td>
                    <span className={`scan-impact scan-impact-${check.impact}`}>{formatScanImpact(check.impact)}</span>
                  </td>
                  <td>{check.networkEffect}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="vulnerability-plan-fields">
          <label>
            <span>Operator note</span>
            <textarea
              value={operatorNote}
              onChange={(event) => setOperatorNote(event.target.value)}
              placeholder="What you expect to see in AP/router logs"
              rows={3}
            />
          </label>
        </div>
        <div className="vulnerability-plan-actions">
          <button type="button" className="secondary-button" onClick={onClose}>
            Cancel
          </button>
          <button
            type="button"
            className="primary-button"
            onClick={() =>
              {
                onRun({
                  selectedCheckIds: checks.filter((check) => check.available && selectedIds.has(check.id)).map((check) => check.id),
                  operatorNote: operatorNote.trim() || null
                });
              }
            }
            disabled={selectedCount === 0}
          >
            Run {selectedCount} selected
          </button>
        </div>
      </section>
    </div>
    </ModalPortal>
  );
}

function DeviceInsightModal({
  network,
  snapshot,
  profileSecret,
  profileSecretLoading = false,
  profileSecretError = null,
  kind,
  onClose
}: {
  network: WindowsWifiNetwork;
  snapshot?: WindowsWifiSnapshot;
  profileSecret?: WifiProfileSecretResult | null;
  profileSecretLoading?: boolean;
  profileSecretError?: string | null;
  kind: DeviceInsightKind;
  onClose: () => void;
}) {
  useBodyScrollLock(true);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        onClose();
      }
    };

    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [onClose]);

  return (
    <ModalPortal>
    <div className="device-modal-backdrop insight-modal-backdrop" role="presentation" onMouseDown={onClose}>
      <section
        className="device-modal insight-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="insight-modal-title"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <div className="insight-modal-heading">
          <div>
            <h2 id="insight-modal-title">{deviceInsightTitle(kind)}</h2>
            <p>{formatNetworkSsidLabel(network)} | {valueOrUnknown(network.bssid)}</p>
          </div>
          <button type="button" className="device-modal-close" onClick={onClose} aria-label="Close insight">
            x
          </button>
        </div>
        {kind === 'vendor' ? <VendorInsight network={network} /> : null}
        {kind === 'exposure' ? <ExposureInsight network={network} /> : null}
        {kind === 'security' ? (
          <SecurityInsight
            network={network}
            snapshot={snapshot}
            profileSecret={profileSecret}
            profileSecretLoading={profileSecretLoading}
            profileSecretError={profileSecretError}
          />
        ) : null}
        {kind === 'radio' ? <RadioInsight network={network} /> : null}
      </section>
    </div>
    </ModalPortal>
  );
}

function VendorInsight({ network }: { network: WindowsWifiNetwork }) {
  const enrichment = network.mac_enrichment;
  const hint = inferredDeviceHint(network);

  return (
    <>
      <p className="insight-summary">
        Vendor identity is inferred from the local OUI seed and SSID naming hints. It is evidence, not a hardware guarantee.
      </p>
      <dl className="network-detail-grid insight-detail-grid">
        <div>
          <dt>Vendor</dt>
          <dd>{valueOrUnknown(enrichment?.vendor)}</dd>
        </div>
        <div>
          <dt>Device hint</dt>
          <dd>{hint === 'unknown device' ? valueOrUnknown(enrichment?.device_hint) : hint}</dd>
        </div>
        <div>
          <dt>OUI</dt>
          <dd>{valueOrUnknown(enrichment?.oui)}</dd>
        </div>
        <div>
          <dt>MAC scope</dt>
          <dd>{valueOrUnknown(enrichment?.address_scope)}</dd>
        </div>
        <div>
          <dt>Confidence</dt>
          <dd>{valueOrUnknown(enrichment?.confidence)}</dd>
        </div>
        <div>
          <dt>Lookup source</dt>
          <dd>{valueOrUnknown(enrichment?.source)}</dd>
        </div>
      </dl>
      <InsightNotes notes={enrichment?.notes ?? []} emptyLabel="No vendor lookup notes." />
    </>
  );
}

function ExposureInsight({ network }: { network: WindowsWifiNetwork }) {
  const intel = network.vulnerability_intel;

  return (
    <>
      <p className="insight-summary">
        {intel?.summary ?? 'No passive vulnerability exposure signals are available for this AP yet.'}
      </p>
      <dl className="network-detail-grid insight-detail-grid">
        <div>
          <dt>Exposure</dt>
          <dd>{formatVulnerabilityBadge(intel)}</dd>
        </div>
        <div>
          <dt>Confidence</dt>
          <dd>{valueOrUnknown(intel?.confidence)}</dd>
        </div>
        <div>
          <dt>Source</dt>
          <dd>{valueOrUnknown(intel?.source)}</dd>
        </div>
        <div>
          <dt>Device hint</dt>
          <dd>{valueOrUnknown(network.mac_enrichment?.device_hint)}</dd>
        </div>
      </dl>
      {intel?.signals.length ? (
        <div className="insight-block">
          <strong>Signals</strong>
          <ul className="insight-list">
            {intel.signals.map((signal) => (
              <li key={signal.id}>
                <strong>{signal.label}</strong>
                <span>{signal.severity} | {signal.confidence}</span>
                <p>{signal.summary}</p>
                {signal.evidence.length ? <small>{formatList(signal.evidence)}</small> : null}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      <InsightNotes notes={intel?.notes ?? []} emptyLabel="No exposure notes." />
    </>
  );
}

function SecurityInsight({
  network,
  snapshot,
  profileSecret,
  profileSecretLoading = false,
  profileSecretError = null
}: {
  network: WindowsWifiNetwork;
  snapshot?: WindowsWifiSnapshot;
  profileSecret?: WifiProfileSecretResult | null;
  profileSecretLoading?: boolean;
  profileSecretError?: string | null;
}) {
  const assessment = network.security_assessment;
  const attackScenarios = buildSecurityAttackScenarios(network, profileSecret ?? null);
  const defensiveActions = buildSecurityDefensiveActions(network, profileSecret ?? null);
  const passwordRisk =
    profileSecretLoading || (profileSecretError && !profileSecret?.password)
      ? null
      : buildKnownPasswordRisk(network, profileSecret ?? null);

  return (
    <>
      <p className="insight-summary">
        {assessment?.summary ?? 'Security posture is based on Windows scan authentication and cipher metadata.'}
      </p>
      <dl className="network-detail-grid insight-detail-grid">
        <div>
          <dt>Security</dt>
          <dd>{formatNetworkSecurityBadge(network)}</dd>
        </div>
        <div>
          <dt>Posture</dt>
          <dd>{valueOrUnknown(assessment?.posture)}</dd>
        </div>
        <div>
          <dt>Break-in difficulty</dt>
          <dd>{formatAttackDifficulty(assessment?.attack_difficulty)}</dd>
        </div>
        <div>
          <dt>Connection danger</dt>
          <dd>{formatDangerLevel(assessment?.danger_level)}</dd>
        </div>
        <div>
          <dt>WPA3 status</dt>
          <dd>{formatWpa3Status(network)}</dd>
        </div>
        <div>
          <dt>Known password</dt>
          <dd>{formatKnownPasswordStatus(profileSecret ?? null, profileSecretLoading)}</dd>
        </div>
        <div>
          <dt>Authentication</dt>
          <dd>{valueOrUnknown(network.authentication ?? snapshot?.authentication)}</dd>
        </div>
        <div>
          <dt>Encryption</dt>
          <dd>{valueOrUnknown(network.encryption ?? snapshot?.cipher)}</dd>
        </div>
        <div>
          <dt>Band</dt>
          <dd>{valueOrUnknown(network.band ?? snapshot?.band)}</dd>
        </div>
        <div>
          <dt>Channel</dt>
          <dd>{valueOrUnknown(network.channel ?? snapshot?.channel)}</dd>
        </div>
      </dl>
      {profileSecretLoading ? (
        <div className="insight-block security-password-risk security-password-medium">
          <strong>Known Password Risk</strong>
          <p className="insight-summary compact">
            Reading the saved Windows profile password for this AP so the WPA2 risk can be based on the real passphrase.
          </p>
        </div>
      ) : null}
      {!profileSecretLoading && profileSecretError ? (
        <div className="insight-block security-password-risk security-password-medium">
          <strong>Known Password Risk</strong>
          <p className="insight-summary compact">
            Saved password lookup failed: {profileSecretError}
          </p>
        </div>
      ) : null}
      {!profileSecretLoading && passwordRisk ? (
        <div className={`insight-block security-password-risk security-password-${passwordRisk.level}`}>
          <strong>Known Password Risk</strong>
          <p className="insight-summary compact">{passwordRisk.summary}</p>
          <dl className="network-detail-grid insight-detail-grid">
            <div>
              <dt>Password strength</dt>
              <dd>{passwordRisk.strength}</dd>
            </div>
            <div>
              <dt>Break-in difficulty</dt>
              <dd>{passwordRisk.breakInDifficulty}</dd>
            </div>
            <div>
              <dt>SSID-derived</dt>
              <dd>{passwordRisk.ssidDerived}</dd>
            </div>
            <div>
              <dt>Length</dt>
              <dd>{passwordRisk.length}</dd>
            </div>
          </dl>
          {passwordRisk.notes.length ? (
            <ul className="insight-note-list">
              {passwordRisk.notes.map((note) => (
                <li key={note}>{note}</li>
              ))}
            </ul>
          ) : null}
        </div>
      ) : null}
      <div className="insight-block">
        <strong>Attack Paths To Consider</strong>
        <ul className="insight-list">
          {attackScenarios.map((scenario) => (
            <li key={scenario.label}>
              <strong>{scenario.label}</strong>
              <span>{scenario.severity} | {scenario.likelihood}</span>
              <p>{scenario.summary}</p>
              <small>{scenario.evidence}</small>
            </li>
          ))}
        </ul>
      </div>
      <div className="insight-block">
        <strong>Defensive Actions</strong>
        <ul className="insight-note-list">
          {defensiveActions.map((action) => (
            <li key={action}>{action}</li>
          ))}
        </ul>
      </div>
      <InsightNotes notes={assessment?.notes ?? []} emptyLabel="No security notes." />
    </>
  );
}

interface SecurityAttackScenario {
  label: string;
  severity: 'info' | 'low' | 'medium' | 'high';
  likelihood: string;
  summary: string;
  evidence: string;
}

interface KnownPasswordRisk {
  level: 'low' | 'medium' | 'high';
  summary: string;
  strength: string;
  breakInDifficulty: string;
  ssidDerived: string;
  length: string;
  notes: string[];
}

function buildSecurityAttackScenarios(
  network: WindowsWifiNetwork,
  profileSecret: WifiProfileSecretResult | null
): SecurityAttackScenario[] {
  const scenarios: SecurityAttackScenario[] = [];
  const wpa2Personal = isWpa2PersonalNetwork(network);
  const wpa3 = isWpa3Network(network);
  const open = isOpenWifiNetwork(network);
  const enterprise = network.security_assessment?.posture === 'enterprise';
  const passwordRisk = buildKnownPasswordRisk(network, profileSecret);
  const passwordWeak = passwordRisk?.level === 'high' || passwordRisk?.level === 'medium';

  if (open) {
    scenarios.push({
      label: 'Open-network interception risk',
      severity: 'high',
      likelihood: 'no Wi-Fi password',
      summary: 'Anyone nearby can join the network. Traffic still protected by HTTPS remains encrypted, but device discovery and unencrypted protocols are exposed.',
      evidence: 'Windows reports open authentication or no cipher.'
    });
    return scenarios;
  }

  if (wpa2Personal) {
    scenarios.push({
      label: 'Offline password guessing',
      severity: passwordWeak ? 'high' : 'medium',
      likelihood: passwordWeak ? 'easy if the saved password is reused, short, or SSID-derived' : 'depends on passphrase entropy',
      summary: 'WPA2-Personal can be checked against guessed passwords after authentication evidence is captured. The attacker does not need the router password first; the password quality is the defense.',
      evidence: passwordRisk
        ? `Saved profile assessment: ${passwordRisk.strength}, SSID-derived: ${passwordRisk.ssidDerived}.`
        : 'Saved password has not been revealed yet, so exact guessability is unknown.'
    });
    scenarios.push({
      label: 'Network-name targeted guessing',
      severity: passwordRisk?.ssidDerived === 'yes' ? 'high' : 'medium',
      likelihood: passwordRisk?.ssidDerived === 'yes' ? 'high' : 'possible',
      summary: 'Passwords based on the SSID, venue name, address, phone number, or year are much easier to prioritize in targeted guesses.',
      evidence: passwordRisk?.ssidDerived === 'yes'
        ? 'The saved password contains the SSID/network name.'
        : 'No SSID-derived password was confirmed from the current saved profile.'
    });
    scenarios.push({
      label: 'Evil twin credential capture',
      severity: 'medium',
      likelihood: 'requires user interaction',
      summary: 'A fake network with the same name can trick users into entering Wi-Fi or portal credentials. WPA2 itself does not stop phishing-style lookalikes.',
      evidence: 'SSID identity is visible in beacons; user/device behavior determines exposure.'
    });
    scenarios.push({
      label: 'WPS PIN exposure',
      severity: 'medium',
      likelihood: 'unknown from this Windows scan',
      summary: 'If WPS PIN is enabled on the router, it can undermine a good WPA2 password. Windows scan metadata usually does not prove WPS state here.',
      evidence: 'Check router settings directly; disable WPS if present.'
    });
  } else if (wpa3) {
    scenarios.push({
      label: 'Password guessing resistance',
      severity: 'low',
      likelihood: 'reduced by WPA3-SAE',
      summary: 'WPA3-Personal/SAE is designed to resist the classic offline dictionary workflow that affects WPA2-Personal.',
      evidence: 'Windows reports WPA3 authentication metadata.'
    });
    scenarios.push({
      label: 'Transition-mode downgrade risk',
      severity: 'medium',
      likelihood: 'only if WPA2/WPA3 mixed mode is enabled',
      summary: 'Mixed transition mode can leave WPA2 clients exposed to WPA2-style password risk. Pure WPA3 is preferable when all clients support it.',
      evidence: 'This app cannot confirm router transition-mode settings from the current Windows metadata.'
    });
  } else if (enterprise) {
    scenarios.push({
      label: 'Certificate validation mistakes',
      severity: 'medium',
      likelihood: 'configuration-dependent',
      summary: 'Enterprise Wi-Fi is strong when clients validate the server certificate and expected identity. Misconfigured clients can still be phished by lookalike infrastructure.',
      evidence: 'Windows reports enterprise authentication; certificate policy is not visible in the passive scan.'
    });
  } else {
    scenarios.push({
      label: 'Unknown protected-network risk',
      severity: 'medium',
      likelihood: 'metadata incomplete',
      summary: 'Windows did not expose enough security metadata to give a strong claim. Treat it as review-worthy until authentication, cipher, WPS, and password policy are known.',
      evidence: 'Security posture is unknown or only partially inferred.'
    });
  }

  return scenarios;
}

function buildKnownPasswordRisk(
  network: WindowsWifiNetwork,
  profileSecret: WifiProfileSecretResult | null
): KnownPasswordRisk | null {
  if (!profileSecret?.password || !profileSecret.strength) {
    return isWpa2PersonalNetwork(network)
      ? {
          level: 'medium',
          summary: 'Reveal the saved Windows profile password to assess the real WPA2 risk. WPA2-Personal can be strong with a long random passphrase, or easy to guess with a reused/SSID-based one.',
          strength: 'unknown',
          breakInDifficulty: 'unknown',
          ssidDerived: 'unknown',
          length: 'unknown',
          notes: ['The current security score is based on Wi-Fi metadata only, not the actual passphrase.']
        }
      : null;
  }

  const strength = profileSecret.strength;
  const ssidDerived = passwordContainsSsid(profileSecret.password, network.ssid);
  const weakByScore = strength.label === 'weak' || strength.label === 'fair' || strength.break_in_difficulty === 'low';
  const level: KnownPasswordRisk['level'] = ssidDerived || weakByScore ? 'high' : strength.label === 'good' ? 'medium' : 'low';
  const notes = [
    ...strength.notes,
    ssidDerived ? 'Because the passphrase contains the network name, targeted guesses become much easier.' : null,
    isWpa2PersonalNetwork(network) && level === 'high'
      ? 'For WPA2-Personal, this should be treated as easy to guess and rotated.'
      : null
  ].filter((note): note is string => Boolean(note));

  return {
    level,
    summary:
      level === 'high'
        ? 'The saved passphrase looks guessable for a targeted WPA2 attack. Rotate it to a long random value and remove SSID/year/venue words.'
        : level === 'medium'
          ? 'The saved passphrase is not ideal. It may resist casual guesses, but should be improved for WPA2-Personal.'
          : 'The saved passphrase has no obvious local weakness from this check.',
    strength: `${strength.label} | ${strength.score}/100`,
    breakInDifficulty: strength.break_in_difficulty,
    ssidDerived: ssidDerived ? 'yes' : 'no',
    length: valueOrUnknown(strength.length),
    notes
  };
}

function buildSecurityDefensiveActions(
  network: WindowsWifiNetwork,
  profileSecret: WifiProfileSecretResult | null
): string[] {
  const actions: string[] = [];
  const passwordRisk = buildKnownPasswordRisk(network, profileSecret);

  if (isWpa2PersonalNetwork(network)) {
    actions.push('If the AP supports it, switch to WPA3-Personal/SAE; avoid WPA2/WPA3 transition mode once old clients are gone.');
    actions.push('Use a long unique random Wi-Fi passphrase; do not include SSID, venue name, address, phone number, year, or short numeric suffixes.');
    actions.push('Disable WPS PIN/push-button enrollment unless it is explicitly needed.');
  }

  if (passwordRisk?.level === 'high') {
    actions.push('Rotate this Wi-Fi password now and remove the old profile from devices that should no longer connect.');
  } else if (passwordRisk?.level === 'medium') {
    actions.push('Reveal and review the saved password, then rotate it if it is reused, memorable, or based on local words.');
  }

  if (network.security_assessment?.posture === 'enterprise') {
    actions.push('Verify clients validate the expected RADIUS/server certificate and domain before allowing connection.');
  }

  if (isOpenWifiNetwork(network)) {
    actions.push('Treat this as untrusted unless intentionally isolated; use client isolation and application-layer encryption.');
  }

  actions.push('Monitor for repeated reconnects, unexpected BSSID changes, and new lookalike SSIDs, but treat those as signals to verify rather than proof of attack.');

  return actions.filter((action, index, values) => values.indexOf(action) === index);
}

function isWpa2PersonalNetwork(network: WindowsWifiNetwork): boolean {
  const auth = network.authentication?.toLowerCase() ?? '';
  return auth.includes('wpa2') && !auth.includes('enterprise');
}

function isWpa3Network(network: WindowsWifiNetwork): boolean {
  return (network.authentication?.toLowerCase() ?? '').includes('wpa3');
}

function formatWpa3Status(network: WindowsWifiNetwork): string {
  if (isWpa3Network(network)) {
    return 'enabled in scan';
  }

  if (isWpa2PersonalNetwork(network)) {
    return 'not advertised; enable if supported';
  }

  return 'unknown';
}

function formatKnownPasswordStatus(profileSecret: WifiProfileSecretResult | null, loading = false): string {
  if (loading) {
    return 'reading saved profile...';
  }

  if (!profileSecret) {
    return 'not checked';
  }

  if (!profileSecret.password || !profileSecret.strength) {
    return profileSecret.available ? 'not returned by Windows' : 'unavailable';
  }

  return `${profileSecret.strength.label} | ${profileSecret.strength.score}/100`;
}

function passwordContainsSsid(password: string, ssid: string | null): boolean {
  const passwordToken = normalizePasswordToken(password);
  const ssidToken = normalizePasswordToken(ssid ?? '');
  return ssidToken.length >= 4 && passwordToken.includes(ssidToken);
}

function normalizePasswordToken(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]/g, '');
}

function RadioInsight({ network }: { network: WindowsWifiNetwork }) {
  const native = network.native_bss;

  return (
    <>
      <p className="insight-summary">
        Radio evidence comes from passive Windows scan metadata. It helps explain signal, channel pressure and AP capabilities, but it is not monitor mode packet capture.
      </p>
      <dl className="network-detail-grid insight-detail-grid">
        <div>
          <dt>Signal</dt>
          <dd>{formatPercent(network.signal_percent)}</dd>
        </div>
        <div>
          <dt>Native RSSI</dt>
          <dd>{formatRssi(native?.rssi_dbm ?? null)}</dd>
        </div>
        <div>
          <dt>Link quality</dt>
          <dd>{formatPercent(native?.link_quality ?? null)}</dd>
        </div>
        <div>
          <dt>Band / channel</dt>
          <dd>{valueOrUnknown(network.band)} / ch {valueOrUnknown(network.channel)}</dd>
        </div>
        <div>
          <dt>Center frequency</dt>
          <dd>{formatFrequency(native?.center_frequency_khz)}</dd>
        </div>
        <div>
          <dt>Beacon interval</dt>
          <dd>{formatBeaconPeriod(native?.beacon_period_tu)}</dd>
        </div>
        <div>
          <dt>Radio</dt>
          <dd>{valueOrUnknown(network.radio_type)}</dd>
        </div>
        <div>
          <dt>Native PHY</dt>
          <dd>{valueOrUnknown(native?.phy_type)}</dd>
        </div>
        <div>
          <dt>Capability bits</dt>
          <dd>{formatCapability(native?.capability_information)}</dd>
        </div>
        <div>
          <dt>Native rates</dt>
          <dd>{formatNumberList(native?.rates_mbps ?? [], 'Mbps')}</dd>
        </div>
      </dl>
      {native ? (
        <div className="insight-block">
          <strong>Information elements</strong>
          <p className="insight-summary compact">{formatNativeIeSummary(native.information_elements)}</p>
          <dl className="network-detail-grid insight-detail-grid">
            <div>
              <dt>IE names</dt>
              <dd>{formatList(native.information_elements.names)}</dd>
            </div>
            <div>
              <dt>Vendor OUIs</dt>
              <dd>{formatList(native.information_elements.vendor_ouis)}</dd>
            </div>
            <div>
              <dt>Extension IDs</dt>
              <dd>{formatList(native.information_elements.extension_ids)}</dd>
            </div>
            <div>
              <dt>BSS Load IE</dt>
              <dd>{formatBoolean(native.information_elements.has_bss_load)}</dd>
            </div>
          </dl>
        </div>
      ) : (
        <p className="muted compact">Native BSS details are not available for this AP in the current scan.</p>
      )}
    </>
  );
}

function InsightNotes({ notes, emptyLabel }: { notes: string[]; emptyLabel: string }) {
  if (notes.length === 0) {
    return <p className="muted compact">{emptyLabel}</p>;
  }

  return (
    <div className="insight-block">
      <strong>Notes</strong>
      <ul className="insight-note-list">
        {notes.map((note) => (
          <li key={note}>{note}</li>
        ))}
      </ul>
    </div>
  );
}

interface AiUpdateReportRow {
  label: string;
  before: string;
  after: string;
  changed: boolean;
}

function AiUpdateDiffTable({
  title,
  rows,
  emptyLabel
}: {
  title: string;
  rows: AiUpdateReportRow[];
  emptyLabel: string;
}) {
  return (
    <div className="ai-diff-section">
      <strong>{title}</strong>
      {rows.length === 0 ? (
        <p className="muted compact">{emptyLabel}</p>
      ) : (
        <dl className="ai-diff-list">
          {rows.map((row) => (
            <div key={`${title}-${row.label}`}>
              <dt>{row.label}</dt>
              <dd>
                <span>{row.before}</span>
                <b aria-hidden="true">-&gt;</b>
                <span>{row.after}</span>
              </dd>
            </div>
          ))}
        </dl>
      )}
    </div>
  );
}

function buildAiUpdateReportRows(
  network: WindowsWifiNetwork,
  override: DeviceIntelligenceOverride
): AiUpdateReportRow[] {
  const preview = applyDeviceIntelligenceOverrideToNetwork(network, override);
  const rows = [
    reportRow('Match', 'none', `${override.match_type} | ${override.match_value}`),
    reportRow('Vendor', network.mac_enrichment?.vendor, preview.mac_enrichment?.vendor),
    reportRow('Device hint', network.mac_enrichment?.device_hint, preview.mac_enrichment?.device_hint),
    reportRow('Confidence', network.mac_enrichment?.confidence, preview.mac_enrichment?.confidence),
    reportRow('Role', null, override.device_role),
    reportRow('Model', null, override.model),
    reportRow('Mesh', null, formatBoolean(override.is_mesh)),
    reportRow('Exposure', network.vulnerability_intel?.exposure_level, preview.vulnerability_intel?.exposure_level),
    reportRow('Vulnerability summary', network.vulnerability_intel?.summary, preview.vulnerability_intel?.summary),
    reportRow('Source', network.mac_enrichment?.source, preview.mac_enrichment?.source)
  ];

  return rows;
}

function reportRow(
  label: string,
  beforeValue: string | number | null | undefined,
  afterValue: string | number | null | undefined
): AiUpdateReportRow {
  const before = valueOrUnknown(beforeValue);
  const after = valueOrUnknown(afterValue);
  return {
    label,
    before,
    after,
    changed: normalizeReportValue(before) !== normalizeReportValue(after)
  };
}

function normalizeReportValue(value: string): string {
  return value.trim().toLowerCase();
}

function createAiJobId(): string {
  return `device-${Date.now().toString(36)}-${
    globalThis.crypto?.randomUUID?.() ?? Math.random().toString(36).slice(2)
  }`;
}

function formatAiProviderLabel(provider: DeviceIntelligenceUpdateResult['provider'] | null | undefined): string {
  if (provider === 'smart') {
    return 'Smart local update';
  }

  if (provider === 'codex') {
    return 'Codex';
  }

  if (provider === 'claude') {
    return 'Claude';
  }

  return 'AI';
}

function AiResearchModal({
  network,
  onClose,
  onUpdated
}: {
  network: WindowsWifiNetwork;
  onClose: () => void;
  onUpdated: (network: WindowsWifiNetwork, override: DeviceIntelligenceOverride) => void;
}) {
  useBodyScrollLock(true);
  const activeJobIdRef = useRef<string | null>(null);
  const smartAutoRunRef = useRef(false);

  const [runState, setRunState] = useState<{
    provider: DeviceIntelligenceUpdateResult['provider'] | null;
    jobId: string | null;
    startedAtMs: number | null;
    loading: boolean;
    result: DeviceIntelligenceUpdateResult | null;
    error: string | null;
  }>({
    provider: null,
    jobId: null,
    startedAtMs: null,
    loading: false,
    result: null,
    error: null
  });
  const [savedResult, setSavedResult] = useState<DeviceIntelligenceUpdateResult | null>(null);
  const [tickMs, setTickMs] = useState(() => Date.now());

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        onClose();
      }
    };

    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [onClose]);

  useEffect(() => {
    if (!runState.loading) {
      return undefined;
    }

    const timer = window.setInterval(() => setTickMs(Date.now()), 500);
    return () => window.clearInterval(timer);
  }, [runState.loading]);

  const runUpdate = useCallback(async (provider: DeviceIntelligenceUpdateResult['provider']) => {
    if (!window.monitor) {
      setRunState({
        provider,
        jobId: null,
        startedAtMs: null,
        loading: false,
        result: null,
        error: 'AI device update is available inside Electron.'
      });
      return;
    }

    const jobId = createAiJobId();
    activeJobIdRef.current = jobId;
    const startedAtMs = Date.now();
    setTickMs(startedAtMs);
    setRunState({
      provider,
      jobId,
      startedAtMs,
      loading: true,
      result: null,
      error: null
    });

    try {
      const result = await window.monitor.updateDeviceIntelligence({ provider, network, jobId });
      setRunState({
        provider,
        jobId,
        startedAtMs,
        loading: false,
        result,
        error: result.error
      });

      if (activeJobIdRef.current === jobId) {
        activeJobIdRef.current = null;
      }

      if (result.saved && result.override) {
        setSavedResult(result);
        onUpdated(network, result.override);
      }
    } catch (error: unknown) {
      setRunState({
        provider,
        jobId,
        startedAtMs,
        loading: false,
        result: null,
        error: error instanceof Error ? error.message : String(error)
      });
      if (activeJobIdRef.current === jobId) {
        activeJobIdRef.current = null;
      }
    }
  }, [network, onUpdated]);

  useEffect(() => {
    if (smartAutoRunRef.current) {
      return;
    }

    smartAutoRunRef.current = true;
    void runUpdate('smart');
  }, [runUpdate]);

  const cancelUpdate = async () => {
    const jobId = runState.jobId;
    if (!jobId || !window.monitor?.cancelDeviceIntelligenceUpdate) {
      return;
    }

    try {
      await window.monitor.cancelDeviceIntelligenceUpdate({ jobId });
    } catch {
      // The pending update promise will surface the final backend state.
    }
    setRunState((current) => ({
      ...current,
      loading: false,
      error: 'AI update cancellation requested.'
    }));
  };

  const runningProvider = runState.loading ? runState.provider : null;
  const displayedResult = runState.result?.saved && runState.result.override ? runState.result : savedResult;
  const override = displayedResult?.override ?? null;
  const reportRows = override ? buildAiUpdateReportRows(network, override) : [];
  const changedRows = reportRows.filter((row) => row.changed);
  const unchangedRows = reportRows.filter((row) => !row.changed);
  const elapsedMs = runState.startedAtMs === null ? null : Math.max(0, tickMs - runState.startedAtMs);
  const timeoutMs = runState.result?.job.timeout_ms ?? 45_000;
  const remainingMs = elapsedMs === null ? null : Math.max(0, timeoutMs - elapsedMs);
  const rawDetails = runState.result?.raw_output ?? displayedResult?.raw_output ?? null;

  return (
    <ModalPortal>
    <div className="device-modal-backdrop insight-modal-backdrop" role="presentation" onMouseDown={onClose}>
      <section
        className="device-modal ai-research-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="ai-research-title"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <div className="insight-modal-heading">
          <div>
            <h2 id="ai-research-title">AI Device Update</h2>
            <p>{formatNetworkSsidLabel(network)} | {valueOrUnknown(network.bssid)}</p>
          </div>
          <button type="button" className="device-modal-close" onClick={onClose} aria-label="Close AI research">
            x
          </button>
        </div>
        <p className="insight-summary">
          Smart update runs automatically from local telemetry and saved Wi-Fi evidence. Codex and Claude are optional enrich steps; they time out instead of hanging the app.
        </p>
        {runState.loading && runState.provider === 'smart' ? (
          <p className="ai-status ai-status-running">Applying smart local update for this AP...</p>
        ) : null}
        {runState.loading && runState.provider !== 'smart' ? (
          <p className="ai-status ai-status-running">
            Running {formatAiProviderLabel(runState.provider)} for {formatDuration(Math.ceil((elapsedMs ?? 0) / 1000))}; timeout in{' '}
            {formatDuration(Math.ceil((remainingMs ?? timeoutMs) / 1000))}.
          </p>
        ) : null}
        <div className="ai-command-grid">
          <button
            type="button"
            onClick={() => void runUpdate('smart')}
            disabled={runState.loading}
          >
            {runningProvider === 'smart' ? 'Updating...' : savedResult?.provider === 'smart' ? 'Refresh smart update' : 'Run smart update'}
          </button>
          <button
            type="button"
            onClick={() => void runUpdate('codex')}
            disabled={runState.loading}
          >
            {runningProvider === 'codex' ? 'Running Codex...' : 'Run Codex enrich'}
          </button>
          <button
            type="button"
            onClick={() => void runUpdate('claude')}
            disabled={runState.loading}
          >
            {runningProvider === 'claude' ? 'Running Claude...' : 'Run Claude enrich'}
          </button>
          {runState.loading && runState.provider !== 'smart' ? (
            <button type="button" className="ai-cancel-button" onClick={() => void cancelUpdate()}>
              Cancel
            </button>
          ) : null}
        </div>
        {runState.error ? <p className="ai-status ai-status-error">{runState.error}</p> : null}
        {runState.error && savedResult ? (
          <p className="ai-status ai-status-ok">
            Last saved update from {formatAiProviderLabel(savedResult.provider)} is still shown below.
          </p>
        ) : null}
        {runState.result?.saved ? (
          <p className="ai-status ai-status-ok">
            {formatAiProviderLabel(runState.result.provider)} saved device intelligence for this AP only.
          </p>
        ) : null}
        {runState.result && !runState.result.available ? (
          <p className="ai-status ai-status-warn">{runState.result.provider} CLI is not available.</p>
        ) : null}
        {runState.result?.job ? (
          <div className={`ai-job-card ai-job-${runState.result.job.status}`}>
            <strong>Job status</strong>
            <dl className="network-detail-grid insight-detail-grid">
              <div>
                <dt>Status</dt>
                <dd>{runState.result.job.status}</dd>
              </div>
              <div>
                <dt>Provider</dt>
                <dd>{formatAiProviderLabel(runState.result.job.provider)}</dd>
              </div>
              <div>
                <dt>Command</dt>
                <dd>{valueOrUnknown(runState.result.job.command)}</dd>
              </div>
              <div>
                <dt>Duration</dt>
                <dd>{formatDuration(Math.ceil((runState.result.job.duration_ms ?? 0) / 1000))}</dd>
              </div>
            </dl>
            {runState.result.job.stderr_summary ? (
              <p className="ai-result-summary">{runState.result.job.stderr_summary}</p>
            ) : null}
          </div>
        ) : null}
        {override ? (
          <div className="ai-result-card ai-report-card">
            <strong>Update report</strong>
            <p className="ai-result-summary">
              {changedRows.length} changed, {unchangedRows.length} unchanged for this AP.
            </p>
            <AiUpdateDiffTable title="Changed fields" rows={changedRows} emptyLabel="No visible field changed." />
            <AiUpdateDiffTable title="Unchanged fields" rows={unchangedRows} emptyLabel="No unchanged fields." />
          </div>
        ) : null}
        {override ? (
          <div className="ai-result-card">
            <strong>Saved Intelligence</strong>
            <dl className="network-detail-grid insight-detail-grid">
              <div>
                <dt>Match</dt>
                <dd>{override.match_type} | {override.match_value}</dd>
              </div>
              <div>
                <dt>Vendor</dt>
                <dd>{valueOrUnknown(override.vendor)}</dd>
              </div>
              <div>
                <dt>Device hint</dt>
                <dd>{valueOrUnknown(override.device_hint)}</dd>
              </div>
              <div>
                <dt>Role</dt>
                <dd>{valueOrUnknown(override.device_role)}</dd>
              </div>
              <div>
                <dt>Model</dt>
                <dd>{valueOrUnknown(override.model)}</dd>
              </div>
              <div>
                <dt>Confidence</dt>
                <dd>{override.confidence}</dd>
              </div>
              <div>
                <dt>Mesh</dt>
                <dd>{formatBoolean(override.is_mesh)}</dd>
              </div>
              <div>
                <dt>Exposure</dt>
                <dd>{valueOrUnknown(override.exposure_level)}</dd>
              </div>
              <div>
                <dt>Updated</dt>
                <dd>{formatDateTime(override.updated_at_utc)}</dd>
              </div>
            </dl>
            {override.vulnerability_summary ? (
              <p className="ai-result-summary">{override.vulnerability_summary}</p>
            ) : null}
            {override.notes.length ? (
              <ul className="insight-note-list">
                {override.notes.map((note) => (
                  <li key={note}>{note}</li>
                ))}
              </ul>
            ) : null}
          </div>
        ) : null}
        {rawDetails ? (
          <details className="ai-raw-output">
            <summary>Raw update/debug details</summary>
            <pre>{rawDetails}</pre>
          </details>
        ) : null}
      </section>
    </div>
    </ModalPortal>
  );
}

function AiThreatReviewModal({
  request,
  onClose
}: {
  request: AiThreatReviewRequest;
  onClose: () => void;
}) {
  useBodyScrollLock(true);

  const [runState, setRunState] = useState<{
    provider: AiThreatReviewResult['provider'] | null;
    loading: boolean;
    result: AiThreatReviewResult | null;
    error: string | null;
  }>({
    provider: null,
    loading: false,
    result: null,
    error: null
  });

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        onClose();
      }
    };

    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [onClose]);

  const runReview = async (provider: AiThreatReviewResult['provider']) => {
    if (!window.monitor?.runAiThreatReview) {
      setRunState({
        provider,
        loading: false,
        result: null,
        error: 'AI threat review is available inside Electron.'
      });
      return;
    }

    setRunState({
      provider,
      loading: true,
      result: null,
      error: null
    });

    try {
      const result = await window.monitor.runAiThreatReview({
        provider,
        scope: request.scope,
        networks: request.networks,
        snapshot: request.snapshot,
        alerts: request.alerts
      });
      setRunState({
        provider,
        loading: false,
        result,
        error: result.error
      });
    } catch (error: unknown) {
      setRunState({
        provider,
        loading: false,
        result: null,
        error: error instanceof Error ? error.message : String(error)
      });
    }
  };

  const runningProvider = runState.loading ? runState.provider : null;
  const review = runState.result?.review ?? null;

  return (
    <ModalPortal>
    <div className="device-modal-backdrop insight-modal-backdrop" role="presentation" onMouseDown={onClose}>
      <section
        className="device-modal ai-threat-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="ai-threat-title"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <div className="insight-modal-heading">
          <div>
            <h2 id="ai-threat-title">AI Threat Review</h2>
            <p>
              {request.scope === 'map' ? 'Environment map' : 'Detector signals'} | {request.networks.length} APs | {request.alerts.length} alerts
            </p>
          </div>
          <button type="button" className="device-modal-close" onClick={onClose} aria-label="Close AI threat review">
            x
          </button>
        </div>
        <p className="insight-summary">
          Runs defensive cybersecurity triage over Monitor evidence. The prompt asks for exposure paths, confidence, benign causes, safe validation, and remediation.
        </p>
        <div className="ai-command-grid">
          <button type="button" onClick={() => void runReview('codex')} disabled={runState.loading}>
            {runningProvider === 'codex' ? 'Running Codex...' : 'Run Codex cyber review'}
          </button>
          <button type="button" onClick={() => void runReview('claude')} disabled={runState.loading}>
            {runningProvider === 'claude' ? 'Running Claude...' : 'Run Claude review'}
          </button>
        </div>
        {runState.error ? <p className="ai-status ai-status-error">{runState.error}</p> : null}
        {runState.result && !runState.result.available ? (
          <p className="ai-status ai-status-warn">{runState.result.provider} CLI is not available.</p>
        ) : null}
        {review ? (
          <div className={`ai-threat-result ai-threat-${review.verdict}`}>
            <div className="ai-threat-verdict">
              <div>
                <span>Verdict</span>
                <strong>{review.verdict}</strong>
              </div>
              <div>
                <span>Severity</span>
                <strong>{review.severity}</strong>
              </div>
              <div>
                <span>Confidence</span>
                <strong>{review.confidence}</strong>
              </div>
            </div>
            <p className="ai-result-summary">{review.summary}</p>
            <div className="insight-block">
              <strong>Findings</strong>
              <ul className="ai-threat-finding-list">
                {review.findings.map((finding, index) => (
                  <li key={`${finding.label}-${index}`} className={`ai-threat-finding-${finding.severity}`}>
                    <div>
                      <strong>{finding.label}</strong>
                      <span>{finding.severity}</span>
                    </div>
                    <p>{finding.summary}</p>
                    {finding.evidence.length ? <small>{formatList(finding.evidence)}</small> : null}
                  </li>
                ))}
              </ul>
            </div>
            {review.recommended_next_steps.length ? (
              <InsightNotes notes={review.recommended_next_steps} emptyLabel="No recommended passive steps." />
            ) : null}
            {review.false_positive_notes.length ? (
              <div className="insight-block">
                <strong>False-positive notes</strong>
                <ul className="insight-note-list">
                  {review.false_positive_notes.map((note) => (
                    <li key={note}>{note}</li>
                  ))}
                </ul>
              </div>
            ) : null}
          </div>
        ) : null}
        {runState.result?.raw_output ? (
          <details className="ai-raw-output">
            <summary>Raw AI response</summary>
            <pre>{runState.result.raw_output}</pre>
          </details>
        ) : null}
      </section>
    </div>
    </ModalPortal>
  );
}

function NearbyScanStatus({
  networks,
  freshness,
  snapshot,
  connectivity,
  nowMs,
  enabled,
  refreshing,
  clientRefreshing,
  onRefresh,
  onRefreshClient,
  onConnectivityCheck
}: {
  networks: BaselineNetworksResult | null;
  freshness: NetworkFreshnessState;
  snapshot: WindowsWifiSnapshot | null;
  connectivity: ConnectivityCheckState;
  nowMs: number;
  enabled: boolean;
  refreshing: boolean;
  clientRefreshing: boolean;
  onRefresh: () => void;
  onRefreshClient: () => void;
  onConnectivityCheck: () => void;
}) {
  const lastGoodAgeSeconds = secondsSince(freshness.acceptedAtUtc ?? networks?.ts_utc ?? null, nowMs);
  const checkedAgeSeconds = secondsSince(freshness.checkedAtUtc, nowMs);
  const latestScanAgeSeconds = secondsSince(freshness.latestScanAtUtc, nowMs);
  const connectivityAgeSeconds = secondsSince(connectivity.result?.ts_utc ?? null, nowMs);
  const isStale = enabled && lastGoodAgeSeconds !== null && lastGoodAgeSeconds * 1000 >= NETWORK_STALE_MS;
  const isRetained = enabled && freshness.retainedLastGood && networks !== null;
  const hasScanError = enabled && freshness.latestError !== null && networks === null;
  const statusTone = !enabled ? 'off' : hasScanError || isStale ? 'stale' : isRetained ? 'retained' : 'live';
  const statusLabel = !enabled ? 'Off' : hasScanError ? 'No scan' : isStale ? 'Stale' : isRetained ? 'Holding' : 'Live';
  const connectivityTone = connectivity.loading
    ? 'checking'
    : connectivity.result?.status ?? (connectivity.error ? 'offline' : 'unknown');
  const acceptedLabel =
    lastGoodAgeSeconds === null ? 'No accepted AP scan yet' : `Last good ${formatAge(lastGoodAgeSeconds)}`;
  const checkedLabel = checkedAgeSeconds === null ? 'No scan check yet' : `Last check ${formatAge(checkedAgeSeconds)}`;
  const latestScanLabel =
    latestScanAgeSeconds === null
      ? null
      : `Latest scan ${formatAge(latestScanAgeSeconds)} saw ${valueOrUnknown(freshness.latestScanSsidCount)} SSIDs / ${valueOrUnknown(freshness.latestScanBssidCount)} BSSIDs`;
  const latestScanAgeLabel = latestScanAgeSeconds === null ? null : formatAge(latestScanAgeSeconds);
  const retainedLabel =
    isRetained && networks
      ? `Showing last good ${networks.network_count} SSIDs / ${networks.bssid_count} BSSIDs for up to ${formatDuration(Math.floor(NETWORK_LAST_GOOD_HOLD_MS / 1000))}`
      : null;
  const statusTitle = [acceptedLabel, checkedLabel, latestScanLabel, retainedLabel].filter(Boolean).join(' | ');
  const scanButtonTitle = latestScanLabel
    ? `${latestScanLabel}. Click to run a fresh nearby AP scan.`
    : 'Run a fresh nearby AP scan.';

  return (
    <div className={`network-scan-status network-scan-${statusTone}`}>
      <div className="network-scan-main">
        <div className="network-scan-copy">
          <span className={`scan-status-pill scan-status-${statusTone}`} title={statusTitle}>
            {statusLabel}
          </span>
          {freshness.latestError ? <small className="scan-error">{freshness.latestError}</small> : null}
          {freshness.narrowScanCount > 0 ? (
            <small title="Repeated partial AP scans were ignored to avoid replacing a good map with narrow scan data.">
              held {freshness.narrowScanCount}
            </small>
          ) : null}
          <span className="network-live-chip">
            <strong>Client</strong>
            <span>MAC {valueOrUnknown(snapshot?.physical_address ?? null)}</span>
            <span>IPv4 {formatList(snapshot?.ipv4_addresses ?? [])}</span>
            <span>GW {valueOrUnknown(snapshot?.default_gateway ?? null)}</span>
            <span>SSID {valueOrUnknown(snapshot?.ssid ?? null)}</span>
          </span>
          <span className={`network-live-chip internet-check-${connectivityTone}`}>
            <strong>Internet</strong>
            <span>{formatConnectivitySummary(connectivity, connectivityAgeSeconds)}</span>
            {connectivity.result?.public_ip ? <span>Public IP {connectivity.result.public_ip}</span> : null}
            {connectivity.error ? <span className="scan-error">{connectivity.error}</span> : null}
          </span>
        </div>
      </div>
      <div className="network-scan-actions">
        <button
          type="button"
          className="scan-now-button"
          onClick={onRefreshClient}
          disabled={clientRefreshing}
          title="Refresh local client Wi-Fi adapter, IP, gateway, and MAC details"
        >
          {clientRefreshing ? 'Client...' : 'Client'}
        </button>
        <button
          type="button"
          className="scan-now-button"
          onClick={onConnectivityCheck}
          disabled={connectivity.loading}
          title="Manual lightweight Cloudflare connectivity and download check"
        >
          {connectivity.loading ? 'Speed...' : 'Speed'}
        </button>
        <button
          type="button"
          className="scan-now-button"
          onClick={onRefresh}
          disabled={!enabled || refreshing}
          title={scanButtonTitle}
        >
          <span>{refreshing ? 'Scanning' : 'Scan'}</span>
          {latestScanAgeLabel ? <small>{latestScanAgeLabel}</small> : null}
        </button>
      </div>
    </div>
  );
}

function NetworkIntelSummary({
  summary,
  targetHref = '#nearby-ap-list',
  activeFilter = ALL_NETWORK_INTEL_FILTER,
  onFilterChange
}: {
  summary: BaselineNetworksResult['mac_summary'];
  targetHref?: string;
  activeFilter?: NetworkIntelFilter;
  onFilterChange?: (filter: NetworkIntelFilter) => void;
}) {
  const topVendors = summary.vendors.slice(0, onFilterChange ? 5 : 3);
  const topHints = summary.device_hints.slice(0, onFilterChange ? 5 : 3);
  const unknownOuis = summary.unknown_ouis.slice(0, onFilterChange ? 5 : 3);
  const filterable = Boolean(onFilterChange);

  const renderStat = (filter: NetworkIntelFilter, title: string, count: number) => {
    const className = `intel-stat ${
      filterable && isSameNetworkIntelFilter(activeFilter, filter) ? 'intel-filter-active' : ''
    }`;
    const content = (
      <>
        <span>{title}</span>
        <strong>{count}</strong>
      </>
    );

    if (!filterable) {
      return (
        <a href={targetHref} className={className}>
          {content}
        </a>
      );
    }

    return (
      <button type="button" className={className} onClick={() => onFilterChange?.(filter)}>
        {content}
      </button>
    );
  };

  const renderBucket = (
    title: string,
    values: Array<{ value: string; count: number }>,
    kind: Extract<NetworkIntelFilterKind, 'vendor' | 'deviceHint' | 'unknownOui'>
  ) => (
    <div className="intel-bucket">
      <span>{title}</span>
      {filterable ? (
        <div className="intel-chip-list">
          {values.length === 0 ? (
            <strong>none</strong>
          ) : (
            values.map((item) => {
              const filter = buildNetworkIntelBucketFilter(kind, item.value);
              const active = isSameNetworkIntelFilter(activeFilter, filter);
              return (
                <button
                  key={`${kind}:${item.value}`}
                  type="button"
                  className={`intel-chip ${active ? 'intel-filter-active' : ''}`}
                  onClick={() => onFilterChange?.(filter)}
                  title={`Filter Nearby APs by ${filter.label}`}
                >
                  <span>{item.value}</span>
                  <strong>{item.count}</strong>
                </button>
              );
            })
          )}
        </div>
      ) : (
        <strong>{formatBuckets(values)}</strong>
      )}
    </div>
  );

  return (
    <div className={`network-intel-summary ${filterable ? 'network-intel-filterable' : 'network-intel-static'}`}>
      {renderStat({ kind: 'knownVendor', label: 'Known vendors' }, 'Known vendors', summary.known_vendor_count)}
      {renderStat({ kind: 'unknownVendor', label: 'Unknown vendor' }, 'Unknown vendor', summary.unknown_vendor_count)}
      {renderStat({ kind: 'localMac', label: 'Local MAC' }, 'Local MAC', summary.local_mac_count)}
      {renderStat(
        { kind: 'highConfidence', label: 'High confidence' },
        'High confidence',
        summary.confidence_counts.high
      )}
      {renderBucket('Vendors', topVendors, 'vendor')}
      {renderBucket('Device hints', topHints, 'deviceHint')}
      {renderBucket('Unknown OUIs', unknownOuis, 'unknownOui')}
    </div>
  );
}

function uniqueStrings(values: Array<string | null | undefined>): string[] {
  return [...new Set(values.filter((value): value is string => Boolean(value)))].sort((left, right) =>
    left.localeCompare(right)
  );
}

function uniqueNumbers(values: Array<number | null | undefined>): number[] {
  return [...new Set(values.filter((value): value is number => value !== null && value !== undefined && Number.isFinite(value)))]
    .sort((left, right) => left - right);
}

function NetworkList({
  items,
  currentSnapshot,
  source,
  onIntelligenceUpdated,
  onVulnerabilityLookupUpdated,
  onVulnerabilityLookupRecorded
}: {
  items: Array<RememberedNetwork & { ageSeconds: number | null; isStale: boolean }>;
  currentSnapshot: WindowsWifiSnapshot | null;
  source: CollectorSourceStatus | null;
  onIntelligenceUpdated: (network: WindowsWifiNetwork, override: DeviceIntelligenceOverride) => void;
  onVulnerabilityLookupUpdated: (network: WindowsWifiNetwork, result: DeviceVulnerabilityLookupResult) => void;
  onVulnerabilityLookupRecorded: LeakLookupRecordAppender;
}) {
  const [selectedItemKey, setSelectedItemKey] = useState<string | null>(null);
  const [searchText, setSearchText] = useState('');
  const [page, setPage] = useState(1);
  const pageSize = 15;
  const selectedItem = selectedItemKey ? items.find((item) => item.key === selectedItemKey) ?? null : null;

  const query = searchText.trim().toLowerCase();
  const filteredItems = useMemo(() => {
    if (!query) {
      return items;
    }
    return items.filter((item) => {
      const network = item.network;
      const haystack = [
        formatNetworkSsidLabel(network),
        network.ssid,
        network.bssid,
        formatMacHint(network)
      ]
        .filter((value): value is string => Boolean(value))
        .join(' ')
        .toLowerCase();
      return haystack.includes(query);
    });
  }, [items, query]);

  // Reset to the first page whenever the search text or the upstream filtered item set changes.
  useEffect(() => {
    setPage(1);
  }, [query, items]);

  if (!source?.available) {
    return (
      <p className="muted compact">
        Nearby network scan is not available right now.
        {source?.detail ? <span className="detail-block">{source.detail}</span> : null}
      </p>
    );
  }

  if (items.length === 0) {
    return <p className="muted compact">No nearby APs returned by Windows.</p>;
  }

  const totalPages = Math.max(1, Math.ceil(filteredItems.length / pageSize));
  const safePage = Math.min(Math.max(1, page), totalPages);
  const pageItems = filteredItems.slice((safePage - 1) * pageSize, safePage * pageSize);

  return (
    <>
      <div id="nearby-ap-list" className="nearby-table-controls anchor-target">
        <input
          type="search"
          className="nearby-table-search"
          value={searchText}
          onChange={(event) => setSearchText(event.target.value)}
          placeholder="Search SSID, BSSID, or vendor"
          aria-label="Search nearby APs"
        />
        <span className="nearby-table-count">
          {filteredItems.length} of {items.length} shown
        </span>
      </div>
      <div className="nearby-table-wrap">
        <table className="nearby-table">
          <thead>
            <tr>
              <th scope="col">Device</th>
              <th scope="col">SSID</th>
              <th scope="col">BSSID</th>
              <th scope="col">Signal</th>
              <th scope="col">Ch</th>
              <th scope="col">Security</th>
              <th scope="col">Exposure</th>
              <th scope="col">Band / Auth</th>
            </tr>
          </thead>
          <tbody>
            {pageItems.length === 0 ? (
              <tr className="nearby-row-empty">
                <td colSpan={8}>No APs match that search.</td>
              </tr>
            ) : (
              pageItems.map((item) => {
                const network = item.network;
                const visual = networkDeviceVisual(network);
                const isNewDevice = isRememberedNetworkNewInInventory(item);
                const label = formatNetworkSsidLabel(network);

                return (
                  <tr
                    key={item.key}
                    className={`nearby-row ${isNewDevice ? 'nearby-row-new' : ''}`}
                    role="button"
                    tabIndex={0}
                    aria-label={`Open ${label} details`}
                    title={`Open ${label} details`}
                    onClick={() => setSelectedItemKey(item.key)}
                    onKeyDown={(event) => {
                      if (event.key === 'Enter' || event.key === ' ') {
                        event.preventDefault();
                        setSelectedItemKey(item.key);
                      }
                    }}
                  >
                    <td>
                      <span className={`network-visual network-visual-${visual.kind}`} title={visual.alt}>
                        <img src={visual.image} alt={visual.alt} />
                        <small>{visual.label}</small>
                      </span>
                    </td>
                    <td>
                      <strong className="nearby-ssid">{label}</strong>
                      <small className="network-device-hint">{formatMacHint(network)}</small>
                    </td>
                    <td className="nearby-bssid">{valueOrUnknown(network.bssid)}</td>
                    <td>{formatPercent(network.signal_percent)}</td>
                    <td>ch {valueOrUnknown(network.channel)}</td>
                    <td>
                      <span
                        className={`network-security-pill security-risk-${network.security_assessment?.danger_level ?? 'medium'}`}
                        title={network.security_assessment?.summary ?? 'Security posture unknown'}
                      >
                        {formatNetworkSecurityBadge(network)}
                      </span>
                    </td>
                    <td>
                      <span
                        className={`network-vulnerability-pill vulnerability-${network.vulnerability_intel?.exposure_level ?? 'none'}`}
                        title={network.vulnerability_intel?.summary ?? 'No passive exposure signals'}
                      >
                        {formatVulnerabilityBadge(network.vulnerability_intel)}
                      </span>
                    </td>
                    <td className="nearby-bandauth">
                      {valueOrUnknown(network.band)} | {valueOrUnknown(network.authentication)} /{' '}
                      {valueOrUnknown(network.encryption)}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
      {totalPages > 1 ? (
        <div className="nearby-table-pager">
          <button
            type="button"
            className="secondary-button"
            onClick={() => setPage((current) => Math.max(1, current - 1))}
            disabled={safePage <= 1}
          >
            Prev
          </button>
          <span>
            page {safePage} of {totalPages}
          </span>
          <button
            type="button"
            className="secondary-button"
            onClick={() => setPage((current) => Math.min(totalPages, current + 1))}
            disabled={safePage >= totalPages}
          >
            Next
          </button>
        </div>
      ) : null}
      {selectedItem ? (
        <DeviceModal
          item={selectedItem}
          currentSnapshot={currentSnapshot}
          onClose={() => setSelectedItemKey(null)}
          onIntelligenceUpdated={onIntelligenceUpdated}
          onVulnerabilityLookupUpdated={onVulnerabilityLookupUpdated}
          onVulnerabilityLookupRecorded={onVulnerabilityLookupRecorded}
        />
      ) : null}
    </>
  );
}

function NetworkDetails({
  network,
  id,
  onInspect
}: {
  network: WindowsWifiNetwork;
  id: string;
  onInspect?: (kind: DeviceInsightKind) => void;
}) {
  const rawFields = Object.entries(network.raw).filter(
    ([name, value]) => name !== 'BSSID' && value.trim().length > 0
  );

  return (
    <div id={id} className="network-details">
      {onInspect ? (
        <div className="network-detail-actions" aria-label="AP detail actions">
          <span className="network-detail-actions-label">Inspect</span>
          <button type="button" onClick={() => onInspect('vendor')}>Vendor evidence</button>
          <button type="button" onClick={() => onInspect('radio')}>Radio evidence</button>
          <button type="button" onClick={() => onInspect('security')}>Security</button>
          <button type="button" onClick={() => onInspect('exposure')}>Exposure</button>
        </div>
      ) : null}
      <dl className="network-detail-grid">
        <DetailFact label="Device hint" value={valueOrUnknown(network.mac_enrichment?.device_hint)} kind="vendor" onInspect={onInspect} />
        <DetailFact label="Vendor" value={valueOrUnknown(network.mac_enrichment?.vendor)} kind="vendor" onInspect={onInspect} />
        <DetailFact label="OUI" value={valueOrUnknown(network.mac_enrichment?.oui)} kind="vendor" onInspect={onInspect} />
        <DetailFact label="MAC scope" value={valueOrUnknown(network.mac_enrichment?.address_scope)} kind="vendor" onInspect={onInspect} />
        <DetailFact label="Confidence" value={valueOrUnknown(network.mac_enrichment?.confidence)} kind="vendor" onInspect={onInspect} />
        <DetailFact label="Lookup source" value={valueOrUnknown(network.mac_enrichment?.source)} kind="vendor" onInspect={onInspect} />
        <DetailFact label="Native RSSI" value={formatRssi(network.native_bss?.rssi_dbm ?? null)} kind="radio" onInspect={onInspect} />
        <DetailFact label="Link quality" value={formatPercent(network.native_bss?.link_quality ?? null)} kind="radio" onInspect={onInspect} />
        <DetailFact label="Center frequency" value={formatFrequency(network.native_bss?.center_frequency_khz)} kind="radio" onInspect={onInspect} />
        <DetailFact label="Beacon interval" value={formatBeaconPeriod(network.native_bss?.beacon_period_tu)} kind="radio" onInspect={onInspect} />
        <DetailFact label="Native PHY" value={valueOrUnknown(network.native_bss?.phy_type)} kind="radio" onInspect={onInspect} />
        <DetailFact label="Capability bits" value={formatCapability(network.native_bss?.capability_information)} kind="radio" onInspect={onInspect} />
        <DetailFact label="Security posture" value={valueOrUnknown(network.security_assessment?.label)} kind="security" onInspect={onInspect} />
        <DetailFact label="Break-in difficulty" value={formatAttackDifficulty(network.security_assessment?.attack_difficulty)} kind="security" onInspect={onInspect} />
        <DetailFact label="Connection danger" value={formatDangerLevel(network.security_assessment?.danger_level)} kind="security" onInspect={onInspect} />
        <DetailFact label="Vulnerability exposure" value={formatVulnerabilityBadge(network.vulnerability_intel)} kind="exposure" onInspect={onInspect} />
        <DetailFact label="Exposure confidence" value={valueOrUnknown(network.vulnerability_intel?.confidence)} kind="exposure" onInspect={onInspect} />
        <DetailFact label="Interface" value={valueOrUnknown(network.interface_name)} kind="radio" onInspect={onInspect} />
        <DetailFact label="Network type" value={valueOrUnknown(network.network_type)} kind="radio" onInspect={onInspect} />
        <DetailFact label="Radio" value={valueOrUnknown(network.radio_type)} kind="radio" onInspect={onInspect} />
        <DetailFact label="Band" value={valueOrUnknown(network.band)} kind="radio" onInspect={onInspect} />
        <DetailFact label="Channel" value={valueOrUnknown(network.channel)} kind="radio" onInspect={onInspect} />
        <DetailFact label="Signal" value={formatPercent(network.signal_percent)} kind="radio" onInspect={onInspect} />
        <DetailFact label="Security" value={`${valueOrUnknown(network.authentication)} / ${valueOrUnknown(network.encryption)}`} kind="security" onInspect={onInspect} />
        <DetailFact label="Basic rates" value={formatNumberList(network.basic_rates_mbps, 'Mbps')} kind="radio" onInspect={onInspect} />
        <DetailFact label="Other rates" value={formatNumberList(network.other_rates_mbps, 'Mbps')} kind="radio" onInspect={onInspect} />
        <DetailFact label="Seen at" value={formatDateTime(network.ts_utc)} />
      </dl>
      {network.mac_enrichment?.notes.length ? (
        <div className="network-intel-notes">
          <DetailSectionTitle
            label="MAC intelligence notes"
            kind="vendor"
            onInspect={onInspect}
          />
          <ul>
            {network.mac_enrichment.notes.map((note) => (
              <li key={note}>{note}</li>
            ))}
          </ul>
        </div>
      ) : null}
      {network.security_assessment ? (
        <div className={`network-security-notes security-note-${network.security_assessment.danger_level}`}>
          <DetailSectionTitle
            label={network.security_assessment.summary}
            kind="security"
            onInspect={onInspect}
          />
          <ul>
            {network.security_assessment.notes.map((note) => (
              <li key={note}>{note}</li>
            ))}
          </ul>
        </div>
      ) : null}
      {network.vulnerability_intel ? (
        <div className={`network-vulnerability-notes vulnerability-note-${network.vulnerability_intel.exposure_level}`}>
          <DetailSectionTitle
            label={network.vulnerability_intel.summary}
            kind="exposure"
            onInspect={onInspect}
          />
          {network.vulnerability_intel.signals.length ? (
            <ul>
              {network.vulnerability_intel.signals.map((signal) => (
                <li key={signal.id}>
                  <b>{signal.label}</b>: {signal.summary}
                  {signal.evidence.length ? <span> Evidence: {signal.evidence.join('; ')}.</span> : null}
                </li>
              ))}
            </ul>
          ) : null}
          <p>{network.vulnerability_intel.notes.join(' ')}</p>
        </div>
      ) : null}
      {network.native_bss ? (
        <div className="network-native-bss">
          <DetailSectionTitle
            label="Native BSS evidence"
            kind="radio"
            onInspect={onInspect}
          />
          <dl>
            <div>
              <dt>Information elements</dt>
              <dd>{formatNativeIeSummary(network.native_bss.information_elements)}</dd>
            </div>
            <div>
              <dt>Vendor OUIs</dt>
              <dd>{formatList(network.native_bss.information_elements.vendor_ouis)}</dd>
            </div>
            <div>
              <dt>Extension IDs</dt>
              <dd>{formatList(network.native_bss.information_elements.extension_ids)}</dd>
            </div>
            <div>
              <dt>Native rates</dt>
              <dd>{formatNumberList(network.native_bss.rates_mbps, 'Mbps')}</dd>
            </div>
            <div>
              <dt>In reg domain</dt>
              <dd>{formatBoolean(network.native_bss.in_reg_domain)}</dd>
            </div>
            <div>
              <dt>Host timestamp</dt>
              <dd>{valueOrUnknown(network.native_bss.host_timestamp)}</dd>
            </div>
          </dl>
        </div>
      ) : null}
      {rawFields.length > 0 ? (
        <div className="network-raw-fields">
          <DetailSectionTitle
            label="Raw netsh fields"
            kind="radio"
            onInspect={onInspect}
          />
          <dl>
            {rawFields.map(([name, value]) => (
              <div key={name}>
                <dt>{name}</dt>
                <dd>{value}</dd>
              </div>
            ))}
          </dl>
        </div>
      ) : null}
    </div>
  );
}

function DetailFact({
  label,
  value,
  kind,
  onInspect
}: {
  label: string;
  value: string | number;
  kind?: DeviceInsightKind;
  onInspect?: (kind: DeviceInsightKind) => void;
}) {
  const valueLabel = valueOrUnknown(value);
  const canInspect = Boolean(kind && onInspect);
  return (
    <div>
      <dt>{label}</dt>
      <dd className={canInspect ? 'detail-fact-actions' : undefined}>
        {canInspect && kind ? (
          <button
            type="button"
            className="detail-fact-button"
            title={`Open ${deviceInsightTitle(kind)} for ${label}`}
            onClick={() => onInspect?.(kind)}
          >
            {valueLabel}
          </button>
        ) : (
          <span>{valueLabel}</span>
        )}
      </dd>
    </div>
  );
}

function DetailSectionTitle({
  label,
  kind,
  onInspect
}: {
  label: string;
  kind: DeviceInsightKind;
  onInspect?: (kind: DeviceInsightKind) => void;
}) {
  if (!onInspect) {
    return <strong>{label}</strong>;
  }

  return (
    <div className="detail-section-title">
      {onInspect ? (
        <button
          type="button"
          className="detail-section-button"
          title={`Open ${deviceInsightTitle(kind)}`}
          onClick={() => onInspect(kind)}
        >
          <span>{label}</span>
          <small aria-hidden="true">+</small>
        </button>
      ) : (
        <strong>{label}</strong>
      )}
    </div>
  );
}

function SourcesPanel({
  sources,
  controls,
  onToggle
}: {
  sources: CollectorSourceStatus[];
  controls: SourceControls;
  onToggle: (key: SourceControlKey, enabled: boolean) => void;
}) {
  const sourceByName = new Map(sources.map((source) => [source.name, source]));
  const enabledLiveSources = Number(controls.wlanEvents) + Number(controls.nearbyAps) + 1;

  return (
    <>
      <div className="panel-heading">
        <h2>Sources</h2>
        <span>{enabledLiveSources}/3 live</span>
      </div>
      <ul className="source-list">
        {SOURCE_DESCRIPTORS.map((descriptor) => {
          const primaryStatuses = descriptor.sourceNames
            .map((name) => sourceByName.get(name))
            .filter(isCollectorSourceStatus);
          const optionalStatuses = (descriptor.optionalSourceNames ?? [])
            .map((name) => sourceByName.get(name))
            .filter(isCollectorSourceStatus);
          const enabled = sourceDescriptorEnabled(descriptor, controls);
          const reported = primaryStatuses.length > 0;
          const available = reported && primaryStatuses.every((source) => source.available);
          // Not yet reported = still checking (initial load); a reported-but-unavailable source stays "down".
          const stateText = !enabled ? 'off' : !reported ? 'checking' : available ? 'available' : 'down';
          const toggleKey = descriptor.key === 'wifiStatus' ? null : descriptor.key;

          return (
            <li key={descriptor.key} className={!enabled ? 'source-disabled' : undefined}>
              <div className="source-copy">
                <span>{descriptor.title}</span>
                <small>{descriptor.role}</small>
                <code>{descriptor.command}</code>
                <SourceDetails sources={[...primaryStatuses, ...optionalStatuses]} />
              </div>
              <div className="source-actions">
                <strong className={`source-state source-state-${stateText}`}>{stateText}</strong>
                {toggleKey === null ? (
                  <span className="source-fixed">required</span>
                ) : (
                  <label className="source-toggle">
                    <input
                      type="checkbox"
                      checked={enabled}
                      onChange={(event) => onToggle(toggleKey, event.currentTarget.checked)}
                    />
                    <span>{enabled ? 'on' : 'off'}</span>
                  </label>
                )}
              </div>
            </li>
          );
        })}
      </ul>
    </>
  );
}

function SourceDetails({ sources }: { sources: CollectorSourceStatus[] }) {
  const detailedSources = sources.filter((source) => source.detail);

  if (detailedSources.length === 0) {
    return null;
  }

  return (
    <dl className="source-details">
      {detailedSources.map((source) => (
        <div key={source.name}>
          <dt>{formatSourceName(source.name)}</dt>
          <dd>{source.detail}</dd>
        </div>
      ))}
    </dl>
  );
}

function DiagnosticsBundleList({ bundles }: { bundles: BaselineDiagnosticsBundleRecord[] }) {
  if (bundles.length === 0) {
    return <p className="muted compact">No diagnostics bundles found yet.</p>;
  }

  return (
    <ol className="diagnostics-list">
      {bundles.map((bundle) => (
        <li key={bundle.bundle_id}>
          <div className="diagnostics-item-heading">
            <strong>{bundle.bundle_id}</strong>
            <span className={`run-status run-status-${bundle.status}`}>{bundle.status}</span>
          </div>
          <dl>
            <dt>Created</dt>
            <dd>{formatDateTime(bundle.created_at_utc)}</dd>
            <dt>Counts</dt>
            <dd>{formatDiagnosticsCounts(bundle)}</dd>
            <dt>Path</dt>
            <dd>{bundle.out_dir}</dd>
          </dl>
          {bundle.error ? <span className="run-error">{bundle.error}</span> : null}
        </li>
      ))}
    </ol>
  );
}

function RunList({
  runs,
  selectedRunId,
  onSelectRun
}: {
  runs: BaselineRunRecord[];
  selectedRunId: string | null;
  onSelectRun: (runId: string) => void;
}) {
  if (runs.length === 0) {
    return <p className="muted compact">No saved baseline runs found yet.</p>;
  }

  return (
    <ol className="run-list">
      {runs.map((run) => (
        <li key={run.run_id}>
          <button
            type="button"
            className={`run-card-button ${selectedRunId === run.run_id ? 'selected' : ''}`}
            disabled={run.status !== 'complete'}
            onClick={() => onSelectRun(run.run_id)}
          >
            <span className="run-title">
              <strong title={run.run_id}>{formatRunLabel(run)}</strong>
              <span className={`run-status run-status-${formatRunState(run)}`}>{formatRunState(run)}</span>
            </span>
            <dl>
              <dt>Run ID</dt>
              <dd>{run.run_id}</dd>
              <dt>Started</dt>
              <dd>{formatDateTime(run.started_at_utc)}</dd>
              <dt>Storage</dt>
              <dd>{formatRunStorage(run)}</dd>
              <dt>Duration</dt>
              <dd>{formatDuration(run.duration_seconds)}</dd>
              <dt>Events</dt>
              <dd>
                {valueOrUnknown(run.event_count)} total, {valueOrUnknown(run.wlan_event_count)} WLAN
              </dd>
              <dt>Snapshots</dt>
              <dd>{valueOrUnknown(run.snapshot_count)}</dd>
              <dt>APs</dt>
              <dd>
                {valueOrUnknown(run.network_bssid_count)} BSSID, {valueOrUnknown(run.network_scan_count)} scans
              </dd>
            </dl>
            {run.error ? <span className="run-error">{run.error}</span> : null}
          </button>
        </li>
      ))}
    </ol>
  );
}

function RunAnalysis({
  analysis,
  loading,
  error
}: {
  analysis: BaselineRunAnalysisResult | null;
  loading: boolean;
  error: string | null;
}) {
  if (loading) {
    return <p className="muted compact">Reading saved run evidence...</p>;
  }

  if (error) {
    return <p className="error compact">{error}</p>;
  }

  if (!analysis) {
    return <p className="muted compact">Select a complete saved run to analyze it.</p>;
  }

  const recentSavedTimeline = [...analysis.timeline].reverse().slice(0, 5);

  return (
    <>
      <ReportCard report={analysis.report} />
      <div className="analysis-layout">
      <section id="run-snapshot-summary" className="anchor-target">
        <h3>Snapshot Summary</h3>
        <dl className="analysis-facts">
          <dt>Duration</dt>
          <dd>{formatDuration(analysis.duration_seconds)}</dd>
          <dt>Parsed events</dt>
          <dd>{analysis.parsed_event_count}</dd>
          <dt>Invalid records</dt>
          <dd>{analysis.invalid_line_count}</dd>
          <dt>Snapshots</dt>
          <dd>{analysis.snapshots.count}</dd>
          <dt>State</dt>
          <dd>{formatCounts(analysis.snapshots.states)}</dd>
          <dt>SSID</dt>
          <dd>{formatList(analysis.snapshots.ssids)}</dd>
          <dt>BSSID</dt>
          <dd>{formatList(analysis.snapshots.bssids)}</dd>
          <dt>Channel</dt>
          <dd>{formatList(analysis.snapshots.channels)}</dd>
          <dt>RSSI</dt>
          <dd>{formatNumericSummary(analysis.snapshots.rssi_dbm, 'dBm')}</dd>
          <dt>Signal</dt>
          <dd>{formatNumericSummary(analysis.snapshots.signal_percent, '%')}</dd>
          <dt>Nearby</dt>
          <dd>
            {analysis.networks.ssid_count} SSIDs / {analysis.networks.count} BSSIDs
          </dd>
          <dt>AP channels</dt>
          <dd>{formatList(analysis.networks.channels)}</dd>
        </dl>
        <div id="run-network-intel" className="analysis-subsection anchor-target">
          <h3>MAC Intelligence</h3>
          <NetworkIntelSummary summary={analysis.networks.mac_summary} targetHref="#run-network-intel" />
        </div>
      </section>

      <section>
        <h3>Saved Detector Output</h3>
        <div className="analysis-metrics">
          <Metric
            label="WLAN"
            value={analysis.wlan_event_count}
            href="#run-event-types"
            title="Jump to saved WLAN event type counts"
          />
          <Metric
            label="APs"
            value={analysis.networks.count}
            href="#run-snapshot-summary"
            title="Jump to nearby AP and snapshot summary"
          />
          <Metric
            label="Timeline"
            value={analysis.timeline_count}
            href="#run-saved-timeline"
            title="Jump to lifecycle events saved in this run"
          />
          <Metric
            label="Observ."
            value={analysis.observation_count}
            tone={analysis.observation_count > 0 ? 'warn' : 'ok'}
            href="#run-observations"
            title="Jump to run observations"
          />
          <Metric
            label="Alerts"
            value={analysis.alert_count}
            tone={analysis.alert_count > 0 ? 'warn' : 'ok'}
            href="#run-alerts"
            title="Jump to detector alerts"
          />
        </div>
        {analysis.collector_errors.length > 0 ? (
          <p className="error compact">{analysis.collector_errors.length} collector errors in this run.</p>
        ) : (
          <p className="muted compact">No collector loop errors in this run.</p>
        )}
        <div id="run-observations" className="analysis-subsection anchor-target">
          <h3>Observations</h3>
          <ObservationList observations={analysis.observations} />
        </div>
        <div id="run-alerts" className="analysis-subsection anchor-target">
          <h3>Alerts</h3>
          <AlertList alerts={analysis.alerts} />
        </div>
      </section>

      <section>
        <div id="run-event-types" className="analysis-subsection anchor-target">
          <h3>Event Types</h3>
          <dl className="analysis-facts compact-facts">
            {Object.entries(analysis.event_type_counts).map(([name, count]) => (
              <div key={name}>
                <dt>{name}</dt>
                <dd>{count}</dd>
              </div>
            ))}
          </dl>
        </div>
        <div id="run-saved-timeline" className="analysis-subsection anchor-target">
          <h3>Saved Timeline</h3>
          <TimelineList events={recentSavedTimeline} />
        </div>
      </section>
      </div>
    </>
  );
}

function ReportCard({ report }: { report: BaselineRunEvidenceReport }) {
  return (
    <section className="report-card">
      <div className="report-heading">
        <div>
          <h3>Evidence Report</h3>
          <p>{report.summary}</p>
        </div>
        <div className={`report-verdict report-verdict-${report.verdict}`}>
          <strong>{report.verdict}</strong>
          <span>{report.confidence} confidence | score {report.score}</span>
        </div>
      </div>
      <div className="report-grid">
        <div>
          <h3>Evidence</h3>
          <ul className="report-list">
            {report.evidence.slice(0, 5).map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </div>
        <div>
          <h3>Limitations</h3>
          <ul className="report-list">
            {report.limitations.slice(0, 4).map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </div>
      </div>
    </section>
  );
}

function Metric({
  label,
  value,
  tone = 'neutral',
  href,
  title
}: {
  label: string;
  value: number;
  tone?: 'neutral' | 'ok' | 'warn';
  href?: string;
  title?: string;
}) {
  const content = (
    <>
      <span>{label}</span>
      <strong>{value}</strong>
    </>
  );
  const className = `metric metric-${tone} ${href ? 'metric-link' : ''}`;

  return href ? (
    <a className={className} href={href} title={title} aria-label={title ?? `${label}: ${value}`}>
      {content}
    </a>
  ) : (
    <div className={className} title={title}>{content}</div>
  );
}

function OverviewKpi({
  label,
  value,
  detail,
  tone = 'neutral',
  onActivate,
  activateHint
}: {
  label: string;
  value: string | number;
  detail: string;
  tone?: 'neutral' | 'ok' | 'warn' | 'danger';
  onActivate?: () => void;
  activateHint?: string;
}) {
  const className = `overview-kpi overview-kpi-${tone}${onActivate ? ' overview-kpi-button' : ''}`;
  const body = (
    <>
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{detail}</small>
    </>
  );

  if (onActivate) {
    return (
      <button type="button" className={className} onClick={onActivate} title={activateHint}>
        {body}
      </button>
    );
  }

  return <div className={className}>{body}</div>;
}

function ConnectionBadges({
  snapshot,
  network,
  onInspect
}: {
  snapshot: WindowsWifiSnapshot;
  network: WindowsWifiNetwork | null;
  onInspect?: (kind: DeviceInsightKind) => void;
}) {
  const vendor = formatShortVendor(network?.mac_enrichment?.vendor);
  const exposure = formatVulnerabilityBadge(network?.vulnerability_intel);
  const security = network?.security_assessment
    ? formatDangerLevel(network.security_assessment.danger_level)
    : formatSecurity(snapshot.authentication, snapshot.cipher);
  const renderBadge = (kind: DeviceInsightKind, label: string, value: string, className = '') => {
    const content = (
      <>
        <b>{label}</b>
        {value}
      </>
    );

    if (!onInspect) {
      return <span className={`connection-badge ${className}`}>{content}</span>;
    }

    return (
      <button
        type="button"
        className={`connection-badge connection-badge-button ${className}`}
        title={`Open ${label.toLowerCase()} details`}
        onClick={() => onInspect(kind)}
      >
        {content}
      </button>
    );
  };

  return (
    <div className="connection-badges" aria-label="Current connection summary">
      {renderBadge('vendor', 'Vendor', vendor)}
      {renderBadge('exposure', 'Exposure', exposure, `connection-exposure-${network?.vulnerability_intel?.exposure_level ?? 'unknown'}`)}
      {renderBadge('security', 'Security', security, `connection-security-${network?.security_assessment?.danger_level ?? 'unknown'}`)}
    </div>
  );
}

function SignalMeter({ signalPercent }: { signalPercent: number | null }) {
  const signal = signalPercent === null ? 0 : Math.min(100, Math.max(0, signalPercent));

  return (
    <div className="signal-meter" aria-label="Signal strength">
      <span style={{ width: `${signal}%` }} />
    </div>
  );
}

function NetworkHistoryScrubber({
  history,
  selectedId,
  onSelect,
  onLive,
  liveStatus
}: {
  history: NetworkHistorySnapshot[];
  selectedId: string | null;
  onSelect: (id: string | null) => void;
  onLive: () => void;
  liveStatus?: ReactNode;
}) {
  const maxIndex = Math.max(0, history.length - 1);
  const selectedIndex = selectedId ? history.findIndex((snapshot) => snapshot.id === selectedId) : -1;
  const sliderIndex = selectedIndex >= 0 ? selectedIndex : maxIndex;
  const activeSnapshot = selectedIndex >= 0 ? history[selectedIndex] : null;
  const disabled = history.length === 0;

  return (
    <section className={`history-scrubber-shell ${activeSnapshot ? 'history-scrubber-paused' : ''}`}>
      <div className="history-scrubber">
        <div className="history-scrubber-copy">
          <span>{activeSnapshot ? 'History View' : 'Live View'}</span>
          <strong>
            {activeSnapshot
              ? `${formatDateTime(activeSnapshot.tsUtc)} | ${activeSnapshot.ssidCount} SSIDs / ${activeSnapshot.bssidCount} BSSIDs`
              : history.length > 0
                ? `Live | ${history.length} snapshots buffered`
                : 'Live | waiting for scans'}
          </strong>
        </div>
        <div className="history-slider-wrap">
          <small>{history[0] ? formatTimeOnly(history[0].tsUtc) : '--:--'}</small>
          <input
            type="range"
            min={0}
            max={maxIndex}
            step={1}
            value={sliderIndex}
            disabled={disabled}
            aria-label="Nearby AP history position"
            onChange={(event) => {
              const nextSnapshot = history[Number(event.target.value)];
              onSelect(nextSnapshot?.id ?? null);
            }}
          />
          <small>{history[maxIndex] ? formatTimeOnly(history[maxIndex].tsUtc) : '--:--'}</small>
        </div>
        <button type="button" className="scan-now-button" onClick={onLive} disabled={!activeSnapshot}>
          Live
        </button>
      </div>
      {liveStatus ? <div className="history-live-status">{liveStatus}</div> : null}
    </section>
  );
}

function HistorySnapshotStatus({
  snapshot,
  onLive
}: {
  snapshot: NetworkHistorySnapshot;
  onLive: () => void;
}) {
  return (
    <div className="network-scan-status network-scan-retained history-snapshot-status">
      <div className="network-scan-copy">
        <span className="scan-status-pill scan-status-retained">History</span>
        <small>Viewing {formatDateTime(snapshot.tsUtc)}</small>
        <small>{snapshot.ssidCount} SSIDs / {snapshot.bssidCount} BSSIDs</small>
        <small>{snapshot.liveCount} live then</small>
        <small>strongest {formatPercent(snapshot.strongestSignal)}</small>
      </div>
      <button type="button" className="scan-now-button" onClick={onLive}>
        Back live
      </button>
    </div>
  );
}

function ObservationList({ observations }: { observations: BaselineRunObservation[] }) {
  const shownObservations = useMemo(() => observations.slice(0, 6), [observations]);
  const [expandedObservationKey, setExpandedObservationKey] = useState<string | null>(null);

  useEffect(() => {
    if (
      expandedObservationKey &&
      !shownObservations.some((observation, index) => observationKey(observation, index) === expandedObservationKey)
    ) {
      setExpandedObservationKey(null);
    }
  }, [expandedObservationKey, shownObservations]);

  if (observations.length === 0) {
    return <p className="muted compact">No saved run observations.</p>;
  }

  return (
    <ol className="observation-list">
      {shownObservations.map((observation, index) => {
        const key = observationKey(observation, index);
        const isExpanded = expandedObservationKey === key;

        return (
          <li key={key} className={isExpanded ? 'observation-item-expanded' : undefined}>
            <button
              type="button"
              className={`observation-row observation-risk-${observation.severity}`}
              aria-expanded={isExpanded}
              aria-controls={`observation-details-${toDomId(key)}`}
              onClick={() => setExpandedObservationKey(isExpanded ? null : key)}
            >
              <span className="observation-summary">
                <span className="alert-line">
                  <strong>{formatObservationTitle(observation.observation_type)}</strong>
                  <span className="observation-flags">
                    <span className={`severity severity-${observation.severity}`}>
                      {formatObservationRiskLabel(observation.severity)}
                    </span>
                    <span
                      className="observation-help-mark"
                      title={formatObservationReason(observation)}
                      aria-label="Detector rationale"
                    >
                      ?
                    </span>
                  </span>
                </span>
                <p>{observation.summary}</p>
                <small>
                  {formatDateTime(observation.ts_utc)} | {valueOrUnknown(observation.ssid)} |{' '}
                  {valueOrUnknown(observation.bssid)} | ch {valueOrUnknown(observation.channel)} |{' '}
                  {formatObservationSignal(observation)}
                </small>
              </span>
              <span className="activity-toggle-mark" aria-hidden="true">
                {isExpanded ? '-' : '+'}
              </span>
            </button>
            {isExpanded ? (
              <ObservationDetails observation={observation} id={`observation-details-${toDomId(key)}`} />
            ) : null}
          </li>
        );
      })}
    </ol>
  );
}

function ObservationDetails({ observation, id }: { observation: BaselineRunObservation; id: string }) {
  return (
    <div id={id} className="activity-details observation-details">
      <div className={`observation-rationale observation-rationale-${observation.severity}`}>
        <strong>Why flagged</strong>
        <p>{formatObservationReason(observation)}</p>
      </div>
      <dl className="activity-detail-grid">
        <div>
          <dt>Observation</dt>
          <dd>{formatObservationTitle(observation.observation_type)}</dd>
        </div>
        <div>
          <dt>Code</dt>
          <dd>{observation.observation_type}</dd>
        </div>
        <div>
          <dt>Severity</dt>
          <dd>{observation.severity}</dd>
        </div>
        <div>
          <dt>Score</dt>
          <dd>{observation.score}</dd>
        </div>
        <div>
          <dt>SSID</dt>
          <dd>{valueOrUnknown(observation.ssid)}</dd>
        </div>
        <div>
          <dt>BSSID</dt>
          <dd>{valueOrUnknown(observation.bssid)}</dd>
        </div>
        <div>
          <dt>Channel</dt>
          <dd>{valueOrUnknown(observation.channel)}</dd>
        </div>
        <div>
          <dt>Signal</dt>
          <dd>{formatObservationSignal(observation)}</dd>
        </div>
        <div>
          <dt>Previous</dt>
          <dd>{valueOrUnknown(observation.previous_value)}</dd>
        </div>
        <div>
          <dt>Current</dt>
          <dd>{valueOrUnknown(observation.current_value)}</dd>
        </div>
        <div>
          <dt>Interface</dt>
          <dd>{valueOrUnknown(observation.interface_name)}</dd>
        </div>
        <div>
          <dt>Observed</dt>
          <dd>{formatDateTime(observation.ts_utc)}</dd>
        </div>
      </dl>
      <p className="activity-detail-note">{observation.summary}</p>
      <div className="activity-message-fields">
        <strong>Evidence IDs</strong>
        <p className="observation-detail-text">{formatList(observation.evidence_event_ids)}</p>
      </div>
      {observation.false_positive_notes.length > 0 ? (
        <div className="activity-message-fields">
          <strong>False-positive notes</strong>
          <ul className="observation-note-list">
            {observation.false_positive_notes.map((note) => (
              <li key={note}>{note}</li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}

function AlertList({ alerts, targetHref }: { alerts: DetectorAlert[]; targetHref?: string }) {
  const [selectedAlertKey, setSelectedAlertKey] = useState<string | null>(null);
  const selectedAlert = selectedAlertKey
    ? alerts.find((alert, index) => alertKey(alert, index) === selectedAlertKey) ?? null
    : null;

  useEffect(() => {
    if (
      selectedAlertKey &&
      !alerts.some((alert, index) => alertKey(alert, index) === selectedAlertKey)
    ) {
      setSelectedAlertKey(null);
    }
  }, [alerts, selectedAlertKey]);

  if (alerts.length === 0) {
    return <p className="muted compact">No detector alerts in the current window.</p>;
  }

  return (
    <>
      <ul className="alert-list">
        {alerts.slice(0, 4).map((alert, index) => {
          const key = alertKey(alert, index);
          return (
            <li key={key}>
              <button
                type="button"
                className="alert-link alert-button"
                aria-label={`${formatAlertTitle(alert.alert_type)} at ${formatAlertWindow(alert)}: ${alert.summary}`}
                onClick={() => setSelectedAlertKey(key)}
              >
                <AlertContent alert={alert} />
              </button>
            </li>
          );
        })}
      </ul>
      {selectedAlert ? (
        <AlertModal
          alert={selectedAlert}
          targetHref={targetHref}
          onClose={() => setSelectedAlertKey(null)}
        />
      ) : null}
    </>
  );
}

function AlertContent({ alert }: { alert: DetectorAlert }) {
  return (
    <>
      <div className="alert-line">
        <strong>{formatAlertTitle(alert.alert_type)}</strong>
        <span className={`severity severity-${alert.severity}`}>{alert.severity}</span>
      </div>
      <p>{alert.summary}</p>
      <small className="alert-time-line">
        {formatAlertWindow(alert)} | {formatAlertWindowDuration(alert)} window
      </small>
      <small>
        {valueOrUnknown(alert.client)} | {valueOrUnknown(alert.ssid)} | score {alert.score}
      </small>
    </>
  );
}

function AlertModal({
  alert,
  targetHref,
  onClose
}: {
  alert: DetectorAlert;
  targetHref?: string;
  onClose: () => void;
}) {
  useBodyScrollLock(true);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        onClose();
      }
    };

    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [onClose]);

  return (
    <ModalPortal>
    <div className="device-modal-backdrop" role="presentation" onMouseDown={onClose}>
      <section
        className="device-modal alert-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="alert-modal-title"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <div className="alert-modal-heading">
          <div>
            <h2 id="alert-modal-title">{formatAlertTitle(alert.alert_type)}</h2>
            <p>{alert.summary}</p>
          </div>
          <span className={`severity severity-${alert.severity}`}>{alert.severity}</span>
          <button type="button" className="device-modal-close" onClick={onClose} aria-label="Close alert details">
            x
          </button>
        </div>

        <div className="alert-rationale">
          <strong>Why this is marked</strong>
          <p>{formatAlertReason(alert)}</p>
        </div>

        <dl className="network-detail-grid alert-detail-grid">
          <div>
            <dt>Detector</dt>
            <dd>{alert.alert_type}</dd>
          </div>
          <div>
            <dt>Score</dt>
            <dd>{alert.score}</dd>
          </div>
          <div>
            <dt>Cycles</dt>
            <dd>{alert.cycle_count}</dd>
          </div>
          <div>
            <dt>Client</dt>
            <dd>{valueOrUnknown(alert.client)}</dd>
          </div>
          <div>
            <dt>SSID</dt>
            <dd>{valueOrUnknown(alert.ssid)}</dd>
          </div>
          <div>
            <dt>Window start</dt>
            <dd>{formatDateTime(alert.window_start_utc)}</dd>
          </div>
          <div>
            <dt>Window end</dt>
            <dd>{formatDateTime(alert.window_end_utc)}</dd>
          </div>
          <div>
            <dt>Created</dt>
            <dd>{formatDateTime(alert.ts_utc)}</dd>
          </div>
        </dl>

        <div className="activity-message-fields">
          <strong>Evidence event ids</strong>
          <p>{formatList(alert.evidence_event_ids)}</p>
        </div>

        {alert.false_positive_notes.length > 0 ? (
          <div className="activity-message-fields">
            <strong>False-positive notes</strong>
            <ul className="observation-note-list">
              {alert.false_positive_notes.map((note) => (
                <li key={note}>{note}</li>
              ))}
            </ul>
          </div>
        ) : null}

        {targetHref ? (
          <a className="modal-jump-link" href={targetHref} onClick={onClose}>
            Open timeline evidence
          </a>
        ) : null}
      </section>
    </div>
    </ModalPortal>
  );
}

function ActivityPanelHeading({
  title,
  countLabel,
  checkedAt,
  newestAt,
  hint
}: {
  title: string;
  countLabel: string;
  checkedAt: string | null;
  newestAt: string | null;
  hint: string;
}) {
  return (
    <div className="activity-heading">
      <div className="panel-heading">
        <h2>{title}</h2>
        <span>{countLabel}</span>
      </div>
      <div className="activity-heading-meta">
        <span>Checked {formatDateTime(checkedAt)}</span>
        <span>Newest {formatDateTime(newestAt)}</span>
        <button type="button" className="hint-button" title={hint} aria-label={`${title} hint`}>
          ?
        </button>
      </div>
    </div>
  );
}

function TimelineList({ events }: { events: ClientTimelineEvent[] }) {
  const [expandedEventKey, setExpandedEventKey] = useState<string | null>(null);

  useEffect(() => {
    if (
      expandedEventKey &&
      !events.some((event, index) => timelineEventKey(event, index) === expandedEventKey)
    ) {
      setExpandedEventKey(null);
    }
  }, [events, expandedEventKey]);

  if (events.length === 0) {
    return <p className="muted compact">No recent lifecycle events loaded.</p>;
  }

  return (
    <ol className="activity-list">
      {events.map((event, index) => {
        const key = timelineEventKey(event, index);
        const isExpanded = expandedEventKey === key;

        return (
          <li key={key} className={isExpanded ? 'activity-item-expanded' : undefined}>
            <button
              type="button"
              className="activity-row"
              aria-expanded={isExpanded}
              aria-controls={`timeline-details-${toDomId(key)}`}
              onClick={() => setExpandedEventKey(isExpanded ? null : key)}
            >
              <time>{formatDateTime(event.ts_utc)}</time>
              <span className="activity-summary">
                <strong>{formatLifecycleAction(event.action)}</strong>
                <p>{event.summary}</p>
                <small>
                  Event {event.event_id} | {valueOrUnknown(event.client)} | {valueOrUnknown(event.ssid)}
                </small>
              </span>
              <span className="activity-toggle-mark" aria-hidden="true">
                {isExpanded ? '-' : '+'}
              </span>
            </button>
            {isExpanded ? <TimelineDetails event={event} id={`timeline-details-${toDomId(key)}`} /> : null}
          </li>
        );
      })}
    </ol>
  );
}

function EventList({ events }: { events: WindowsWifiEvent[] }) {
  const [expandedEventKey, setExpandedEventKey] = useState<string | null>(null);

  useEffect(() => {
    if (
      expandedEventKey &&
      !events.some((event, index) => wlanEventKey(event, index) === expandedEventKey)
    ) {
      setExpandedEventKey(null);
    }
  }, [events, expandedEventKey]);

  if (events.length === 0) {
    return <p className="muted compact">No WLAN AutoConfig events loaded.</p>;
  }

  return (
    <ol className="activity-list">
      {events.map((event, index) => {
        const key = wlanEventKey(event, index);
        const isExpanded = expandedEventKey === key;

        return (
          <li key={key} className={isExpanded ? 'activity-item-expanded' : undefined}>
            <button
              type="button"
              className="activity-row"
              aria-expanded={isExpanded}
              aria-controls={`wlan-event-details-${toDomId(key)}`}
              onClick={() => setExpandedEventKey(isExpanded ? null : key)}
            >
              <time>{formatDateTime(event.ts_utc)}</time>
              <span className="activity-summary">
                <strong>{formatWlanEventTitle(event.event_id)}</strong>
                <p>{firstLine(event.raw_message)}</p>
                <small>
                  {valueOrUnknown(event.level)} | {valueOrUnknown(event.local_mac)} | {valueOrUnknown(event.ssid)}
                </small>
              </span>
              <span className="activity-toggle-mark" aria-hidden="true">
                {isExpanded ? '-' : '+'}
              </span>
            </button>
            {isExpanded ? <WlanEventDetails event={event} id={`wlan-event-details-${toDomId(key)}`} /> : null}
          </li>
        );
      })}
    </ol>
  );
}

function TimelineDetails({ event, id }: { event: ClientTimelineEvent; id: string }) {
  return (
    <div id={id} className="activity-details">
      <dl className="activity-detail-grid">
        <div>
          <dt>Action</dt>
          <dd>{formatLifecycleAction(event.action)}</dd>
        </div>
        <div>
          <dt>Client</dt>
          <dd>{valueOrUnknown(event.client)}</dd>
        </div>
        <div>
          <dt>SSID</dt>
          <dd>{valueOrUnknown(event.ssid)}</dd>
        </div>
        <div>
          <dt>Adapter</dt>
          <dd>{valueOrUnknown(event.adapter)}</dd>
        </div>
        <div>
          <dt>Event ID</dt>
          <dd>{event.event_id}</dd>
        </div>
        <div>
          <dt>Record ID</dt>
          <dd>{valueOrUnknown(event.record_id)}</dd>
        </div>
        <div>
          <dt>Observed</dt>
          <dd>{formatDateTime(event.ts_utc)}</dd>
        </div>
        <div>
          <dt>Evidence</dt>
          <dd>{formatList(event.evidence_event_ids)}</dd>
        </div>
      </dl>
      <p className="activity-detail-note">{event.summary}</p>
    </div>
  );
}

function WlanEventDetails({ event, id }: { event: WindowsWifiEvent; id: string }) {
  const messageFields = Object.entries(event.message_fields).filter(([_name, value]) => value.trim().length > 0);

  return (
    <div id={id} className="activity-details">
      <dl className="activity-detail-grid">
        <div>
          <dt>Event ID</dt>
          <dd>{event.event_id}</dd>
        </div>
        <div>
          <dt>Record ID</dt>
          <dd>{valueOrUnknown(event.record_id)}</dd>
        </div>
        <div>
          <dt>Provider</dt>
          <dd>{valueOrUnknown(event.provider_name)}</dd>
        </div>
        <div>
          <dt>Level</dt>
          <dd>{valueOrUnknown(event.level)}</dd>
        </div>
        <div>
          <dt>Client</dt>
          <dd>{valueOrUnknown(event.local_mac)}</dd>
        </div>
        <div>
          <dt>SSID</dt>
          <dd>{valueOrUnknown(event.ssid)}</dd>
        </div>
        <div>
          <dt>BSS type</dt>
          <dd>{valueOrUnknown(event.bss_type)}</dd>
        </div>
        <div>
          <dt>Adapter</dt>
          <dd>{valueOrUnknown(event.adapter)}</dd>
        </div>
        <div>
          <dt>Interface GUID</dt>
          <dd>{valueOrUnknown(event.interface_guid)}</dd>
        </div>
        <div>
          <dt>Observed</dt>
          <dd>{formatDateTime(event.ts_utc)}</dd>
        </div>
      </dl>
      {messageFields.length > 0 ? (
        <div className="activity-message-fields">
          <strong>Parsed message fields</strong>
          <dl>
            {messageFields.map(([name, value]) => (
              <div key={name}>
                <dt>{name}</dt>
                <dd>{value}</dd>
              </div>
            ))}
          </dl>
        </div>
      ) : null}
      <div className="activity-raw-message">
        <strong>Raw message</strong>
        <p>{event.raw_message}</p>
      </div>
    </div>
  );
}

function DeltaParts({
  added,
  removed,
  shared
}: {
  added: string[];
  removed: string[];
  shared: string[];
}) {
  if (added.length === 0 && removed.length === 0) {
    return <span className="delta-empty">{shared.length > 0 ? 'no change' : 'none'}</span>;
  }

  return (
    <span className="delta-part-list">
      {added.length > 0 ? <DeltaPart label="added" sign="+" values={added} /> : null}
      {removed.length > 0 ? <DeltaPart label="removed" sign="-" values={removed} /> : null}
    </span>
  );
}

function DeltaPart({ label, sign, values }: { label: string; sign: '+' | '-'; values: string[] }) {
  const shownValues = values.slice(0, 6);
  const hiddenCount = Math.max(0, values.length - shownValues.length);

  return (
    <span className="delta-part">
      <strong>
        {sign}
        {values.length} {label}
      </strong>
      <span>{shownValues.join(', ')}</span>
      {hiddenCount > 0 ? <em>{hiddenCount} more</em> : null}
    </span>
  );
}

function deriveRememberedNetworkItems(
  items: RememberedNetwork[],
  nowMs: number
): Array<RememberedNetwork & { ageSeconds: number | null; isStale: boolean }> {
  return items
    .map((item) => ({
      ...item,
      ageSeconds: secondsSince(item.lastSeenUtc, nowMs),
      isStale: isRememberedNetworkStale(item, nowMs)
    }))
    .sort((left, right) => {
      const leftLive = left.isStale ? 0 : 1;
      const rightLive = right.isStale ? 0 : 1;
      if (leftLive !== rightLive) {
        return rightLive - leftLive;
      }

      return (right.network.signal_percent ?? -1) - (left.network.signal_percent ?? -1);
    });
}

function buildDeviceHistoryByBssid(history: DeviceHistoryResult | null): Map<string, DeviceHistoryRecord> {
  const byBssid = new Map<string, DeviceHistoryRecord>();
  for (const record of history?.records ?? []) {
    const bssid = normalizeMacForCompare(record.bssid);
    if (bssid) {
      byBssid.set(bssid, record);
    }
  }

  return byBssid;
}

function annotateRememberedNetworkItemsWithHistory<
  T extends RememberedNetwork & { ageSeconds: number | null; isStale: boolean }
>(
  items: T[],
  historyByBssid: Map<string, DeviceHistoryRecord>,
  newWindow?: { nowMs: number; windowMs: number }
): Array<T & {
  historyRecord: DeviceHistoryRecord | null;
  isNewInInventory: boolean;
}> {
  return items.map((item) => {
    const historyRecord = deviceHistoryRecordForNetwork(item.network, historyByBssid);
    return {
      ...item,
      historyRecord,
      isNewInInventory: computeHistoryRecordIsNew(historyRecord, newWindow)
    };
  });
}

// Newness is derived client-side from first_seen_utc so the configurable "New =" window can honor
// sub-hour spans (15/30 min). Falls back to the backend's coarse is_new flag when no window/timestamp.
function computeHistoryRecordIsNew(
  historyRecord: DeviceHistoryRecord | null,
  newWindow?: { nowMs: number; windowMs: number }
): boolean {
  if (!historyRecord) {
    return false;
  }
  if (newWindow) {
    const firstSeenMs = Date.parse(historyRecord.first_seen_utc);
    if (Number.isFinite(firstSeenMs)) {
      return newWindow.nowMs - firstSeenMs <= newWindow.windowMs;
    }
  }
  return historyRecord.is_new;
}

function deviceHistoryRecordForNetwork(
  network: WindowsWifiNetwork,
  historyByBssid: Map<string, DeviceHistoryRecord>
): DeviceHistoryRecord | null {
  const bssid = normalizeMacForCompare(network.bssid);
  return bssid ? historyByBssid.get(bssid) ?? null : null;
}

function isRememberedNetworkNewInInventory(
  item: RememberedNetwork & { ageSeconds: number | null; isStale: boolean }
): boolean {
  return (item as { isNewInInventory?: boolean }).isNewInInventory === true;
}

function ensureMapItemIncluded<T extends { key: string }>(items: T[], item: T | null, limit?: number): T[] {
  if (!item || items.some((existing) => existing.key === item.key)) {
    return items;
  }

  const next = [item, ...items];
  return typeof limit === 'number' ? next.slice(0, Math.max(1, limit)) : next;
}

function filterMapItemsByHistory(
  items: Array<RememberedNetwork & { ageSeconds: number | null; isStale: boolean }>,
  filter: MapHistoryFilter,
  nowMs: number
): Array<RememberedNetwork & { ageSeconds: number | null; isStale: boolean }> {
  return items.filter((item) => {
    const ageSeconds = item.ageSeconds;
    const lastSeenMs = Date.parse(item.lastSeenUtc);

    switch (filter) {
      case 'current':
        return isRememberedNetworkFromLatestSource(item);
      case '5m':
        return ageSeconds !== null && ageSeconds <= 5 * 60;
      case '15m':
        return ageSeconds !== null && ageSeconds <= 15 * 60;
      case '30m':
        return ageSeconds !== null && ageSeconds <= 30 * 60;
      case '1h':
        return ageSeconds !== null && ageSeconds <= 60 * 60;
      case '2h':
        return ageSeconds !== null && ageSeconds <= 2 * 60 * 60;
      case '6h':
        return ageSeconds !== null && ageSeconds <= 6 * 60 * 60;
      case '12h':
        return ageSeconds !== null && ageSeconds <= 12 * 60 * 60;
      case '24h':
        return ageSeconds !== null && ageSeconds <= 24 * 60 * 60;
      case 'today':
        return Number.isFinite(lastSeenMs) && isSameLocalDay(lastSeenMs, nowMs);
      case 'old':
        return isMapItemOld(item);
      case 'all':
        return true;
    }
  });
}

function isMapItemOld(item: RememberedNetwork & { ageSeconds: number | null; isStale: boolean }): boolean {
  return item.ageSeconds === null || item.ageSeconds > 60 * 60;
}

function isSameLocalDay(leftMs: number, rightMs: number): boolean {
  const left = new Date(leftMs);
  const right = new Date(rightMs);
  return (
    left.getFullYear() === right.getFullYear() &&
    left.getMonth() === right.getMonth() &&
    left.getDate() === right.getDate()
  );
}

function formatMapHistoryFilter(filter: MapHistoryFilter): string {
  return MAP_HISTORY_FILTERS.find((item) => item.value === filter)?.label ?? filter;
}

function formatMapLastVisible(item: RememberedNetwork & { ageSeconds: number | null; isStale: boolean }): string {
  return `last visible ${formatDateTime(item.lastSeenUtc)} (${formatAge(item.ageSeconds)})`;
}

function formatMapClusterLastVisible(
  items: Array<RememberedNetwork & { ageSeconds: number | null; isStale: boolean }>
): string {
  const latest = items
    .map((item) => Date.parse(item.lastSeenUtc))
    .filter(Number.isFinite)
    .sort((left, right) => right - left)[0];
  if (!Number.isFinite(latest)) {
    return 'Last visible unknown';
  }

  return `Last visible ${formatDateTime(new Date(latest).toISOString())}`;
}

function formatMapItemTitle(options: {
  item: RememberedNetwork & { ageSeconds: number | null; isStale: boolean };
  vendor: string;
  rfOnly?: boolean;
  distanceKm?: number;
  connected: boolean;
}): string {
  const { item, vendor, connected } = options;
  const parts = [
    formatNetworkSsidLabel(item.network),
    vendor,
    formatVulnerabilityBadge(item.network.vulnerability_intel),
    valueOrUnknown(item.network.bssid),
    `signal ${formatPercent(item.network.signal_percent)}`,
    item.network.native_bss?.rssi_dbm !== null && item.network.native_bss?.rssi_dbm !== undefined
      ? `RSSI ${formatRssi(item.network.native_bss.rssi_dbm)}`
      : null,
    formatMapLastVisible(item),
    `source ${formatMapItemSource(item)}`,
    connected ? 'connected anchor' : null
  ].filter((part): part is string => Boolean(part));

  return parts.join(' | ');
}

function buildMapItemTooltip(options: {
  item: RememberedNetwork & { ageSeconds: number | null; isStale: boolean };
  vendor: string;
  visual: NetworkDeviceVisual;
  rfOnly?: boolean;
  distanceKm: number;
  connected: boolean;
  position: { x: number; y: number };
}): MapHoverTooltip {
  const { item, vendor, visual, connected, position } = options;
  const facts: Array<{ label: string; value: string }> = [
    { label: 'Signal', value: formatMapTooltipSignal(item.network) },
    { label: 'Channel', value: valueOrUnknown(item.network.channel) },
    { label: 'Security', value: formatSecurityLabel(item.network) },
    { label: 'Exposure', value: formatVulnerabilityBadge(item.network.vulnerability_intel) },
    { label: 'Last visible', value: formatMapLastVisible(item).replace(/^last visible\s+/i, '') },
    { label: 'Source', value: formatMapItemSource(item) }
  ];

  if (connected) {
    facts.unshift({ label: 'Anchor', value: 'connected AP' });
  }

  return {
    id: `map-item:${item.key}`,
    x: position.x,
    y: position.y,
    title: formatNetworkSsidLabel(item.network),
    subtitle: `${visual.label} | ${vendor} | ${valueOrUnknown(item.network.bssid)}`,
    facts
  };
}

function buildMapClusterTooltip(
  cluster: MapCluster,
  position: { x: number; y: number },
  _rfOnly: boolean,
  _distanceKm: number,
  lastVisible: string
): MapHoverTooltip {
  const strongest = cluster.items[0];
  const ssids = new Set(cluster.items.map((item) => normalizeSsid(item.network.ssid)).filter(Boolean));
  const vendors = new Set(cluster.items.map((item) => formatNetworkVendorLabel(item.network)).filter(Boolean));
  const facts = [
    { label: 'APs', value: `${cluster.items.length} grouped` },
    { label: 'Live', value: `${cluster.liveCount}` },
    { label: 'Review', value: `${cluster.reviewCount}` },
    { label: 'Strongest', value: formatPercent(cluster.strongestSignal) },
    { label: 'SSIDs', value: `${ssids.size}` },
    { label: 'Last visible', value: lastVisible.replace(/^Last visible\s+/i, '') }
  ];

  return {
    id: `map-cluster:${cluster.id}`,
    x: position.x,
    y: position.y,
    title: `${cluster.items.length} grouped APs`,
    subtitle: `${valueOrUnknown(strongest?.network.ssid ?? null)} | ${vendors.size} vendor${vendors.size === 1 ? '' : 's'}`,
    facts
  };
}

function buildLocalMapTooltip(
  snapshot: WindowsWifiSnapshot | null,
  position: { x: number; y: number },
  linkCount: number
): MapHoverTooltip {
  return {
    id: LOCAL_MAP_NODE_KEY,
    x: position.x,
    y: position.y,
    title: 'You',
    subtitle: `${valueOrUnknown(snapshot?.ssid ?? null)} | ${snapshot?.state ?? 'unknown'}`,
    facts: [
      { label: 'MAC', value: valueOrUnknown(snapshot?.physical_address ?? null) },
      { label: 'IPv4', value: formatList(snapshot?.ipv4_addresses ?? []) },
      { label: 'BSSID', value: valueOrUnknown(snapshot?.bssid ?? null) },
      { label: 'Channel', value: valueOrUnknown(snapshot?.channel ?? null) },
      { label: 'Signal', value: formatSnapshotSignal(snapshot) },
      { label: 'Visible links', value: `${linkCount}` }
    ]
  };
}

function formatMapTooltipSignal(network: WindowsWifiNetwork): string {
  const parts = [formatPercent(network.signal_percent)];
  if (network.native_bss?.rssi_dbm !== null && network.native_bss?.rssi_dbm !== undefined) {
    parts.push(formatRssi(network.native_bss.rssi_dbm));
  }
  return parts.join(' / ');
}

function formatSnapshotSignal(snapshot: WindowsWifiSnapshot | null): string {
  if (!snapshot) {
    return 'unknown';
  }

  const parts = [formatPercent(snapshot.signal_percent)];
  if (snapshot.rssi_dbm !== null && snapshot.rssi_dbm !== undefined) {
    parts.push(formatRssi(snapshot.rssi_dbm));
  }
  return parts.join(' / ');
}

function formatMapItemSource(item: RememberedNetwork & { ageSeconds: number | null; isStale: boolean }): string {
  if (isRememberedNetworkFromLatestSource(item)) {
    return 'current scan';
  }
  if (isMapItemOld(item)) {
    return 'history';
  }
  if (item.isStale) {
    return 'held memory';
  }
  return 'live memory';
}

function createNetworkHistorySnapshot(
  tsUtc: string,
  items: RememberedNetwork[],
  nowMs: number
): NetworkHistorySnapshot {
  const derivedItems = deriveRememberedNetworkItems(items, nowMs);
  const liveItems = derivedItems.filter((item) => !item.isStale);

  return {
    id: networkHistorySnapshotKey(tsUtc, items),
    tsUtc,
    items: cloneRememberedNetworks(items),
    ssidCount: countUniqueNetworkSsids(derivedItems),
    bssidCount: derivedItems.length,
    liveCount: liveItems.length,
    strongestSignal: maxNullable(derivedItems.map((item) => item.network.signal_percent))
  };
}

function appendNetworkHistorySnapshot(
  current: NetworkHistorySnapshot[],
  snapshot: NetworkHistorySnapshot
): NetworkHistorySnapshot[] {
  const next = [...current.filter((item) => item.id !== snapshot.id), snapshot];
  return next.slice(Math.max(0, next.length - NETWORK_HISTORY_LIMIT));
}

function loadPersistedNetworkHistory(): NetworkHistorySnapshot[] {
  try {
    const raw = window.localStorage?.getItem(NETWORK_HISTORY_STORAGE_KEY);
    if (!raw) {
      return [];
    }
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as NetworkHistorySnapshot[]) : [];
  } catch {
    return [];
  }
}

function savePersistedNetworkHistory(history: NetworkHistorySnapshot[]): void {
  try {
    const trimmed = history.slice(Math.max(0, history.length - NETWORK_HISTORY_PERSIST_LIMIT));
    window.localStorage?.setItem(NETWORK_HISTORY_STORAGE_KEY, JSON.stringify(trimmed));
  } catch {
    // Quota exceeded or serialization issue: history persistence is best-effort.
  }
}

function networkHistorySnapshotKey(tsUtc: string, items: RememberedNetwork[]): string {
  const strongest = maxNullable(items.map((item) => item.network.signal_percent)) ?? 'none';
  return `${tsUtc}:${items.length}:${strongest}`;
}

function cloneRememberedNetworks(items: RememberedNetwork[]): RememberedNetwork[] {
  return items.map((item) => ({
    ...item,
    network: {
      ...item.network,
      raw: { ...item.network.raw },
      basic_rates_mbps: [...item.network.basic_rates_mbps],
      other_rates_mbps: [...item.network.other_rates_mbps]
    }
  }));
}

function countUniqueNetworkSsids(
  items: Array<RememberedNetwork & { ageSeconds?: number | null; isStale?: boolean }>
): number {
  return new Set(items.map((item) => item.network.ssid).filter(Boolean)).size;
}

function ChannelView({
  items,
  currentSnapshot,
  currentChannel,
  currentBand,
  nowMs,
  refreshing,
  source,
  freshness,
  onRefresh,
  onIntelligenceUpdated,
  onVulnerabilityLookupUpdated,
  onVulnerabilityLookupRecorded
}: {
  items: Array<RememberedNetwork & { ageSeconds: number | null; isStale: boolean }>;
  currentSnapshot: WindowsWifiSnapshot | null;
  currentChannel: number | null;
  currentBand: string | null;
  nowMs: number;
  refreshing: boolean;
  source: CollectorSourceStatus | null;
  freshness: NetworkFreshnessState;
  onRefresh: () => void;
  onIntelligenceUpdated: (network: WindowsWifiNetwork, override: DeviceIntelligenceOverride) => void;
  onVulnerabilityLookupUpdated: (network: WindowsWifiNetwork, result: DeviceVulnerabilityLookupResult) => void;
  onVulnerabilityLookupRecorded: LeakLookupRecordAppender;
}) {
  const buckets = useMemo(() => buildChannelCongestionBuckets(items), [items]);
  const summary = useMemo(() => summarizeChannelCongestion(buckets), [buckets]);
  const [selectedChannelId, setSelectedChannelId] = useState<string | null>(null);
  const [selectedApKey, setSelectedApKey] = useState<string | null>(null);
  const [chartMode, setChartMode] = useState<ChannelChartMode>('rows');
  const currentBandName = normalizeChannelBand(currentBand, currentChannel);
  const currentBucket =
    currentChannel === null
      ? null
      : buckets.find((bucket) => bucket.channel === currentChannel && bucket.band === currentBandName) ?? null;
  const selectedBucket =
    buckets.find((bucket) => bucket.id === selectedChannelId) ??
    currentBucket ??
    summary.busiestBucket ??
    buckets[0] ??
    null;
  const selectedAp = selectedApKey ? items.find((item) => item.key === selectedApKey) ?? null : null;
  const lastScanAge = secondsSince(freshness.acceptedAtUtc, nowMs);

  useEffect(() => {
    if (selectedChannelId && buckets.some((bucket) => bucket.id === selectedChannelId)) {
      return;
    }

    setSelectedChannelId(currentBucket?.id ?? summary.busiestBucket?.id ?? buckets[0]?.id ?? null);
  }, [buckets, currentBucket?.id, selectedChannelId, summary.busiestBucket?.id]);

  useEffect(() => {
    if (selectedApKey && !items.some((item) => item.key === selectedApKey)) {
      setSelectedApKey(null);
    }
  }, [items, selectedApKey]);

  if (!source?.available) {
    return (
      <article className="panel channels-panel">
        <div className="panel-heading">
          <h2>Channel Pressure</h2>
          <span>source down</span>
        </div>
        <p className="muted compact">
          Nearby AP channel data is not available right now.
          {source?.detail ? <span className="detail-block">{source.detail}</span> : null}
        </p>
      </article>
    );
  }

  return (
    <article className="panel channels-panel">
      <div className="panel-heading">
        <h2>Channel Pressure</h2>
        <div className="channel-heading-actions">
          <span>
            {items.filter((item) => !item.isStale).length} live / {items.length} tracked
            {lastScanAge !== null ? ` | last scan ${formatAge(lastScanAge)}` : ''}
          </span>
          <div className="chart-mode-toggle" aria-label="Channel chart view">
            <button
              type="button"
              className={chartMode === 'rows' ? 'chart-mode-button chart-mode-button-active' : 'chart-mode-button'}
              onClick={() => setChartMode('rows')}
              aria-pressed={chartMode === 'rows'}
            >
              Rows
            </button>
            <button
              type="button"
              className={chartMode === 'matrix' ? 'chart-mode-button chart-mode-button-active' : 'chart-mode-button'}
              onClick={() => setChartMode('matrix')}
              aria-pressed={chartMode === 'matrix'}
            >
              Matrix
            </button>
          </div>
          <button type="button" className="scan-now-button" onClick={onRefresh} disabled={refreshing}>
            {refreshing ? 'Scanning' : 'Scan now'}
          </button>
        </div>
      </div>

      <div className="channel-summary-grid">
        <ChannelStat label="Busiest" value={summary.busiestBucket ? channelLabel(summary.busiestBucket) : 'none'} detail={summary.busiestBucket ? channelScoreLabel(summary.busiestBucket.congestionScore) : 'no channels'} tone="warn" />
        <ChannelStat label="Quietest" value={summary.quietestBucket ? channelLabel(summary.quietestBucket) : 'none'} detail={summary.quietestBucket ? channelScoreLabel(summary.quietestBucket.congestionScore) : 'no channels'} tone="ok" />
        <ChannelStat label="Current" value={currentChannel === null ? 'unknown' : `ch ${currentChannel}`} detail={currentBandName} tone={currentBucket && currentBucket.congestionScore >= 70 ? 'warn' : 'ok'} />
        <ChannelStat label="Crowded" value={summary.crowdedCount} detail="score 70+" tone={summary.crowdedCount > 0 ? 'warn' : 'ok'} />
        <ChannelStat label="BSS Load IE" value={summary.bssLoadCount} detail="APs advertise load data" />
      </div>

      <div className="channel-layout">
        <section className="channel-chart-panel" aria-label="Channel congestion chart">
          {buckets.length === 0 ? (
            <p className="muted compact">No channel records are available yet. Run a nearby AP scan.</p>
          ) : (
            chartMode === 'matrix' ? (
              <ChannelMatrixChart
                buckets={buckets}
                selectedId={selectedBucket?.id ?? null}
                currentChannel={currentChannel}
                currentBand={currentBandName}
                onSelect={setSelectedChannelId}
              />
            ) : (
              <ChannelChart
                buckets={buckets}
                selectedId={selectedBucket?.id ?? null}
                currentChannel={currentChannel}
                currentBand={currentBandName}
                onSelect={setSelectedChannelId}
              />
            )
          )}
        </section>

        <section className="channel-detail-panel">
          {selectedBucket ? (
            <ChannelDetails
              bucket={selectedBucket}
              currentChannel={currentChannel}
              currentBand={currentBandName}
              onSelectAp={(item) => setSelectedApKey(item.key)}
            />
          ) : (
            <p className="muted compact">Select a channel to inspect AP pressure.</p>
          )}
        </section>
      </div>
      {selectedAp ? (
        <DeviceModal
          item={selectedAp}
          currentSnapshot={currentSnapshot}
          onClose={() => setSelectedApKey(null)}
          onIntelligenceUpdated={onIntelligenceUpdated}
          onVulnerabilityLookupUpdated={onVulnerabilityLookupUpdated}
          onVulnerabilityLookupRecorded={onVulnerabilityLookupRecorded}
        />
      ) : null}
    </article>
  );
}

function ChannelStat({
  label,
  value,
  detail,
  tone
}: {
  label: string;
  value: string | number;
  detail: string;
  tone?: 'ok' | 'warn';
}) {
  return (
    <div className={`channel-stat ${tone ? `channel-stat-${tone}` : ''}`}>
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{detail}</small>
    </div>
  );
}

function ChannelChart({
  buckets,
  selectedId,
  currentChannel,
  currentBand,
  onSelect
}: {
  buckets: ChannelCongestionBucket[];
  selectedId: string | null;
  currentChannel: number | null;
  currentBand: ChannelBand;
  onSelect: (id: string) => void;
}) {
  const bucketsByBand = groupChannelBucketsByBand(buckets);

  return (
    <div className="channel-chart">
      {bucketsByBand.map(([band, bandBuckets]) => (
        <section key={band} className="channel-band-section">
          <div className="channel-band-heading">
            <strong>{band}</strong>
            <span>
              {bandBuckets.length} channels | {bandBuckets.reduce((total, bucket) => total + bucket.items.length, 0)} APs
            </span>
          </div>
          <div className="channel-row-list">
            {bandBuckets.map((bucket) => (
              <ChannelRow
                key={bucket.id}
                bucket={bucket}
                selected={bucket.id === selectedId}
                current={bucket.channel === currentChannel && bucket.band === currentBand}
                onSelect={() => onSelect(bucket.id)}
              />
            ))}
          </div>
        </section>
      ))}
    </div>
  );
}

function ChannelMatrixChart({
  buckets,
  selectedId,
  currentChannel,
  currentBand,
  onSelect
}: {
  buckets: ChannelCongestionBucket[];
  selectedId: string | null;
  currentChannel: number | null;
  currentBand: ChannelBand;
  onSelect: (id: string) => void;
}) {
  const bucketsByBand = groupChannelBucketsByBand(buckets);

  return (
    <div className="channel-matrix-chart">
      {bucketsByBand.map(([band, bandBuckets]) => (
        <section key={band} className="channel-band-section">
          <div className="channel-band-heading">
            <strong>{band}</strong>
            <span>
              {bandBuckets.length} channels | {bandBuckets.reduce((total, bucket) => total + bucket.items.length, 0)} APs
            </span>
          </div>
          <div className="channel-matrix-grid">
            {bandBuckets.map((bucket) => {
              const tone = channelScoreTone(bucket.congestionScore);
              const selected = bucket.id === selectedId;
              const current = bucket.channel === currentChannel && bucket.band === currentBand;
              return (
                <button
                  key={bucket.id}
                  type="button"
                  className={`channel-matrix-cell channel-matrix-${tone} ${selected ? 'channel-matrix-selected' : ''} ${current ? 'channel-matrix-current' : ''}`}
                  onClick={() => onSelect(bucket.id)}
                  title={`${channelLabel(bucket)}: ${bucket.items.length} APs, score ${bucket.congestionScore}`}
                >
                  <span className="channel-matrix-bars" aria-hidden="true">
                    <span
                      className={`channel-matrix-pressure channel-pressure-${tone}`}
                      style={{ height: `${Math.max(8, bucket.congestionScore)}%` }}
                    />
                    <span
                      className="channel-matrix-signal"
                      style={{ height: `${Math.max(8, bucket.strongestSignal ?? bucket.averageSignal ?? 0)}%` }}
                    />
                  </span>
                  <strong>ch {bucket.channel}</strong>
                  <small>{bucket.congestionScore} score</small>
                  <small>{bucket.liveCount} live</small>
                </button>
              );
            })}
          </div>
        </section>
      ))}
    </div>
  );
}

function ChannelRow({
  bucket,
  selected,
  current,
  onSelect
}: {
  bucket: ChannelCongestionBucket;
  selected: boolean;
  current: boolean;
  onSelect: () => void;
}) {
  const total = Math.max(1, bucket.strongCount + bucket.mediumCount + bucket.weakCount);

  return (
    <button
      type="button"
      className={`channel-row channel-row-${channelScoreTone(bucket.congestionScore)} ${selected ? 'channel-row-selected' : ''} ${current ? 'channel-row-current' : ''}`}
      onClick={onSelect}
      title={`${channelLabel(bucket)}: ${bucket.items.length} APs, score ${bucket.congestionScore}`}
    >
      <span className="channel-label">
        <strong>ch {bucket.channel}</strong>
        <small>{current ? 'current' : bucket.band}</small>
      </span>
      <span className="channel-bars">
        <span className="channel-pressure-track">
          <span
            className={`channel-pressure-fill channel-pressure-${channelScoreTone(bucket.congestionScore)}`}
            style={{ width: `${bucket.congestionScore}%` }}
          />
        </span>
        <span className="channel-stack" aria-label="AP signal mix">
          {bucket.strongCount > 0 ? (
            <span className="channel-stack-strong" style={{ flexBasis: `${(bucket.strongCount / total) * 100}%` }} />
          ) : null}
          {bucket.mediumCount > 0 ? (
            <span className="channel-stack-medium" style={{ flexBasis: `${(bucket.mediumCount / total) * 100}%` }} />
          ) : null}
          {bucket.weakCount > 0 ? (
            <span className="channel-stack-weak" style={{ flexBasis: `${(bucket.weakCount / total) * 100}%` }} />
          ) : null}
        </span>
      </span>
      <span className="channel-row-meta">
        <strong>{bucket.congestionScore}</strong>
        <small>{bucket.liveCount} live | {formatPercent(bucket.strongestSignal)}</small>
      </span>
    </button>
  );
}

function ChannelDetails({
  bucket,
  currentChannel,
  currentBand,
  onSelectAp
}: {
  bucket: ChannelCongestionBucket;
  currentChannel: number | null;
  currentBand: ChannelBand;
  onSelectAp: (item: RememberedNetwork & { ageSeconds: number | null; isStale: boolean }) => void;
}) {
  const isCurrent = bucket.channel === currentChannel && bucket.band === currentBand;
  const reasons = channelCongestionReasons(bucket);

  return (
    <div className="channel-details">
      <div className="channel-detail-heading">
        <div>
          <h3>{channelLabel(bucket)}</h3>
          <p>
            {channelScoreLabel(bucket.congestionScore)}
            {isCurrent ? ' | connected here' : ''}
          </p>
        </div>
        <span className={`channel-score-badge channel-score-${channelScoreTone(bucket.congestionScore)}`}>
          {bucket.congestionScore}
        </span>
      </div>
      <dl className="network-detail-grid channel-facts">
        <div>
          <dt>APs</dt>
          <dd>{bucket.items.length} total, {bucket.liveCount} live</dd>
        </div>
        <div>
          <dt>Signal mix</dt>
          <dd>{bucket.strongCount} strong, {bucket.mediumCount} medium, {bucket.weakCount} weak</dd>
        </div>
        <div>
          <dt>Strongest</dt>
          <dd>{formatPercent(bucket.strongestSignal)}</dd>
        </div>
        <div>
          <dt>Average</dt>
          <dd>{formatPercent(bucket.averageSignal)}</dd>
        </div>
        <div>
          <dt>Overlap pressure</dt>
          <dd>{bucket.overlapScore}</dd>
        </div>
        <div>
          <dt>Utilization</dt>
          <dd>{bucket.utilizationPercent === null ? 'not reported' : `${bucket.utilizationPercent}%`}</dd>
        </div>
      </dl>
      <div className="channel-explain">
        <strong>Why this score</strong>
        <ul>
          {reasons.map((reason) => (
            <li key={reason}>{reason}</li>
          ))}
        </ul>
      </div>
      <div className="channel-ap-list">
        <strong>APs on this channel</strong>
        <ol>
          {bucket.items.map((item) => {
            const visual = networkDeviceVisual(item.network);
            const vendor = formatNetworkVendorLabel(item.network);
            return (
              <li key={item.key} className={item.isStale ? 'channel-ap-stale' : undefined}>
                <button
                  type="button"
                  className="channel-ap-button"
                  onClick={() => onSelectAp(item)}
                  title={`Open ${formatNetworkSsidLabel(item.network)} details`}
                >
                  <span className={`map-memory-avatar map-memory-${visual.kind}`}>
                    <img src={visual.image} alt={visual.alt} />
                  </span>
                  <span>
                    <strong>{formatNetworkSsidLabel(item.network)}</strong>
                    <small>{valueOrUnknown(item.network.bssid)}</small>
                    <small>
                      {vendor} | {formatPercent(item.network.signal_percent)} | {formatNetworkSecurityBadge(item.network)} | {formatVulnerabilityBadge(item.network.vulnerability_intel)}
                    </small>
                  </span>
                </button>
              </li>
            );
          })}
        </ol>
      </div>
    </div>
  );
}

function updateRememberedNetworks(
  current: RememberedNetwork[],
  scannedNetworks: WindowsWifiNetwork[],
  scanTsUtc: string,
  nowMs: number
): RememberedNetwork[] {
  const nextByKey = new Map<string, RememberedNetwork>();
  const scannedKeys = new Set<string>();

  for (const item of current) {
    const lastSeenMs = new Date(item.lastSeenUtc).getTime();
    if (Number.isFinite(lastSeenMs) && nowMs - lastSeenMs <= NETWORK_MEMORY_HOLD_MS) {
      nextByKey.set(item.key, item);
    }
  }

  for (const network of scannedNetworks) {
    const key = rememberedNetworkKey(network);
    if (!key) {
      continue;
    }

    const existing = nextByKey.get(key);
    scannedKeys.add(key);
    nextByKey.set(key, {
      key,
      network,
      firstSeenUtc: existing?.firstSeenUtc ?? scanTsUtc,
      lastSeenUtc: scanTsUtc,
      seenCount: (existing?.seenCount ?? 0) + 1,
      missedScans: 0
    });
  }

  for (const [key, item] of nextByKey) {
    if (!scannedKeys.has(key)) {
      nextByKey.set(key, {
        ...item,
        missedScans: item.missedScans + 1
      });
    }
  }

  return [...nextByKey.values()];
}

function buildRememberedItemsForScanLocation(
  location: ScanLocationRecord | null,
  scanLocations: ScanLocationsResult | null,
  liveItems: Array<RememberedNetwork & { ageSeconds: number | null; isStale: boolean }>,
  nowMs: number
): Array<RememberedNetwork & { ageSeconds: number | null; isStale: boolean }> {
  if (!location || !scanLocations) {
    return liveItems;
  }

  const liveByBssid = new Map<string, RememberedNetwork & { ageSeconds: number | null; isStale: boolean }>();
  for (const item of liveItems) {
    const bssid = normalizeMacForCompare(item.network.bssid);
    if (bssid) {
      liveByBssid.set(bssid, item);
    }
  }

  const items: RememberedNetwork[] = [];
  for (const metric of scanLocations.metrics.filter((item) => item.location_key === location.location_key)) {
    const bssid = normalizeMacForCompare(metric.bssid);
    if (!bssid) {
      continue;
    }

    const liveItem = liveByBssid.get(bssid);
    if (liveItem) {
      items.push(liveItem);
      continue;
    }

    const latestNetwork = metric.latest_network;
    if (!latestNetwork) {
      continue;
    }

    items.push({
      key: rememberedNetworkKey(latestNetwork) ?? metric.bssid.toLowerCase(),
      network: latestNetwork,
      firstSeenUtc: metric.first_seen_utc,
      lastSeenUtc: metric.last_seen_utc,
      seenCount: metric.seen_count,
      missedScans: 1
    });
  }

  return deriveRememberedNetworkItems(items, nowMs);
}

function scanLocationSummary(
  location: ScanLocationRecord,
  metrics: ScanLocationsResult['metrics']
): {
  location: ScanLocationRecord;
  apCount: number;
  reviewCount: number;
  scanCount: number;
} {
  const locationMetrics = metrics.filter((metric) => metric.location_key === location.location_key);
  return {
    location,
    apCount: locationMetrics.length,
    reviewCount: locationMetrics.filter((metric) => {
      const level = metric.latest_network?.vulnerability_intel?.exposure_level;
      return level === 'review' || level === 'priority';
    }).length,
    scanCount: location.scan_count
  };
}

function formatScanLocationLabel(location: ScanLocationRecord): string {
  return location.label?.trim() || `Point ${location.id}`;
}

function scanLocationCardStyle(index: number, count: number): CSSProperties {
  if (count <= 1) {
    return { left: '50%', top: '50%' };
  }

  const ring = count <= 6 ? 28 : 36;
  const angle = (index / count) * Math.PI * 2 - Math.PI / 2;
  return {
    left: `${50 + Math.cos(angle) * ring}%`,
    top: `${50 + Math.sin(angle) * ring}%`
  };
}

function rememberedNetworkKey(network: WindowsWifiNetwork): string | null {
  if (network.bssid) {
    return network.bssid.toLowerCase();
  }

  if (!network.ssid) {
    return null;
  }

  return `${network.ssid}|${network.channel ?? 'channel'}|${network.radio_type ?? 'radio'}`.toLowerCase();
}

function clearLegacyMapLayoutStorage(): void {
  if (typeof window === 'undefined') {
    return;
  }

  for (const key of LEGACY_MAP_LAYOUT_STORAGE_KEYS) {
    try {
      window.localStorage.removeItem(key);
    } catch {
      // Local storage cleanup is best-effort; the map no longer reads these keys.
    }
  }
}

function applyRfSpreadToPosition(position: { x: number; y: number }, rangeKm: number): { x: number; y: number } {
  const factor = mapRfSpreadFactor(rangeKm);
  return {
    x: Math.round(clampLayoutValue(50 + (position.x - 50) * factor, 2, 98) * 10) / 10,
    y: Math.round(clampLayoutValue(50 + (position.y - 50) * factor, 2, 98) * 10) / 10
  };
}

function mapRfSpreadFactor(rangeKm: number): number {
  if (rangeKm <= 0.03) {
    return 0.62;
  }
  if (rangeKm <= 0.05) {
    return 0.78;
  }
  if (rangeKm <= 0.08) {
    return 1;
  }
  if (rangeKm <= 0.12) {
    return 1.16;
  }
  if (rangeKm <= 0.25) {
    return 1.36;
  }
  if (rangeKm <= 0.5) {
    return 1.58;
  }
  return 1.82;
}

function compareMapPositionedItemsForClustering(left: MapPositionedItem, right: MapPositionedItem): number {
  return (
    Math.round(left.position.y * 10) - Math.round(right.position.y * 10) ||
    Math.round(left.position.x * 10) - Math.round(right.position.x * 10) ||
    left.id.localeCompare(right.id)
  );
}

function mapItemPositionsFromDrawables(
  drawables: MapDrawable[],
  drawablePositions: Map<string, { x: number; y: number }>,
  zoom: number
): Map<string, { x: number; y: number }> {
  const positions = new Map<string, { x: number; y: number }>();
  for (const drawable of drawables) {
    const displayPosition = drawablePositions.get(drawable.id) ?? zoomMapPosition(drawable.position, zoom);
    if (drawable.kind === 'item') {
      positions.set(drawable.item.key, displayPosition);
      continue;
    }

    for (const item of drawable.items) {
      positions.set(item.key, displayPosition);
    }
  }

  return positions;
}

function mapItemEndpointRadiiFromDrawables(drawables: MapDrawable[]): Map<string, number> {
  const radii = new Map<string, number>();
  for (const drawable of drawables) {
    if (drawable.kind === 'item') {
      radii.set(drawable.item.key, MAP_NODE_ENDPOINT_RADIUS_PX);
      continue;
    }

    for (const item of drawable.items) {
      radii.set(item.key, MAP_CLUSTER_ENDPOINT_RADIUS_PX);
    }
  }

  return radii;
}

function buildMapConnectionLinks(
  items: Array<RememberedNetwork & { ageSeconds: number | null; isStale: boolean }>,
  currentSnapshot: WindowsWifiSnapshot | null,
  itemPositions: Map<string, { x: number; y: number }>,
  itemEndpointRadii: Map<string, number>
): MapConnectionLink[] {
  const connectedItem = findConnectedMapItem(items, currentSnapshot);
  const mapCenter = { x: 50, y: 50 };
  if (!connectedItem) {
    return [];
  }

  const links: MapConnectionLink[] = [];
  const rayEndpointKeys = new Set<string>();
  const connectedPosition = itemPositions.get(connectedItem.key);
  if (connectedPosition) {
    rayEndpointKeys.add(mapConnectionEndpointKey(connectedPosition));
    links.push({
      id: `connected:${connectedItem.key}`,
      sourceKey: null,
      targetKey: connectedItem.key,
      kind: 'connected',
      start: mapCenter,
      end: connectedPosition,
      sourceRadiusPx: 0,
      targetRadiusPx: itemEndpointRadii.get(connectedItem.key) ?? MAP_NODE_ENDPOINT_RADIUS_PX,
      signal: connectedItem.network.signal_percent,
      label: 'Connected AP',
      detail: `${valueOrUnknown(connectedItem.network.ssid)} | ${formatPercent(connectedItem.network.signal_percent)} | ch ${valueOrUnknown(connectedItem.network.channel)}`
    });
  }

  const meshCandidates = items
    .filter((item) =>
      item.key !== connectedItem.key &&
      !item.isStale &&
      !isMapItemOld(item) &&
      isLikelyMeshPeer(item.network, connectedItem.network, currentSnapshot)
    )
    .sort((left, right) => (right.network.signal_percent ?? -1) - (left.network.signal_percent ?? -1))
    .slice(0, 14);

  for (const item of meshCandidates) {
    const position = itemPositions.get(item.key);
    if (!position) {
      continue;
    }

    const endpointKey = mapConnectionEndpointKey(position);
    if (rayEndpointKeys.has(endpointKey)) {
      continue;
    }
    rayEndpointKeys.add(endpointKey);

    links.push({
      id: `mesh:${item.key}`,
      sourceKey: null,
      targetKey: item.key,
      kind: 'mesh',
      start: mapCenter,
      end: position,
      sourceRadiusPx: 0,
      targetRadiusPx: itemEndpointRadii.get(item.key) ?? MAP_NODE_ENDPOINT_RADIUS_PX,
      signal: item.network.signal_percent,
      label: 'Likely mesh peer',
      detail: `${formatNetworkSsidLabel(item.network)} | ${formatPercent(item.network.signal_percent)} | ch ${valueOrUnknown(item.network.channel)}`
    });
  }

  const linkedKeys = new Set(links.map((link) => link.targetKey));
  const memoryCandidates = items
    .filter((item) =>
      !linkedKeys.has(item.key) &&
      item.isStale &&
      !isMapItemOld(item) &&
      isLikelyMeshPeer(item.network, connectedItem.network, currentSnapshot)
    )
    .sort((left, right) => (right.seenCount - left.seenCount) || (right.network.signal_percent ?? -1) - (left.network.signal_percent ?? -1))
    .slice(0, 8);

  for (const item of memoryCandidates) {
    const position = itemPositions.get(item.key);
    if (!position) {
      continue;
    }

    const endpointKey = mapConnectionEndpointKey(position);
    if (rayEndpointKeys.has(endpointKey)) {
      continue;
    }
    rayEndpointKeys.add(endpointKey);

    links.push({
      id: `memory:${item.key}`,
      sourceKey: null,
      targetKey: item.key,
      kind: 'memory',
      start: mapCenter,
      end: position,
      sourceRadiusPx: 0,
      targetRadiusPx: itemEndpointRadii.get(item.key) ?? MAP_NODE_ENDPOINT_RADIUS_PX,
      signal: item.network.signal_percent,
      label: 'Remembered mesh peer',
      detail: `${formatNetworkSsidLabel(item.network)} | ${formatAge(item.ageSeconds)} | last seen`
    });
  }

  const peerItems = [connectedItem, ...meshCandidates]
    .filter((item) => !isMapItemOld(item) && isLikelyRouterOrMesh(item.network))
    .slice(0, 10);
  const peerLinkCandidates: Array<{
    left: RememberedNetwork & { ageSeconds: number | null; isStale: boolean };
    right: RememberedNetwork & { ageSeconds: number | null; isStale: boolean };
    start: { x: number; y: number };
    end: { x: number; y: number };
    score: number;
  }> = [];

  for (let rightIndex = 1; rightIndex < peerItems.length; rightIndex += 1) {
    const right = peerItems[rightIndex];
    const end = itemPositions.get(right.key);
    if (!end) {
      continue;
    }

    const candidatesForNode = peerItems
      .slice(0, rightIndex)
      .map((left) => {
        const start = itemPositions.get(left.key);
        if (!start || !isLikelyMeshPeer(right.network, left.network, currentSnapshot)) {
          return null;
        }

        const distance = distancePercent(start, end);
        if (distance < 4) {
          return null;
        }

        const minSignal = Math.min(left.network.signal_percent ?? 45, right.network.signal_percent ?? 45);
        return {
          left,
          right,
          start,
          end,
          score: minSignal + (left.key === connectedItem.key ? 12 : 0) - distance * 0.18
        };
      })
      .filter((candidate): candidate is NonNullable<typeof candidate> => candidate !== null)
      .sort((left, rightCandidate) => rightCandidate.score - left.score);

    const best = candidatesForNode[0];
    if (best) {
      peerLinkCandidates.push(best);
    }
  }

  for (const candidate of peerLinkCandidates.slice(0, 8)) {
    const signal = Math.min(candidate.left.network.signal_percent ?? 50, candidate.right.network.signal_percent ?? 50);
    links.push({
      id: `mesh-peer:${candidate.left.key}:${candidate.right.key}`,
      sourceKey: candidate.left.key,
      targetKey: candidate.right.key,
      kind: 'mesh_peer',
      start: candidate.start,
      end: candidate.end,
      sourceRadiusPx: itemEndpointRadii.get(candidate.left.key) ?? MAP_NODE_ENDPOINT_RADIUS_PX,
      targetRadiusPx: itemEndpointRadii.get(candidate.right.key) ?? MAP_NODE_ENDPOINT_RADIUS_PX,
      signal,
      label: 'Router mesh link',
      detail: `${valueOrUnknown(candidate.right.network.ssid)} | ${formatPercent(signal)} peer`
    });
  }

  const allPositions = Array.from(itemPositions.values());
  return links.slice(0, 40).map((link) => ({
    ...link,
    avoidPoints: allPositions.filter(
      (position) => distancePercent(position, link.start) > 3 && distancePercent(position, link.end) > 3
    )
  }));
}

function mapConnectionEndpointKey(position: { x: number; y: number }): string {
  return `${Math.round(position.x * 2) / 2}:${Math.round(position.y * 2) / 2}`;
}

function findConnectedMapItem(
  items: Array<RememberedNetwork & { ageSeconds: number | null; isStale: boolean }>,
  currentSnapshot: WindowsWifiSnapshot | null
): (RememberedNetwork & { ageSeconds: number | null; isStale: boolean }) | null {
  return findExactConnectedMapItem(items, currentSnapshot);
}

function findExactConnectedMapItem<T extends RememberedNetwork>(
  items: T[],
  currentSnapshot: WindowsWifiSnapshot | null
): T | null {
  if (!isWifiSnapshotConnected(currentSnapshot)) {
    return null;
  }

  const snapshotBssid = normalizeMacForCompare(currentSnapshot.bssid);
  if (!snapshotBssid) {
    return null;
  }

  return items.find((item) => normalizeMacForCompare(item.network.bssid) === snapshotBssid) ?? null;
}

function isLikelyMeshPeer(
  candidate: WindowsWifiNetwork,
  connected: WindowsWifiNetwork,
  currentSnapshot: WindowsWifiSnapshot | null
): boolean {
  if (!sameWifiProfile(candidate, connected)) {
    return false;
  }

  if (normalizeMacForCompare(candidate.bssid) === normalizeMacForCompare(connected.bssid)) {
    return false;
  }

  const ssid = normalizeSsid(candidate.ssid);
  if (!ssid || ssid.startsWith('direct-') || ssid.includes('print')) {
    return false;
  }

  const candidateHint = inferredDeviceHint(candidate).toLowerCase();
  const connectedHint = inferredDeviceHint(connected).toLowerCase();
  const candidateVendor = candidate.mac_enrichment?.vendor?.toLowerCase() ?? '';
  const connectedVendor = connected.mac_enrichment?.vendor?.toLowerCase() ?? '';
  const candidateOui = candidate.mac_enrichment?.oui?.toLowerCase() ?? '';
  const connectedOuis = new Set([
    connected.mac_enrichment?.oui?.toLowerCase() ?? '',
    currentSnapshot ? normalizeMacForCompare(currentSnapshot.bssid)?.slice(0, 6).match(/.{2}/g)?.join(':') ?? '' : ''
  ]);
  const localProtected =
    candidate.mac_enrichment?.address_scope === 'local' &&
    Boolean(candidate.authentication && !candidate.authentication.toLowerCase().includes('open'));
  const routerHint =
    candidateHint.includes('mesh') ||
    candidateHint.includes('router') ||
    candidateHint.includes('gateway') ||
    candidateHint.includes('extender') ||
    connectedHint.includes('mesh') ||
    connectedHint.includes('router');
  const sameVendor = Boolean(candidateVendor && connectedVendor && candidateVendor === connectedVendor);
  const sameOUI = Boolean(candidateOui && connectedOuis.has(candidateOui));

  return localProtected || routerHint || sameVendor || sameOUI;
}

function isLikelyRouterOrMesh(network: WindowsWifiNetwork): boolean {
  const ssid = network.ssid?.trim().toLowerCase() ?? '';
  if (!ssid || ssid.startsWith('direct-') || ssid.includes('print') || ssid.includes('laserjet')) {
    return false;
  }

  const hint = inferredDeviceHint(network).toLowerCase();
  const visual = networkDeviceVisual(network).kind;
  return (
    visual === 'router' ||
    visual === 'access' ||
    hint.includes('mesh') ||
    hint.includes('router') ||
    hint.includes('gateway') ||
    hint.includes('extender') ||
    (network.mac_enrichment?.address_scope === 'local' && Boolean(network.authentication && !network.authentication.toLowerCase().includes('open')))
  );
}

function sameWifiProfile(left: WindowsWifiNetwork, right: WindowsWifiNetwork): boolean {
  const leftSsid = normalizeSsid(left.ssid);
  return Boolean(leftSsid && leftSsid === normalizeSsid(right.ssid));
}

function normalizeSsid(value: string | null | undefined): string {
  return value?.trim().toLowerCase() ?? '';
}

function isWifiSnapshotConnected(snapshot: WindowsWifiSnapshot | null): snapshot is WindowsWifiSnapshot {
  return snapshot?.state?.trim().toLowerCase() === 'connected';
}

function mapConnectionPath(link: MapConnectionLink, _index: number, viewportSize: MapViewportSize): string {
  const { start, end } = trimMapConnectionEndpoints(link, viewportSize);

  return `M ${roundMapPath(start.x)} ${roundMapPath(start.y)} L ${roundMapPath(end.x)} ${roundMapPath(end.y)}`;
}

function trimMapConnectionEndpoints(
  link: MapConnectionLink,
  viewportSize: MapViewportSize
): { start: { x: number; y: number }; end: { x: number; y: number } } {
  return {
    start: offsetMapPointByPixelRadius(link.start, link.end, link.sourceRadiusPx, viewportSize),
    end: offsetMapPointByPixelRadius(link.end, link.start, link.targetRadiusPx, viewportSize)
  };
}

function offsetMapPointByPixelRadius(
  point: { x: number; y: number },
  toward: { x: number; y: number },
  radiusPx: number,
  viewportSize: MapViewportSize
): { x: number; y: number } {
  if (radiusPx <= 0 || viewportSize.width <= 0 || viewportSize.height <= 0) {
    return point;
  }

  const dxPx = ((toward.x - point.x) / 100) * viewportSize.width;
  const dyPx = ((toward.y - point.y) / 100) * viewportSize.height;
  const lengthPx = Math.hypot(dxPx, dyPx);
  if (lengthPx < 1) {
    return point;
  }

  const offsetPx = Math.min(radiusPx, lengthPx * 0.82);
  return {
    x: point.x + (dxPx / lengthPx) * (offsetPx / viewportSize.width) * 100,
    y: point.y + (dyPx / lengthPx) * (offsetPx / viewportSize.height) * 100
  };
}

function mapConnectionControlPoint(link: MapConnectionLink, index: number): { x: number; y: number } {
  const start = link.start;
  const end = link.end;
  const dx = end.x - start.x;
  const dy = end.y - start.y;
  const length = Math.max(1, Math.hypot(dx, dy));
  const baseBend = Math.min(16, 4 + length * (link.kind === 'mesh_peer' ? 0.18 : 0.1));
  const preferredDirection = link.kind === 'mesh_peer'
    ? (hashString(link.id) % 2 === 0 ? 1 : -1)
    : index % 2 === 0 ? 1 : -1;
  const candidates = [preferredDirection, -preferredDirection].flatMap((direction) =>
    [baseBend, baseBend * 1.45, baseBend * 0.62].map((bend) => ({
      x: (start.x + end.x) / 2 + (-dy / length) * bend * direction,
      y: (start.y + end.y) / 2 + (dx / length) * bend * direction
    }))
  );

  return candidates
    .map((candidate) => ({
      candidate,
      score: mapConnectionAvoidanceScore(candidate, link.avoidPoints ?? [])
    }))
    .sort((left, right) => right.score - left.score)[0]?.candidate ?? candidates[0];
}

function mapConnectionAvoidanceScore(
  control: { x: number; y: number },
  avoidPoints: Array<{ x: number; y: number }>
): number {
  if (avoidPoints.length === 0) {
    return 100;
  }

  return Math.min(...avoidPoints.map((point) => distancePercent(point, control)));
}

function mapConnectionLabelPosition(link: MapConnectionLink): { x: number; y: number } {
  const mid = {
    x: (link.start.x + link.end.x) / 2,
    y: (link.start.y + link.end.y) / 2
  };
  const dx = link.end.x - link.start.x;
  const dy = link.end.y - link.start.y;
  const length = Math.max(1, Math.hypot(dx, dy));
  const offset = link.kind === 'mesh_peer' ? 4 : 6;
  return {
    x: clampLayoutValue(roundMapPath(mid.x + (-dy / length) * offset - 14), 1, 71),
    y: clampLayoutValue(roundMapPath(mid.y + (dx / length) * offset - 4), 1, 90)
  };
}

function mapConnectionWidth(link: MapConnectionLink): { edge: string; core: string } {
  const signal = Math.max(15, Math.min(100, link.signal ?? 45));
  const base = link.kind === 'connected' ? 1.8 : link.kind === 'mesh_peer' ? 2.1 : link.kind === 'memory' ? 1.1 : 1.5;
  const edge = base + signal / (link.kind === 'mesh_peer' ? 120 : 145);
  return {
    edge: `${roundMapPath(edge)}`,
    core: `${roundMapPath(Math.max(0.8, edge * 0.42))}`
  };
}

function roundMapPath(value: number): number {
  return Math.round(value * 10) / 10;
}

function mapLinkKindForItem(links: MapConnectionLink[], itemKey: string): MapConnectionLink['kind'] | null {
  const priority: MapConnectionLink['kind'][] = ['connected', 'mesh', 'mesh_peer', 'memory'];
  for (const kind of priority) {
    const link = links.find((candidate) => candidate.kind === kind && (candidate.targetKey === itemKey || candidate.sourceKey === itemKey));
    if (link) {
      return kind;
    }
  }

  return null;
}

function isRememberedNetworkStale(item: RememberedNetwork, nowMs: number): boolean {
  const lastSeenMs = new Date(item.lastSeenUtc).getTime();
  return !Number.isFinite(lastSeenMs) || nowMs - lastSeenMs > NETWORK_STALE_MS;
}

function compactMapItemsForMeshProfiles<T extends RememberedNetwork & { ageSeconds: number | null; isStale: boolean }>(
  items: T[],
  currentSnapshot: WindowsWifiSnapshot | null
): T[] {
  const connectedItem = findExactConnectedMapItem(items, currentSnapshot);
  const buckets = new Map<string, T[]>();

  for (const item of items) {
    if (connectedItem && item.key === connectedItem.key) {
      continue;
    }

    const groupKey = logicalMeshProfileKey(item.network);
    if (!groupKey) {
      continue;
    }

    buckets.set(groupKey, [...(buckets.get(groupKey) ?? []), item]);
  }

  const allowedKeysByGroup = new Map<string, Set<string>>();
  for (const [groupKey, groupItems] of buckets) {
    const maxRepresentatives = connectedItem ? 1 : 2;
    if (groupItems.length > maxRepresentatives) {
      allowedKeysByGroup.set(
        groupKey,
        new Set(selectMeshProfileMapRepresentatives(groupItems, maxRepresentatives).map((item) => item.key))
      );
    }
  }

  const result: T[] = [];
  for (const item of items) {
    if (connectedItem && item.key === connectedItem.key) {
      result.push(item);
      continue;
    }

    const groupKey = logicalMeshProfileKey(item.network);
    const allowedKeys = groupKey ? allowedKeysByGroup.get(groupKey) : null;
    if (!groupKey || !allowedKeys) {
      result.push(item);
      continue;
    }

    if (allowedKeys.has(item.key)) {
      result.push(item);
    }
  }

  return result;
}

function logicalMeshProfileKey(network: WindowsWifiNetwork): string | null {
  const ssid = normalizeSsid(network.ssid);
  const auth = normalizeIntelValue(network.authentication);
  const encryption = normalizeIntelValue(network.encryption);
  const protectedNetwork = Boolean(auth && !auth.includes('open'));
  if (!ssid || !protectedNetwork || !isLikelyRouterOrMesh(network)) {
    return null;
  }

  return `${ssid}|${auth}|${encryption}`;
}

function selectMeshProfileMapRepresentatives<T extends RememberedNetwork & { ageSeconds: number | null; isStale: boolean }>(
  items: T[],
  count: number
): T[] {
  return [...items]
    .sort((left, right) => meshProfileRepresentativeScore(right) - meshProfileRepresentativeScore(left))
    .slice(0, count);
}

function meshProfileRepresentativeScore(item: RememberedNetwork & { ageSeconds: number | null; isStale: boolean }): number {
  const signal = item.network.signal_percent ?? item.network.native_bss?.link_quality ?? 0;
  return (
    (item.isStale ? 0 : 10_000) +
    (isMapItemOld(item) ? 0 : 1_000) +
    signal * 10 +
    item.seenCount -
    item.missedScans * 5
  );
}

function clusterMapItems(
  items: Array<RememberedNetwork & { ageSeconds: number | null; isStale: boolean }>,
  zoom: number,
  currentSnapshot: WindowsWifiSnapshot | null,
  rangeKm: number
): MapDrawable[] {
  const radius = mapClusterRadius(zoom);
  const layoutContext = buildMapLayoutContext(items, currentSnapshot);
  const positionedItems: MapPositionedItem[] = items.map((item, index) => ({
    kind: 'item',
    id: item.key,
    item,
    index,
    position: applyRfSpreadToPosition(
      mapPosition(item.network, index, layoutContext, item.seenCount >= MAP_COORDINATE_FIX_OBSERVATIONS),
      rangeKm
    )
  }));

  if (shouldDisableMapClustering(zoom) || radius <= 0) {
    return positionedItems;
  }

  const clusters = clusterPositionedMapItems(positionedItems, radius);
  return clusters.flatMap((members) => buildMapDrawableFromClusterMembers(members));
}

function mapClusterRadius(zoom: number): number {
  if (shouldDisableMapClustering(zoom)) {
    return 0;
  }

  return Math.max(1.35, 7.4 / Math.max(0.32, zoom));
}

function shouldDisableMapClustering(zoom: number): boolean {
  return zoom >= MAP_UNCLUSTER_ZOOM_RF - 0.001;
}

function clusterPositionedMapItems(positionedItems: MapPositionedItem[], radius: number): MapPositionedItem[][] {
  const remaining = [...positionedItems].sort(compareMapPositionedItemsForClustering);
  const clusters: MapPositionedItem[][] = [];

  while (remaining.length > 0) {
    const seed = remaining.shift();
    if (!seed) {
      break;
    }

    const members = [seed];
    let expanded = true;
    while (expanded) {
      expanded = false;
      for (let index = remaining.length - 1; index >= 0; index -= 1) {
        const candidate = remaining[index];
        if (members.some((member) => distancePercent(member.position, candidate.position) <= radius)) {
          members.push(candidate);
          remaining.splice(index, 1);
          expanded = true;
        }
      }
    }

    clusters.push(members);
  }

  let merged = true;
  while (merged) {
    merged = false;
    for (let leftIndex = 0; leftIndex < clusters.length; leftIndex += 1) {
      const leftCenter = averageMapPosition(clusters[leftIndex].map((member) => member.position));
      for (let rightIndex = clusters.length - 1; rightIndex > leftIndex; rightIndex -= 1) {
        const rightCenter = averageMapPosition(clusters[rightIndex].map((member) => member.position));
        if (distancePercent(leftCenter, rightCenter) <= radius) {
          clusters[leftIndex] = [...clusters[leftIndex], ...clusters[rightIndex]];
          clusters.splice(rightIndex, 1);
          merged = true;
        }
      }
    }
  }

  return clusters;
}

function buildMapDrawableFromClusterMembers(members: MapPositionedItem[]): MapDrawable[] {
  if (members.length === 1) {
    return members;
  }

  const sortedMembers = members.sort(
    (left, right) => (right.item.network.signal_percent ?? -1) - (left.item.network.signal_percent ?? -1)
  );
  const memberItems = sortedMembers.map((member) => member.item);
  const strongestSignal = memberItems.reduce<number | null>((strongest, member) => {
    const signal = member.network.signal_percent;
    return signal === null ? strongest : Math.max(strongest ?? signal, signal);
  }, null);

  return [{
    kind: 'cluster',
    id: `cluster:${memberItems.map((member) => member.key).sort().join(':')}`,
    items: memberItems,
    position: averageMapPosition(sortedMembers.map((member) => member.position)),
    liveCount: memberItems.filter((member) => !member.isStale).length,
    reviewCount: memberItems.filter((member) => {
      const level = member.network.vulnerability_intel?.exposure_level;
      return level === 'review' || level === 'priority';
    }).length,
    strongestSignal
  }];
}

function averageMapPosition(positions: Array<{ x: number; y: number }>): { x: number; y: number } {
  const total = positions.reduce(
    (sum, position) => ({
      x: sum.x + position.x,
      y: sum.y + position.y
    }),
    { x: 0, y: 0 }
  );

  return {
    x: Math.round((total.x / positions.length) * 10) / 10,
    y: Math.round((total.y / positions.length) * 10) / 10
  };
}

function distancePercent(left: { x: number; y: number }, right: { x: number; y: number }): number {
  return Math.hypot(left.x - right.x, left.y - right.y);
}

function layoutMapDrawables(
  drawables: MapDrawable[],
  zoom: number,
  viewportSize: MapViewportSize = { width: 0, height: 0 }
): Map<string, { x: number; y: number }> {
  const bounds = mapLayoutBounds(zoom);
  const positions = drawables.map((drawable, index) => {
    const position = zoomMapPosition(drawable.position, zoom);
    const x = Math.round(clampLayoutValue(position.x, bounds.min, bounds.max) * 10) / 10;
    const y = Math.round(clampLayoutValue(position.y, bounds.min, bounds.max) * 10) / 10;
    return {
      id: drawable.id,
      index,
      x,
      y,
      anchorX: x,
      anchorY: y,
      radius: mapDrawableCollisionRadius(drawable, viewportSize)
    };
  });

  if (positions.length > 1) {
    resolveMapDrawableCollisions(positions, bounds, viewportSize);
  }

  return new Map(
    positions.map((position) => [
      position.id,
      {
        x: Math.round(clampLayoutValue(position.x, bounds.min, bounds.max) * 10) / 10,
        y: Math.round(clampLayoutValue(position.y, bounds.min, bounds.max) * 10) / 10
      }
    ])
  );
}

function resolveMapDrawableCollisions(
  positions: Array<{
    id: string;
    index: number;
    x: number;
    y: number;
    anchorX: number;
    anchorY: number;
    radius: number;
  }>,
  bounds: { min: number; max: number },
  viewportSize: MapViewportSize
): void {
  const centerRadius = rfCollisionRadiusPercent(MAP_RF_CENTER_COLLISION_RADIUS_PX, viewportSize);
  const anchorPull = positions.length > 48 ? 0.006 : 0.01;

  for (let iteration = 0; iteration < MAP_RF_COLLISION_ITERATIONS; iteration += 1) {
    let moved = false;

    for (let leftIndex = 0; leftIndex < positions.length; leftIndex += 1) {
      const left = positions[leftIndex];
      for (let rightIndex = leftIndex + 1; rightIndex < positions.length; rightIndex += 1) {
        const right = positions[rightIndex];
        const dx = right.x - left.x;
        const dy = right.y - left.y;
        const distance = Math.hypot(dx, dy);
        const minDistance = left.radius + right.radius;
        if (distance >= minDistance) {
          continue;
        }

        const angle = distance > 0.01 ? Math.atan2(dy, dx) : deterministicMapSeparationAngle(left.id, right.id);
        const overlap = (minDistance - Math.max(distance, 0.01)) / 2;
        const pushX = Math.cos(angle) * overlap;
        const pushY = Math.sin(angle) * overlap;
        left.x -= pushX;
        left.y -= pushY;
        right.x += pushX;
        right.y += pushY;
        moved = true;
      }
    }

    for (const position of positions) {
      const dx = position.x - 50;
      const dy = position.y - 50;
      const distance = Math.hypot(dx, dy);
      const minDistance = position.radius + centerRadius;
      if (distance < minDistance) {
        const angle = distance > 0.01 ? Math.atan2(dy, dx) : deterministicMapSeparationAngle(position.id, LOCAL_MAP_NODE_KEY);
        const push = minDistance - Math.max(distance, 0.01);
        position.x += Math.cos(angle) * push;
        position.y += Math.sin(angle) * push;
        moved = true;
      }

      position.x += (position.anchorX - position.x) * anchorPull;
      position.y += (position.anchorY - position.y) * anchorPull;
      position.x = clampLayoutValue(position.x, bounds.min, bounds.max);
      position.y = clampLayoutValue(position.y, bounds.min, bounds.max);
    }

    if (!moved && iteration > 10) {
      break;
    }
  }
}

function mapDrawableCollisionRadius(drawable: MapDrawable, viewportSize: MapViewportSize): number {
  const radiusPx = drawable.kind === 'cluster'
    ? MAP_RF_CLUSTER_COLLISION_RADIUS_PX
    : MAP_RF_NODE_COLLISION_RADIUS_PX;
  return rfCollisionRadiusPercent(
    radiusPx,
    viewportSize
  );
}

function rfCollisionRadiusPercent(radiusPx: number, viewportSize: MapViewportSize): number {
  const metricScalePx = Math.max(420, Math.min(viewportSize.width || 0, viewportSize.height || 0) || 620);
  return Math.max(4, (radiusPx / metricScalePx) * 100);
}

function deterministicMapSeparationAngle(leftId: string, rightId: string): number {
  return ((hashString(`${leftId}:${rightId}:layout-separation`) % 360) * Math.PI) / 180;
}

function mapLayoutBounds(zoom: number): { min: number; max: number } {
  const overflow = 18 + Math.max(0, zoom - 1) * 28;
  return {
    min: -overflow,
    max: 100 + overflow
  };
}

function clampLayoutValue(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

function zoomMapPosition(position: { x: number; y: number }, zoom: number): { x: number; y: number } {
  return {
    x: Math.round((50 + (position.x - 50) * zoom) * 10) / 10,
    y: Math.round((50 + (position.y - 50) * zoom) * 10) / 10
  };
}

function mapMetricPointToViewport(
  position: { x: number; y: number },
  viewportSize: MapViewportSize
): { x: number; y: number } {
  if (viewportSize.width <= 0 || viewportSize.height <= 0) {
    return position;
  }

  const metricScalePx = Math.min(viewportSize.width, viewportSize.height);
  return {
    x: Math.round((50 + ((position.x - 50) * metricScalePx) / viewportSize.width) * 10) / 10,
    y: Math.round((50 + ((position.y - 50) * metricScalePx) / viewportSize.height) * 10) / 10
  };
}

function mapConnectionLinkToViewport(link: MapConnectionLink, viewportSize: MapViewportSize): MapConnectionLink {
  return {
    ...link,
    start: mapMetricPointToViewport(link.start, viewportSize),
    end: mapMetricPointToViewport(link.end, viewportSize),
    avoidPoints: link.avoidPoints?.map((point) => mapMetricPointToViewport(point, viewportSize))
  };
}

function mapRingStyle(
  baseSizePercent: number,
  zoom: number,
  viewportSize: MapViewportSize
): CSSProperties {
  const size = Math.round(baseSizePercent * zoom * 10) / 10;
  if (viewportSize.width <= 0 || viewportSize.height <= 0) {
    return {
      width: `${size}%`,
      height: `${size}%`
    };
  }

  // Circular radar rings: node distances are laid out against the viewport's
  // min dimension (see mapMetricPointToViewport), so a circle of this diameter
  // matches the metric space exactly.
  const sizePx = Math.round(Math.min(viewportSize.width, viewportSize.height) * (size / 100));
  return {
    width: `${sizePx}px`,
    height: `${sizePx}px`
  };
}

function mapDistanceForPosition(position: { x: number; y: number }, rangeKm: number, zoom: number): number {
  const radiusPercent = Math.hypot(position.x - 50, position.y - 50);
  const farRadiusPercent = Math.max(1, MAP_FAR_RING_RADIUS_PERCENT * zoom);
  return Math.max(0, (radiusPercent / farRadiusPercent) * rangeKm);
}

function formatMapDistance(distanceKm: number): string {
  if (!Number.isFinite(distanceKm)) {
    return 'unknown';
  }

  if (distanceKm < 1) {
    return `${Math.max(1, Math.round(distanceKm * 1000))} m`;
  }

  return `${Math.round(distanceKm * 10) / 10} km`;
}

function parseCoordinate(value: string, min: number, max: number): number | null {
  const normalized = value.trim().replace(',', '.');
  if (!normalized) {
    return null;
  }

  const parsed = Number(normalized);
  if (!Number.isFinite(parsed) || parsed < min || parsed > max) {
    return null;
  }

  return parsed;
}

function extractCoordinatesFromText(value: string): { latitude: number; longitude: number } | null {
  let decoded = value.trim();
  try {
    decoded = decodeURIComponent(decoded);
  } catch {
    // Keep the raw text; copied URLs occasionally contain partial percent escapes.
  }

  const match =
    decoded.match(/@(-?\d{1,2}(?:\.\d+)?),\s*(-?\d{1,3}(?:\.\d+)?)(?:[,/?]|$)/) ??
    decoded.match(/\b(-?\d{1,2}\.\d{4,})\s*,\s*(-?\d{1,3}\.\d{4,})\b/);
  if (!match) {
    return null;
  }

  const latitude = Number(match[1]);
  const longitude = Number(match[2]);
  if (
    !Number.isFinite(latitude) ||
    !Number.isFinite(longitude) ||
    latitude < -90 ||
    latitude > 90 ||
    longitude < -180 ||
    longitude > 180
  ) {
    return null;
  }

  return { latitude, longitude };
}

function buildMapLayoutContext(
  items: Array<RememberedNetwork & { ageSeconds: number | null; isStale: boolean }>,
  currentSnapshot: WindowsWifiSnapshot | null
): MapLayoutContext {
  const groupCounts = new Map<string, number>();
  for (const item of items) {
    const key = mapLayoutGroupKey(item.network);
    groupCounts.set(key, (groupCounts.get(key) ?? 0) + 1);
  }
  const connectedItem = findConnectedMapItem(items, currentSnapshot);
  const connectedNetwork = connectedItem?.network ?? null;

  return {
    groupCounts,
    connectedGroupKey: connectedNetwork
      ? mapLayoutGroupKey(connectedNetwork)
      : currentSnapshot?.ssid
        ? mapLayoutSsidGroupKey(currentSnapshot.ssid)
        : null,
    connectedNetwork
  };
}

function mapPosition(
  network: WindowsWifiNetwork,
  index: number,
  context: MapLayoutContext,
  fixedCoordinate = false
): { x: number; y: number } {
  const key = rememberedNetworkKey(network) ?? `${network.ssid ?? 'network'}-${index}`;
  const groupKey = mapLayoutGroupKey(network);
  const groupCount = context.groupCounts.get(groupKey) ?? 1;
  const groupAngle = ((hashString(groupKey) % 360) * Math.PI) / 180;
  const memberUnit = (hashString(`${key}:member-angle`) % 10_000) / 10_000;
  const radialUnit = (hashString(`${key}:member-radius`) % 10_000) / 10_000;
  const groupFan = groupCount > 1 ? Math.min(Math.PI * 1.9, 0.55 + Math.sqrt(groupCount) * 0.62) : 0;
  const memberJitter = groupCount > 1 ? (memberUnit - 0.5) * groupFan : ((hashString(key) % 90) - 45) * (Math.PI / 180) * 0.16;
  const angle = groupAngle + memberJitter;
  const signal = fixedCoordinate
    ? fixedMapSignalForKey(key)
    : network.signal_percent ?? network.native_bss?.link_quality ?? 18;
  const boundedSignal = Math.min(100, Math.max(0, signal));
  const estimatedRadius = 8 + Math.pow((100 - boundedSignal) / 100, 1.35) * 40;
  const sameVenueCompression = groupCount > 1 ? 0.64 : 1;
  const connectedCompression = context.connectedGroupKey && groupKey === context.connectedGroupKey ? 0.72 : 1;
  const radiusCap = groupCount > 1 ? 42 : 48;
  const groupRadialSpread = groupCount > 1 ? Math.min(24, 5 + groupCount * 0.42) : 0;
  const radius = Math.min(
    radiusCap,
    Math.max(6, estimatedRadius * sameVenueCompression * connectedCompression + (radialUnit - 0.5) * groupRadialSpread)
  );
  const wobble = ((hashString(`${key}:wobble`) % 7) - 3) * (groupCount > 1 ? 0.24 : 0.65);

  return {
    x: clampPercent(50 + Math.cos(angle) * (radius + wobble)),
    y: clampPercent(50 + Math.sin(angle) * (radius + wobble))
  };
}

function fixedMapSignalForKey(key: string): number {
  return 46 + (hashString(`${key}:fixed-rf-radius`) % 38);
}

function mapLayoutGroupKey(network: WindowsWifiNetwork): string {
  const ssid = network.ssid?.trim();
  if (ssid) {
    return mapLayoutSsidGroupKey(ssid);
  }

  return network.mac_enrichment?.oui ?? network.mac_enrichment?.vendor ?? network.bssid ?? 'unknown';
}

function mapLayoutSsidGroupKey(ssid: string): string {
  const normalized = ssid
    .trim()
    .toLowerCase()
    .replace(/\b(premium|employees|employee|guest|guests|staff|corp|office|main|mesh|node|ext|extended|repeater)\b/g, ' ')
    .replace(/\b(2\.4|2g|5g|5ghz|5 ghz|6g|6ghz|6 ghz)\b/g, ' ')
    .replace(/[^a-z0-9]+/g, ' ')
    .trim()
    .replace(/\s+/g, ' ');

  return normalized || ssid.trim().toLowerCase();
}

function hashString(value: string): number {
  let hash = 0;

  for (let index = 0; index < value.length; index += 1) {
    hash = (hash * 31 + value.charCodeAt(index)) >>> 0;
  }

  return hash;
}

function clampPercent(value: number): number {
  return Math.min(92, Math.max(8, Math.round(value * 10) / 10));
}

function clampMapZoom(value: number): number {
  return Math.min(4, Math.max(0.35, Math.round(value * 100) / 100));
}

function adjustMapPanForZoom(
  pan: MapPan,
  fromZoom: number,
  toZoom: number,
  stageRect: DOMRect | null,
  anchor?: { clientX: number; clientY: number }
): MapPan {
  const ratio = toZoom / Math.max(0.01, fromZoom);
  const centerX = stageRect ? stageRect.width / 2 : 0;
  const centerY = stageRect ? stageRect.height / 2 : 0;
  const anchorX = stageRect && anchor ? anchor.clientX - stageRect.left : centerX;
  const anchorY = stageRect && anchor ? anchor.clientY - stageRect.top : centerY;
  const nextX = pan.x * ratio + (anchorX - centerX) * (1 - ratio);
  const nextY = pan.y * ratio + (anchorY - centerY) * (1 - ratio);

  return {
    x: clampMapPan(nextX, toZoom),
    y: clampMapPan(nextY, toZoom)
  };
}

function clampMapPan(value: number, zoom: number): number {
  const maxPan = Math.round(560 * Math.max(0, zoom - 0.82));
  return Math.min(maxPan, Math.max(-maxPan, Math.round(value)));
}

function shouldPreventFullscreenScrollLeak(target: EventTarget | null, deltaY: number): boolean {
  if (!(target instanceof Element)) {
    return true;
  }

  const panel = target.closest('.map-panel-fullscreen');
  if (!(panel instanceof HTMLElement)) {
    return true;
  }

  const scrollTarget = target.closest('.map-side-list, .map-panel-fullscreen');
  if (!(scrollTarget instanceof HTMLElement)) {
    return true;
  }

  const canScroll = scrollTarget.scrollHeight > scrollTarget.clientHeight + 1;
  if (!canScroll) {
    return true;
  }

  if (deltaY < 0) {
    return scrollTarget.scrollTop <= 0;
  }
  if (deltaY > 0) {
    return scrollTarget.scrollTop + scrollTarget.clientHeight >= scrollTarget.scrollHeight - 1;
  }

  return false;
}

function networkDeviceVisual(network: WindowsWifiNetwork): NetworkDeviceVisual {
  const ssid = network.ssid?.toLowerCase() ?? '';
  const hint = inferredDeviceHint(network).toLowerCase();
  const vendor = network.mac_enrichment?.vendor?.toLowerCase() ?? '';

  if (!network.ssid) {
    return DEVICE_VISUALS.hidden;
  }

  if (ssid.includes('print') || ssid.includes('laserjet') || hint.includes('printer')) {
    return DEVICE_VISUALS.printer;
  }

  if (isLikelyMobileHotspot(network)) {
    return DEVICE_VISUALS.hotspot;
  }

  if (ssid.startsWith('direct-') || hint.includes('wi-fi direct')) {
    return DEVICE_VISUALS.direct;
  }

  if (ssid.includes('polk') || ssid.includes('magnifi') || hint.includes('soundbar') || hint.includes('speaker')) {
    return DEVICE_VISUALS.speaker;
  }

  if (ssid.includes('mesh') || hint.includes('mesh')) {
    return DEVICE_VISUALS.mesh;
  }

  if (
    hint.includes('enterprise') ||
    hint.includes('access point') ||
    vendor.includes('hewlett packard enterprise') ||
    vendor.includes('fortinet')
  ) {
    return DEVICE_VISUALS.access;
  }

  if (
    hint.includes('router') ||
    hint.includes('mesh') ||
    hint.includes('gateway') ||
    hint.includes('range extender') ||
    vendor.includes('netgear') ||
    vendor.includes('tp-link') ||
    vendor.includes('sagemcom')
  ) {
    return DEVICE_VISUALS.router;
  }

  if (network.mac_enrichment?.address_scope === 'local') {
    return DEVICE_VISUALS.local;
  }

  // A BSSID broadcasting a named SSID with a global MAC IS an access point, even
  // when we can't identify the vendor/model. Default to the AP icon rather than
  // the generic "?" so unidentified routers/APs read as APs, not unknown devices.
  return DEVICE_VISUALS.access;
}

function mapNodeDeviceVisual(
  network: WindowsWifiNetwork,
  linkKind: MapConnectionLink['kind'] | null
): NetworkDeviceVisual {
  if (linkKind === 'mesh' || linkKind === 'mesh_peer') {
    return DEVICE_VISUALS.mesh;
  }

  return networkDeviceVisual(network);
}

function isLikelyMobileHotspot(network: WindowsWifiNetwork): boolean {
  const ssid = network.ssid?.toLowerCase() ?? '';
  const hint = inferredDeviceHint(network).toLowerCase();
  const vendor = network.mac_enrichment?.vendor?.toLowerCase() ?? '';
  return (
    hint.includes('mobile') ||
    hint.includes('phone') ||
    hint.includes('hotspot') ||
    ssid.includes('iphone') ||
    ssid.includes('ipad') ||
    ssid.includes('android') ||
    ssid.includes('galaxy') ||
    ssid.includes('pixel') ||
    ssid.includes('hotspot') ||
    vendor.includes('apple') ||
    vendor.includes('samsung')
  );
}

function mergeNearbyNetworkScan(
  currentNetworks: BaselineNetworksResult | null,
  nextNetworks: BaselineNetworksResult | null,
  currentFreshness: NetworkFreshnessState
): NetworkMergeResult {
  const nowMs = Date.now();
  const checkedAtUtc = new Date(nowMs).toISOString();

  if (!nextNetworks) {
    return {
      networks: null,
      freshness: {
        ...INITIAL_NETWORK_FRESHNESS,
        checkedAtUtc
      }
    };
  }

  const latestError = getNetworkSourceError(nextNetworks);

  if (currentNetworks && shouldRetainNetworkResult(currentNetworks, nextNetworks, currentFreshness, nowMs)) {
    return {
      networks: {
        ...currentNetworks,
        platform: nextNetworks.platform,
        host_id: nextNetworks.host_id,
        sources: nextNetworks.sources
      },
      freshness: {
        checkedAtUtc,
        acceptedAtUtc: currentFreshness.acceptedAtUtc ?? currentNetworks.ts_utc,
        latestScanAtUtc: nextNetworks.ts_utc,
        retainedLastGood: true,
        narrowScanCount: currentFreshness.narrowScanCount + 1,
        latestScanSsidCount: nextNetworks.network_count,
        latestScanBssidCount: nextNetworks.bssid_count,
        retainedSsidCount: currentNetworks.network_count,
        retainedBssidCount: currentNetworks.bssid_count,
        latestError
      }
    };
  }

  return {
    networks: nextNetworks,
    freshness: {
      checkedAtUtc,
      acceptedAtUtc: nextNetworks.bssid_count > 0 ? nextNetworks.ts_utc : null,
      latestScanAtUtc: nextNetworks.ts_utc,
      retainedLastGood: false,
      narrowScanCount: 0,
      latestScanSsidCount: nextNetworks.network_count,
      latestScanBssidCount: nextNetworks.bssid_count,
      retainedSsidCount: nextNetworks.network_count,
      retainedBssidCount: nextNetworks.bssid_count,
      latestError
    }
  };
}

function shouldRetainNetworkResult(
  currentNetworks: BaselineNetworksResult,
  nextNetworks: BaselineNetworksResult,
  currentFreshness: NetworkFreshnessState,
  nowMs: number
): boolean {
  if (currentNetworks.bssid_count === 0 || nextNetworks.bssid_count >= currentNetworks.bssid_count) {
    return false;
  }

  const acceptedAtMs = new Date(currentFreshness.acceptedAtUtc ?? currentNetworks.ts_utc).getTime();
  if (Number.isFinite(acceptedAtMs) && nowMs - acceptedAtMs > NETWORK_LAST_GOOD_HOLD_MS) {
    return false;
  }

  if (nextNetworks.bssid_count === 0) {
    return true;
  }

  if (currentNetworks.bssid_count >= 3 && nextNetworks.bssid_count <= 1) {
    return true;
  }

  if (currentNetworks.bssid_count < 5) {
    return false;
  }

  const retainedRatio = nextNetworks.bssid_count / currentNetworks.bssid_count;
  return nextNetworks.bssid_count <= currentNetworks.bssid_count - 3 && retainedRatio < 0.35;
}

function getNetworkSourceError(networks: BaselineNetworksResult): string | null {
  const unavailableSource = networks.sources.find(
    (source) => source.name === 'netsh_wlan_networks' && !source.available
  );

  if (!unavailableSource) {
    return null;
  }

  return unavailableSource.detail ?? `${formatSourceName(unavailableSource.name)} unavailable`;
}

function formatRunState(run: BaselineRunRecord): string {
  if (run.status === 'complete' && run.cancelled) {
    return 'cancelled';
  }

  return run.status;
}

function formatRunOption(run: BaselineRunRecord): string {
  const label = formatRunLabel(run);
  return run.cancelled ? `${label} (cancelled)` : label;
}

function formatRunStorage(run: BaselineRunRecord): string {
  if (run.storage === 'sqlite' || run.events_file?.startsWith('sqlite:')) {
    return 'SQLite';
  }

  return 'JSONL';
}

function formatRunLabel(run: BaselineRunRecord): string {
  return `${formatDateTime(run.started_at_utc)} | ${runIdTail(run.run_id)}`;
}

function runIdTail(runId: string): string {
  const trimmed = runId.trim();
  return trimmed.length <= 4 ? trimmed : trimmed.slice(-4);
}

function formatDiagnosticsCounts(bundle: BaselineDiagnosticsBundleRecord): string {
  if (!bundle.counts) {
    return 'unknown';
  }

  return `${bundle.counts.snapshots} snapshots, ${bundle.counts.events} events, ${bundle.counts.runs} runs, ${bundle.counts.alerts} alerts`;
}

function formatSigned(value: number): string {
  return value > 0 ? `+${value}` : String(value);
}

function valueOrUnknown(value: string | number | null | undefined): string {
  if (value === null || value === undefined || value === '') {
    return 'unknown';
  }

  return String(value);
}

async function readMonitorBridgeCapabilities(): Promise<{ ipc: { device_vulnerability_lookup?: boolean } } | null> {
  if (!window.monitor?.getBridgeCapabilities) {
    return null;
  }

  try {
    return await window.monitor.getBridgeCapabilities();
  } catch (error) {
    if (isMissingBridgeHandlerError(error)) {
      return null;
    }

    throw error;
  }
}

function formatMonitorBridgeError(error: unknown, channel: string): string {
  if (isMissingBridgeHandlerError(error)) {
    return missingBridgeHandlerMessage(channel);
  }

  return error instanceof Error ? error.message : String(error);
}

function isMissingBridgeHandlerError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return /No handler registered/i.test(message);
}

function missingBridgeHandlerMessage(channel: string): string {
  return `Monitor main process is stale: IPC channel ${channel} is not registered. Close all Monitor/Electron windows and restart npm run dev so the latest main/preload handlers are loaded.`;
}

function formatPercent(value: number | null): string {
  return value === null ? 'unknown' : `${value}%`;
}

function formatScanImpact(value: VulnerabilityScanCheckDefinition['impact']): string {
  switch (value) {
    case 'none':
      return 'no impact';
    case 'local_only':
      return 'local only';
    case 'low':
      return 'visible / low';
    case 'manual_disruptive':
      return 'runner required / disruptive';
  }
}

function sortVulnerabilityChecksForMode(
  _mode: VulnerabilityLookupMode,
  checks: VulnerabilityScanCheckDefinition[]
): VulnerabilityScanCheckDefinition[] {
  return [...checks].sort((left, right) => left.label.localeCompare(right.label));
}

function buildVulnerabilityScanPlanFromOptions(
  mode: VulnerabilityLookupMode,
  options: VulnerabilityLookupRunOptions
): VulnerabilityScanPlan {
  const selectedIds = new Set(
    (options.selectedCheckIds.length > 0 ? options.selectedCheckIds : defaultVulnerabilityScanCheckIds(mode))
      .map((id) => id.trim())
      .filter(Boolean)
  );
  const checks = sortVulnerabilityChecksForMode(
    mode,
    VULNERABILITY_SCAN_CHECK_DEFINITIONS.filter((check) => check.modes.includes(mode))
  ).map<VulnerabilityScanPlanCheck>((check) => ({
    id: check.id,
    label: check.label,
    description: check.description,
    selected: check.available && selectedIds.has(check.id),
    available: check.available,
    impact: check.impact,
    network_effect: check.networkEffect,
    blocked_reason: check.blockedReason
  }));

  return {
    mode,
    selected_check_ids: checks.filter((check) => check.selected).map((check) => check.id),
    checks,
    operator_note: options.operatorNote?.trim() || null
  };
}

function defaultVulnerabilityScanCheckIds(mode: VulnerabilityLookupMode): string[] {
  return VULNERABILITY_SCAN_CHECK_DEFINITIONS
    .filter((check) => check.modes.includes(mode) && check.available && check.defaultSelected)
    .map((check) => check.id);
}

function formatNumberList(values: number[], unit: string): string {
  return values.length === 0 ? 'unknown' : `${values.join(', ')} ${unit}`;
}

function formatBuckets(values: Array<{ value: string; count: number }>): string {
  return values.length === 0 ? 'none' : values.map((item) => `${item.value} ${item.count}`).join(', ');
}

function formatMacHint(network: WindowsWifiNetwork): string {
  const enrichment = network.mac_enrichment;
  const inferredHint = inferredDeviceHint(network);
  if (!enrichment) {
    return inferredHint === 'unknown device' ? 'Vendor unknown | lookup missing' : `Vendor unknown | ${inferredHint}`;
  }

  const vendor = enrichment.vendor ?? 'Vendor unknown';
  const hint = inferredHint === 'unknown device' ? '' : ` | ${inferredHint}`;
  return `${vendor}${hint} | ${enrichment.confidence}`;
}

function formatMapNodeRole(
  network: WindowsWifiNetwork,
  visual: NetworkDeviceVisual,
  linkKind: MapConnectionLink['kind'] | null
): string {
  if (linkKind === 'connected') {
    return 'CONN';
  }
  if (linkKind === 'mesh') {
    return 'MESH';
  }
  if (linkKind === 'memory') {
    return 'MEM';
  }

  const hint = inferredDeviceHint(network).toLowerCase();
  if (hint.includes('mesh')) {
    return 'MESH';
  }

  return visual.label;
}

function formatSecurityShort(network: WindowsWifiNetwork): string {
  const auth = network.authentication?.toLowerCase() ?? '';
  const encryption = network.encryption?.toLowerCase() ?? '';
  if (auth.includes('open') || encryption === 'none') {
    return 'OPEN';
  }
  if (auth.includes('wpa3')) {
    return 'WPA3';
  }
  if (auth.includes('wpa2')) {
    return 'WPA2';
  }
  if (auth.includes('wpa')) {
    return 'WPA';
  }
  if (auth.includes('wep')) {
    return 'WEP';
  }

  return 'SEC?';
}

function formatSecurityLabel(network: WindowsWifiNetwork): string {
  return `${formatSecurityShort(network)} | ${valueOrUnknown(network.authentication)} / ${valueOrUnknown(network.encryption)}`;
}

function mapSecurityVisualTone(network: WindowsWifiNetwork): MapSecurityVisualTone {
  const exposure = network.vulnerability_intel?.exposure_level ?? 'none';
  const summary = `${network.vulnerability_intel?.summary ?? ''} ${network.vulnerability_intel?.signals?.map((signal) => signal.label).join(' ') ?? ''}`.toLowerCase();
  if (exposure === 'priority' || summary.includes('evil') || summary.includes('rogue') || summary.includes('identity drift')) {
    return 'suspect';
  }

  const auth = network.authentication?.toLowerCase() ?? '';
  const encryption = network.encryption?.toLowerCase() ?? '';
  const posture = network.security_assessment?.posture;
  if (auth.includes('open') || encryption === 'none' || posture === 'open') {
    return 'open';
  }
  if (auth.includes('wep') || auth.includes('wpa-') || encryption.includes('tkip') || posture === 'obsolete' || posture === 'weak') {
    return 'legacy';
  }
  if (auth.includes('enterprise') || posture === 'enterprise') {
    return 'enterprise';
  }
  if (auth.includes('wpa3')) {
    return 'wpa3';
  }
  if (auth.includes('wpa2') || posture === 'standard') {
    return 'wpa2';
  }

  return 'unknown';
}

function isOpenWifiNetwork(network: WindowsWifiNetwork): boolean {
  const auth = network.authentication?.toLowerCase() ?? '';
  const encryption = network.encryption?.toLowerCase() ?? '';
  return auth.includes('open') || encryption === 'none';
}

function canRevealProfileSecret(network: WindowsWifiNetwork, currentSnapshot: WindowsWifiSnapshot | null): boolean {
  if (!isWifiSnapshotConnected(currentSnapshot) || !network.ssid || isOpenWifiNetwork(network)) {
    return false;
  }

  return normalizeSsid(network.ssid) === normalizeSsid(currentSnapshot.ssid);
}

function profileSecretMatchesNetwork(
  profileSecret: WifiProfileSecretResult | null,
  network: WindowsWifiNetwork
): boolean {
  const profileSsid = normalizeSsid(profileSecret?.ssid ?? null);
  const networkSsid = normalizeSsid(network.ssid);
  return profileSsid.length > 0 && profileSsid === networkSsid;
}

function inferredDeviceHint(network: WindowsWifiNetwork): string {
  const existingHint = network.mac_enrichment?.device_hint;
  if (existingHint) {
    return existingHint;
  }

  const ssid = network.ssid?.trim().toLowerCase() ?? '';
  const localMac = network.mac_enrichment?.address_scope === 'local';
  const infrastructure = network.network_type?.toLowerCase().includes('infrastructure') ?? false;
  const protectedNetwork = Boolean(network.authentication && !network.authentication.toLowerCase().includes('open'));

  if (
    ssid.includes('mesh') ||
    ssid.includes('router') ||
    ssid.includes('gateway')
  ) {
    return 'home router / mesh node';
  }

  if (localMac && infrastructure && protectedNetwork) {
    return 'router / mesh AP with local BSSID';
  }

  return 'unknown device';
}

function normalizeMacForCompare(value: string | null): string | null {
  if (!value) {
    return null;
  }

  const hex = value.replace(/[^a-fA-F0-9]/g, '').toLowerCase();
  return hex.length === 12 ? hex : null;
}

function formatBssidTail(value: string | null): string {
  const normalized = normalizeMacForCompare(value);
  if (!normalized) {
    return 'BSSID unknown';
  }

  return normalized.slice(-4).match(/.{2}/g)?.join(':') ?? normalized.slice(-4);
}

function summarizeVulnerabilityExposure(networks: WindowsWifiNetwork[]): Record<'none' | 'watch' | 'review' | 'priority', number> {
  const counts = {
    none: 0,
    watch: 0,
    review: 0,
    priority: 0
  };

  for (const network of networks) {
    const level = network.vulnerability_intel?.exposure_level ?? 'none';
    counts[level] += 1;
  }

  return counts;
}

function buildChannelCongestionBuckets(
  items: Array<RememberedNetwork & { ageSeconds: number | null; isStale: boolean }>
): ChannelCongestionBucket[] {
  const byChannel = new Map<string, Array<RememberedNetwork & { ageSeconds: number | null; isStale: boolean }>>();

  for (const item of items) {
    const channel = item.network.channel;
    if (channel === null || !Number.isFinite(channel)) {
      continue;
    }

    const band = normalizeChannelBand(item.network.band, channel);
    const id = channelBucketId(band, channel);
    byChannel.set(id, [...(byChannel.get(id) ?? []), item]);
  }

  const buckets = [...byChannel.entries()].map(([id, bucketItems]) => {
    const first = bucketItems[0];
    const channel = first?.network.channel ?? 0;
    const band = normalizeChannelBand(first?.network.band ?? null, channel);
    const liveItems = bucketItems.filter((item) => !item.isStale);
    const signals = liveItems
      .map((item) => item.network.signal_percent)
      .filter((signal): signal is number => typeof signal === 'number' && Number.isFinite(signal));
    const strongCount = liveItems.filter((item) => signalTier(item.network.signal_percent) === 'strong').length;
    const mediumCount = liveItems.filter((item) => signalTier(item.network.signal_percent) === 'medium').length;
    const weakCount = liveItems.filter((item) => signalTier(item.network.signal_percent) === 'weak').length;
    const utilizationPercent = maxNullable(bucketItems.map((item) => channelUtilizationPercent(item.network)));
    const overlapScore = channelOverlapScore(band, channel, items);
    const bssLoadCount = bucketItems.filter((item) => item.network.native_bss?.information_elements.has_bss_load).length;
    const congestionScore = channelCongestionScore({
      liveCount: liveItems.length,
      staleCount: bucketItems.length - liveItems.length,
      strongCount,
      mediumCount,
      weakCount,
      overlapScore,
      utilizationPercent,
      bssLoadCount
    });

    return {
      id,
      band,
      channel,
      items: bucketItems.sort((left, right) => {
        const liveDelta = Number(right.isStale) - Number(left.isStale);
        return liveDelta || (right.network.signal_percent ?? -1) - (left.network.signal_percent ?? -1);
      }),
      liveCount: liveItems.length,
      staleCount: bucketItems.length - liveItems.length,
      strongCount,
      mediumCount,
      weakCount,
      strongestSignal: signals.length ? Math.max(...signals) : null,
      averageSignal: signals.length ? Math.round(signals.reduce((total, signal) => total + signal, 0) / signals.length) : null,
      utilizationPercent,
      overlapScore,
      congestionScore,
      bssLoadCount
    } satisfies ChannelCongestionBucket;
  });

  return buckets.sort((left, right) => {
    const bandDelta = channelBandOrder(left.band) - channelBandOrder(right.band);
    return bandDelta || left.channel - right.channel;
  });
}

function summarizeChannelCongestion(buckets: ChannelCongestionBucket[]): {
  busiestBucket: ChannelCongestionBucket | null;
  quietestBucket: ChannelCongestionBucket | null;
  crowdedCount: number;
  bssLoadCount: number;
} {
  const sortedByScore = [...buckets].sort(
    (left, right) => right.congestionScore - left.congestionScore || right.liveCount - left.liveCount
  );
  return {
    busiestBucket: sortedByScore[0] ?? null,
    quietestBucket: [...buckets]
      .filter((bucket) => bucket.liveCount > 0)
      .sort((left, right) => left.congestionScore - right.congestionScore || left.liveCount - right.liveCount)[0] ?? null,
    crowdedCount: buckets.filter((bucket) => bucket.congestionScore >= 70).length,
    bssLoadCount: buckets.reduce((total, bucket) => total + bucket.bssLoadCount, 0)
  };
}

function groupChannelBucketsByBand(buckets: ChannelCongestionBucket[]): Array<[ChannelBand, ChannelCongestionBucket[]]> {
  const groups = new Map<ChannelBand, ChannelCongestionBucket[]>();
  for (const bucket of buckets) {
    groups.set(bucket.band, [...(groups.get(bucket.band) ?? []), bucket]);
  }

  return [...groups.entries()].sort(([left], [right]) => channelBandOrder(left) - channelBandOrder(right));
}

function normalizeChannelBand(band: string | null, channel: number | null): ChannelBand {
  const normalized = band?.toLowerCase() ?? '';
  if (normalized.includes('2.4') || normalized.includes('2 ghz')) {
    return '2.4 GHz';
  }
  if (normalized.includes('6')) {
    return '6 GHz';
  }
  if (normalized.includes('5')) {
    return '5 GHz';
  }
  if (channel !== null && channel >= 1 && channel <= 14) {
    return '2.4 GHz';
  }

  return 'Other';
}

function channelBucketId(band: ChannelBand, channel: number): string {
  return `${band}:${channel}`;
}

function channelBandOrder(band: ChannelBand): number {
  switch (band) {
    case '2.4 GHz':
      return 0;
    case '5 GHz':
      return 1;
    case '6 GHz':
      return 2;
    case 'Other':
      return 3;
  }
}

function signalTier(signal: number | null): 'strong' | 'medium' | 'weak' {
  if (signal !== null && signal >= 70) {
    return 'strong';
  }
  if (signal !== null && signal >= 40) {
    return 'medium';
  }
  return 'weak';
}

function channelOverlapScore(
  band: ChannelBand,
  channel: number,
  items: Array<RememberedNetwork & { ageSeconds: number | null; isStale: boolean }>
): number {
  let score = 0;

  for (const item of items) {
    if (item.isStale || item.network.channel === null || item.network.channel === channel) {
      continue;
    }

    const candidateBand = normalizeChannelBand(item.network.band, item.network.channel);
    if (candidateBand !== band) {
      continue;
    }

    const channelDistance = Math.abs(item.network.channel - channel);
    const signalWeight = Math.max(0.25, (item.network.signal_percent ?? 35) / 100);
    if (band === '2.4 GHz' && channelDistance <= 4) {
      score += ((5 - channelDistance) / 5) * signalWeight * 14;
    } else if ((band === '5 GHz' || band === '6 GHz') && channelDistance <= 8) {
      score += ((9 - channelDistance) / 9) * signalWeight * 5;
    }
  }

  return Math.min(35, Math.round(score));
}

function channelCongestionScore(input: {
  liveCount: number;
  staleCount: number;
  strongCount: number;
  mediumCount: number;
  weakCount: number;
  overlapScore: number;
  utilizationPercent: number | null;
  bssLoadCount: number;
}): number {
  const passivePressure =
    input.strongCount * 18 +
    input.mediumCount * 10 +
    input.weakCount * 4 +
    input.staleCount * 1 +
    input.overlapScore +
    input.bssLoadCount * 3;
  const utilization = input.utilizationPercent ?? 0;

  return clampScorePercent(Math.max(utilization, passivePressure));
}

function channelUtilizationPercent(network: WindowsWifiNetwork): number | null {
  const rawValue = network.raw['Channel Utilization'];
  if (!rawValue) {
    return null;
  }

  const parentheticalPercent = rawValue.match(/\(\s*(\d+(?:\.\d+)?)\s*%\s*\)/);
  const parsed = Number(parentheticalPercent?.[1] ?? rawValue.match(/\d+(?:\.\d+)?/)?.[0]);
  return Number.isFinite(parsed) ? clampScorePercent(parsed) : null;
}

function maxNullable(values: Array<number | null>): number | null {
  const numbers = values.filter((value): value is number => typeof value === 'number' && Number.isFinite(value));
  return numbers.length ? Math.max(...numbers) : null;
}

function clampScorePercent(value: number): number {
  return Math.min(100, Math.max(0, Math.round(value)));
}

function channelLabel(bucket: ChannelCongestionBucket): string {
  return `${bucket.band} ch ${bucket.channel}`;
}

function channelScoreTone(score: number): 'quiet' | 'active' | 'busy' | 'crowded' {
  if (score >= 70) {
    return 'crowded';
  }
  if (score >= 45) {
    return 'busy';
  }
  if (score >= 22) {
    return 'active';
  }
  return 'quiet';
}

function channelScoreLabel(score: number): string {
  switch (channelScoreTone(score)) {
    case 'crowded':
      return 'Crowded';
    case 'busy':
      return 'Busy';
    case 'active':
      return 'Active';
    case 'quiet':
      return 'Quiet';
  }
}

function channelCongestionReasons(bucket: ChannelCongestionBucket): string[] {
  const reasons = [
    `${bucket.liveCount} live BSSID${bucket.liveCount === 1 ? '' : 's'} on the exact channel.`,
    `${bucket.strongCount} strong, ${bucket.mediumCount} medium, and ${bucket.weakCount} weak live signal${bucket.liveCount === 1 ? '' : 's'} in the stack.`
  ];

  if (bucket.overlapScore > 0) {
    reasons.push(`Neighbor/overlap pressure adds ${bucket.overlapScore} points, mostly relevant on 2.4 GHz and wide 5/6 GHz channels.`);
  }

  if (bucket.utilizationPercent !== null) {
    reasons.push(`Windows reported channel utilization around ${bucket.utilizationPercent}%, so the score is at least that high.`);
  }

  if (bucket.bssLoadCount > 0) {
    reasons.push(`${bucket.bssLoadCount} AP${bucket.bssLoadCount === 1 ? '' : 's'} advertised BSS Load information elements.`);
  }

  if (bucket.staleCount > 0) {
    reasons.push(`${bucket.staleCount} recently remembered AP${bucket.staleCount === 1 ? '' : 's'} are stale and only lightly affect the score.`);
  }

  return reasons;
}

function summarizeNetworksForIntel(networks: WindowsWifiNetwork[]): BaselineNetworksResult['mac_summary'] {
  const vendors = new Map<string, number>();
  const deviceHints = new Map<string, number>();
  const unknownOuis = new Map<string, number>();
  const confidenceCounts: BaselineNetworksResult['mac_summary']['confidence_counts'] = {
    low: 0,
    medium: 0,
    high: 0
  };
  let knownVendorCount = 0;
  let unknownVendorCount = 0;
  let globalMacCount = 0;
  let localMacCount = 0;
  let multicastMacCount = 0;
  let invalidMacCount = 0;

  for (const network of networks) {
    const enrichment = network.mac_enrichment;

    if (!enrichment) {
      unknownVendorCount += 1;
      invalidMacCount += 1;
      continue;
    }

    confidenceCounts[enrichment.confidence] += 1;

    if (enrichment.vendor) {
      knownVendorCount += 1;
      incrementIntelBucket(vendors, enrichment.vendor);
    } else {
      unknownVendorCount += 1;
      if (enrichment.oui && enrichment.address_scope === 'global') {
        incrementIntelBucket(unknownOuis, enrichment.oui);
      }
    }

    if (enrichment.device_hint) {
      incrementIntelBucket(deviceHints, enrichment.device_hint);
    }

    switch (enrichment.address_scope) {
      case 'global':
        globalMacCount += 1;
        break;
      case 'local':
        localMacCount += 1;
        break;
      case 'multicast':
        multicastMacCount += 1;
        break;
      case 'invalid':
      case 'unknown':
        invalidMacCount += 1;
        break;
    }
  }

  return {
    source: 'renderer_ap_memory',
    known_vendor_count: knownVendorCount,
    unknown_vendor_count: unknownVendorCount,
    global_mac_count: globalMacCount,
    local_mac_count: localMacCount,
    multicast_mac_count: multicastMacCount,
    invalid_mac_count: invalidMacCount,
    confidence_counts: confidenceCounts,
    vendors: sortIntelBuckets(vendors),
    device_hints: sortIntelBuckets(deviceHints),
    unknown_ouis: sortIntelBuckets(unknownOuis),
    notes: ['Counts are calculated from AP Memory so filters, map, and Nearby APs use the same dataset.']
  };
}

function incrementIntelBucket(map: Map<string, number>, value: string): void {
  map.set(value, (map.get(value) ?? 0) + 1);
}

function sortIntelBuckets(map: Map<string, number>): Array<{ value: string; count: number }> {
  return [...map.entries()]
    .map(([value, count]) => ({ value, count }))
    .sort((left, right) => right.count - left.count || left.value.localeCompare(right.value));
}

function summarizeRememberedSsids(
  items: Array<RememberedNetwork & { ageSeconds: number | null; isStale: boolean }>
): Array<{ value: string; count: number }> {
  const ssids = new Map<string, number>();
  for (const item of items) {
    const ssid = item.network.ssid?.trim();
    if (ssid) {
      incrementIntelBucket(ssids, ssid);
    }
  }

  return sortIntelBuckets(ssids);
}

function buildNetworkIntelBucketFilter(
  kind: Extract<NetworkIntelFilterKind, 'ssid' | 'vendor' | 'deviceHint' | 'unknownOui'>,
  value: string
): NetworkIntelFilter {
  switch (kind) {
    case 'ssid':
      return { kind, value, label: `SSID: ${value}` };
    case 'vendor':
      return { kind, value, label: `Vendor: ${value}` };
    case 'deviceHint':
      return { kind, value, label: `Device hint: ${value}` };
    case 'unknownOui':
      return { kind, value, label: `Unknown OUI: ${value}` };
  }
}

function isSameNetworkIntelFilter(left: NetworkIntelFilter, right: NetworkIntelFilter): boolean {
  return left.kind === right.kind && normalizeIntelValue(left.value) === normalizeIntelValue(right.value);
}

function networkMatchesIntelFilter(network: WindowsWifiNetwork, filter: NetworkIntelFilter): boolean {
  const enrichment = network.mac_enrichment;

  switch (filter.kind) {
    case 'all':
      return true;
    case 'live':
    case 'stale':
    case 'review':
    case 'source':
    case 'newDevice':
    case 'localNetwork':
      return true;
    case 'ssid':
      return normalizeIntelValue(network.ssid) === normalizeIntelValue(filter.value);
    case 'knownVendor':
      return Boolean(enrichment?.vendor);
    case 'unknownVendor':
      return !enrichment?.vendor;
    case 'localMac':
      return enrichment?.address_scope === 'local';
    case 'highConfidence':
      return enrichment?.confidence === 'high';
    case 'vendor':
      return normalizeIntelValue(enrichment?.vendor) === normalizeIntelValue(filter.value);
    case 'deviceHint':
      return normalizeIntelValue(enrichment?.device_hint) === normalizeIntelValue(filter.value);
    case 'unknownOui':
      return (
        !enrichment?.vendor &&
        enrichment?.address_scope === 'global' &&
        normalizeIntelValue(enrichment?.oui) === normalizeIntelValue(filter.value)
      );
  }
}

function rememberedNetworkMatchesIntelFilter(
  item: RememberedNetwork & { ageSeconds: number | null; isStale: boolean },
  filter: NetworkIntelFilter,
  currentSnapshot: WindowsWifiSnapshot | null = null,
  allItems: Array<RememberedNetwork & { ageSeconds: number | null; isStale: boolean }> = []
): boolean {
  switch (filter.kind) {
    case 'live':
      return !item.isStale;
    case 'stale':
      return item.isStale;
    case 'review': {
      const exposure = item.network.vulnerability_intel?.exposure_level;
      return exposure === 'review' || exposure === 'priority';
    }
    case 'source':
      return isRememberedNetworkFromLatestSource(item);
    case 'newDevice':
      return isRememberedNetworkNewInInventory(item);
    case 'localNetwork':
      return rememberedNetworkInCurrentLocalNetwork(item, currentSnapshot, allItems);
    default:
      return networkMatchesIntelFilter(item.network, filter);
  }
}

function rememberedNetworkInCurrentLocalNetwork(
  item: RememberedNetwork & { ageSeconds: number | null; isStale: boolean },
  currentSnapshot: WindowsWifiSnapshot | null,
  allItems: Array<RememberedNetwork & { ageSeconds: number | null; isStale: boolean }> = []
): boolean {
  if (!isWifiSnapshotConnected(currentSnapshot)) {
    return false;
  }

  const currentBssid = normalizeMacForCompare(currentSnapshot.bssid);
  const itemBssid = normalizeMacForCompare(item.network.bssid);
  if (currentBssid && itemBssid === currentBssid) {
    return true;
  }

  const connectedItem = findExactConnectedMapItem(allItems, currentSnapshot);
  return Boolean(
    connectedItem &&
    item.key !== connectedItem.key &&
    !item.isStale &&
    !isMapItemOld(item) &&
    isLikelyMeshPeer(item.network, connectedItem.network, currentSnapshot)
  );
}

function isRememberedNetworkFromLatestSource(
  item: RememberedNetwork & { ageSeconds: number | null; isStale: boolean }
): boolean {
  return !item.isStale && item.missedScans === 0;
}

function normalizeIntelValue(value: string | null | undefined): string {
  return value?.trim().toLowerCase() ?? '';
}

function formatShortVendor(value: string | null | undefined): string {
  if (!value) {
    return 'Vendor unknown';
  }

  return value
    .replace(/,?\s*(inc\.?|ltd\.?|co\.?|corp\.?|corporation|systems)\b/gi, '')
    .replace(/\s+/g, ' ')
    .trim();
}

function deviceInsightTitle(kind: DeviceInsightKind): string {
  switch (kind) {
    case 'vendor':
      return 'Vendor Evidence';
    case 'exposure':
      return 'Exposure Review';
    case 'security':
      return 'Security Posture';
    case 'radio':
      return 'Radio Evidence';
  }
}

function formatVulnerabilityBadge(value: VulnerabilityIntelAssessment | undefined): string {
  switch (value?.exposure_level) {
    case 'priority':
      return 'Priority review';
    case 'review':
      return 'Review';
    case 'watch':
      return 'Watch';
    case 'none':
      return 'No signals';
    case undefined:
      return 'Exposure unknown';
  }
}

function formatNetworkSecurityBadge(network: WindowsWifiNetwork): string {
  const assessment = network.security_assessment;
  if (!assessment) {
    return 'Security unknown';
  }

  return `${formatDangerLevel(assessment.danger_level)} | ${formatAttackDifficulty(assessment.attack_difficulty)}`;
}

function formatAttackDifficulty(value: WifiSecurityAssessment['attack_difficulty'] | undefined): string {
  switch (value) {
    case 'none':
      return 'No Wi-Fi password';
    case 'low':
      return 'Low';
    case 'medium':
      return 'Password-dependent';
    case 'high':
      return 'High';
    case 'unknown':
    case undefined:
      return 'Unknown';
  }
}

function formatDangerLevel(value: WifiSecurityAssessment['danger_level'] | undefined): string {
  switch (value) {
    case 'high':
      return 'DANGER';
    case 'medium':
      return 'WATCH';
    case 'low':
      return 'LOW';
    case undefined:
      return 'UNKNOWN';
  }
}

function toDomId(value: string): string {
  return value.replace(/[^a-zA-Z0-9_-]+/g, '-');
}

function sourceDescriptorEnabled(descriptor: SourceDescriptor, controls: SourceControls): boolean {
  return descriptor.key === 'wifiStatus' ? true : controls[descriptor.key];
}

function isCollectorSourceStatus(source: CollectorSourceStatus | undefined): source is CollectorSourceStatus {
  return Boolean(source);
}

function mergeSourceStatuses(sources: CollectorSourceStatus[]): CollectorSourceStatus[] {
  const merged = new Map<CollectorSourceStatus['name'], CollectorSourceStatus>();

  for (const source of sources) {
    const existing = merged.get(source.name);
    if (!existing) {
      merged.set(source.name, source);
      continue;
    }

    merged.set(source.name, {
      ...source,
      available: existing.available || source.available,
      detail: source.detail ?? existing.detail
    });
  }

  return [...merged.values()];
}

function formatSourceName(name: CollectorSourceStatus['name']): string {
  switch (name) {
    case 'windows_wlan_autoconfig_operational':
      return 'WLAN AutoConfig';
    case 'windows_native_bss_list':
      return 'Native BSS list';
    case 'windows_native_wifi_scan':
      return 'Native Wi-Fi scan';
    case 'netsh_wlan_interfaces':
      return 'Interface snapshot';
    case 'netsh_wlan_networks':
      return 'Nearby AP list';
    case 'platform_adapter':
      return 'Platform adapter';
  }
}

function latestTimestamp(events: Array<{ ts_utc: string }>): string | null {
  let newest: string | null = null;
  let newestMs = Number.NEGATIVE_INFINITY;

  for (const event of events) {
    const eventMs = new Date(event.ts_utc).getTime();
    if (Number.isFinite(eventMs) && eventMs > newestMs) {
      newestMs = eventMs;
      newest = event.ts_utc;
    }
  }

  return newest;
}

function observationKey(observation: BaselineRunObservation, index: number): string {
  return [
    observation.observation_type,
    observation.ts_utc,
    observation.bssid ?? observation.ssid ?? 'target',
    observation.previous_value ?? 'previous',
    observation.current_value ?? 'current',
    index
  ].join('|');
}

function alertKey(alert: DetectorAlert, index: number): string {
  return [
    alert.alert_type,
    alert.window_start_utc,
    alert.window_end_utc,
    alert.client ?? 'client',
    alert.ssid ?? 'ssid',
    index
  ].join('|');
}

function timelineEventKey(event: ClientTimelineEvent, index: number): string {
  return [
    event.record_id ?? event.event_id,
    event.ts_utc,
    event.action,
    event.client ?? 'client',
    index
  ].join('|');
}

function formatAlertTitle(type: DetectorAlert['alert_type']): string {
  switch (type) {
    case 'reconnect_loop':
      return 'Reconnect Loop';
  }
}

function formatAlertReason(alert: DetectorAlert): string {
  switch (alert.alert_type) {
    case 'reconnect_loop':
      return `The detector saw ${alert.cycle_count} Windows Wi-Fi connect/security cycle(s) between ${formatDateTime(alert.window_start_utc)} and ${formatDateTime(alert.window_end_utc)} for ${valueOrUnknown(alert.client)} on ${valueOrUnknown(alert.ssid)}. This is a correlation signal, not proof of an attack; normal roaming, weak signal, AP restart, driver reset, sleep/wake, or manual reconnect can produce the same pattern.`;
  }
}

function wlanEventKey(event: WindowsWifiEvent, index: number): string {
  return [event.record_id ?? event.event_id, event.ts_utc, event.local_mac ?? 'client', index].join('|');
}

function formatLifecycleAction(action: ClientTimelineEvent['action']): string {
  switch (action) {
    case 'connected':
      return 'Connected';
    case 'disconnected':
      return 'Disconnected';
    case 'association_started':
      return 'Association started';
    case 'association_succeeded':
      return 'Association succeeded';
    case 'association_failed':
      return 'Association failed';
    case 'security_started':
      return 'Security started';
    case 'security_succeeded':
      return 'Security succeeded';
    case 'security_stopped':
      return 'Security stopped';
    case 'other':
      return 'Other WLAN event';
  }
}

function formatWlanEventTitle(eventId: number): string {
  switch (eventId) {
    case 8000:
      return 'Event 8000: Connection started';
    case 8001:
      return 'Event 8001: Connected';
    case 11000:
      return 'Event 11000: Association started';
    case 11001:
      return 'Event 11001: Association succeeded';
    case 11004:
      return 'Event 11004: Security stopped';
    case 11005:
      return 'Event 11005: Security succeeded';
    case 11010:
      return 'Event 11010: Security started';
    default:
      return `Event ${eventId}`;
  }
}

function formatObservationTitle(type: BaselineRunObservation['observation_type']): string {
  switch (type) {
    case 'state_change':
      return 'Wi-Fi State Changed';
    case 'bssid_change':
      return 'Connected BSSID Changed';
    case 'channel_change':
      return 'Connected Channel Changed';
    case 'rssi_drop':
      return 'RSSI Drop';
    case 'weak_signal':
      return 'Weak Signal';
    case 'nearby_bssid_added':
      return 'Nearby BSSID Appeared';
    case 'nearby_bssid_removed':
      return 'Nearby BSSID Disappeared';
    case 'nearby_security_changed':
      return 'Nearby Security Changed';
    case 'nearby_channel_changed':
      return 'Nearby Channel Changed';
    case 'nearby_signal_drop':
      return 'Nearby Signal Drop';
    case 'nearby_high_utilization':
      return 'High Channel Utilization';
  }
}

function formatObservationRiskLabel(severity: BaselineRunObservation['severity']): string {
  switch (severity) {
    case 'high':
      return 'DANGER';
    case 'medium':
      return 'WATCH';
    case 'low':
      return 'LOW';
  }
}

function formatObservationReason(observation: BaselineRunObservation): string {
  switch (observation.observation_type) {
    case 'state_change':
      return `The Windows snapshot changed adapter state from ${valueOrUnknown(observation.previous_value)} to ${valueOrUnknown(observation.current_value)}. This can explain reconnect symptoms, but it can also be normal roaming, sleep, AP restart, or user action.`;
    case 'bssid_change':
      return `The connected AP BSSID changed from ${valueOrUnknown(observation.previous_value)} to ${valueOrUnknown(observation.current_value)}. This is worth checking when it lines up with disconnects, but normal roaming or band steering can cause it.`;
    case 'channel_change':
      return `The connected channel changed from ${valueOrUnknown(observation.previous_value)} to ${valueOrUnknown(observation.current_value)}. The detector marks it because channel changes can coincide with roaming or AP changes, not because it proves an attack.`;
    case 'rssi_drop':
      return `Signal quality dropped sharply between snapshots. A big RSSI drop can cause disconnect loops, but movement, walls, antenna position, load, or ordinary RF fading are common explanations.`;
    case 'weak_signal':
      return `The adapter reported weak signal during the run. Weak signal can create reconnect symptoms by itself, so it is highlighted as context before blaming hostile activity.`;
    case 'nearby_bssid_added':
      return `A strong nearby BSSID appeared in the Windows scan. It may be a real environment change, a scan timing artifact, movement, or an AP that was simply missed before.`;
    case 'nearby_bssid_removed':
      return `A strong nearby BSSID disappeared from a later Windows scan. The detector marks it because sudden visibility changes can matter, but one missing scan can also be normal scan coverage or beacon timing.`;
    case 'nearby_security_changed':
      return `Windows saw different security metadata for the same nearby SSID/BSSID area. That can be suspicious if repeated, but mixed WPA modes, AP config, or scan/parser variance can also explain it.`;
    case 'nearby_channel_changed':
      return `A nearby BSSID moved from channel ${valueOrUnknown(observation.previous_value)} to ${valueOrUnknown(observation.current_value)}. This can happen from DFS/channel planning and should be correlated with client events.`;
    case 'nearby_signal_drop':
      return `A nearby BSSID signal dropped between scans. The detector flags large drops as environmental evidence, but they are weak by themselves without matching WLAN lifecycle events.`;
    case 'nearby_high_utilization':
      return `Windows reported high channel utilization for this nearby BSSID. Heavy airtime usage can cause symptoms, but it can also just be ordinary venue load.`;
  }
}

function formatRssi(value: number | null): string {
  return value === null ? 'unknown' : `${value} dBm`;
}

function formatFrequency(value: number | null | undefined): string {
  if (value === null || value === undefined) {
    return 'unknown';
  }

  return `${value} kHz (${(value / 1_000_000).toFixed(3)} GHz)`;
}

function formatBeaconPeriod(value: number | null | undefined): string {
  if (value === null || value === undefined) {
    return 'unknown';
  }

  return `${value} TU`;
}

function formatCapability(value: number | null | undefined): string {
  if (value === null || value === undefined) {
    return 'unknown';
  }

  return `0x${value.toString(16).padStart(4, '0')}`;
}

function formatBoolean(value: boolean | null | undefined): string {
  if (value === null || value === undefined) {
    return 'unknown';
  }

  return value ? 'yes' : 'no';
}

function formatNativeIeSummary(summary: WifiInformationElementSummary): string {
  const flags = [
    summary.has_rsn ? 'RSN' : null,
    summary.has_wpa ? 'WPA vendor IE' : null,
    summary.has_bss_load ? 'BSS load' : null,
    summary.has_country ? 'Country' : null,
    summary.has_ht ? 'HT' : null,
    summary.has_vht ? 'VHT' : null,
    summary.has_he ? 'HE' : null,
    summary.has_eht ? 'EHT' : null
  ].filter((value): value is string => Boolean(value));

  const names = summary.names.slice(0, 10);
  const hiddenCount = Math.max(0, summary.names.length - names.length);
  const labels = [...flags, ...names].filter((value, index, values) => values.indexOf(value) === index);
  const suffix = hiddenCount > 0 ? `, ${hiddenCount} more` : '';

  return `${summary.element_count} IEs / ${summary.byte_length} bytes: ${labels.length > 0 ? labels.join(', ') : 'none'}${suffix}`;
}

function formatObservationSignal(observation: BaselineRunObservation): string {
  if (observation.rssi_dbm !== null) {
    return formatRssi(observation.rssi_dbm);
  }

  if (observation.signal_percent !== null) {
    return `${observation.signal_percent}%`;
  }

  return 'unknown';
}

function formatRates(receive: number | null, transmit: number | null): string {
  if (receive === null && transmit === null) {
    return 'unknown';
  }

  return `${valueOrUnknown(receive)} down / ${valueOrUnknown(transmit)} up Mbps`;
}

function formatSecurity(authentication: string | null, cipher: string | null): string {
  if (!authentication && !cipher) {
    return 'unknown';
  }

  return [authentication, cipher].filter(Boolean).join(' / ');
}

function formatDateTime(value: string | null): string {
  if (!value) {
    return 'unknown';
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return new Intl.DateTimeFormat(undefined, {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  }).format(date);
}

function formatTimeOnly(value: string | null): string {
  if (!value) {
    return 'unknown';
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return new Intl.DateTimeFormat(undefined, {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  }).format(date);
}

function formatAlertWindow(alert: DetectorAlert): string {
  const startMs = new Date(alert.window_start_utc).getTime();
  const endMs = new Date(alert.window_end_utc).getTime();
  if (!Number.isFinite(startMs) || !Number.isFinite(endMs)) {
    return formatDateTime(alert.ts_utc);
  }

  if (startMs === endMs) {
    return formatDateTime(alert.window_start_utc);
  }

  const sameLocalDate = new Date(alert.window_start_utc).toDateString() === new Date(alert.window_end_utc).toDateString();
  return sameLocalDate
    ? `${formatDateTime(alert.window_start_utc)} - ${formatTimeOnly(alert.window_end_utc)}`
    : `${formatDateTime(alert.window_start_utc)} - ${formatDateTime(alert.window_end_utc)}`;
}

function formatAlertWindowDuration(alert: DetectorAlert): string {
  const startMs = new Date(alert.window_start_utc).getTime();
  const endMs = new Date(alert.window_end_utc).getTime();
  if (!Number.isFinite(startMs) || !Number.isFinite(endMs) || endMs < startMs) {
    return 'unknown';
  }

  return formatDuration(Math.max(0, Math.round((endMs - startMs) / 1000)));
}

function secondsSince(value: string | null, nowMs: number): number | null {
  if (!value) {
    return null;
  }

  const valueMs = new Date(value).getTime();
  if (!Number.isFinite(valueMs)) {
    return null;
  }

  return Math.max(0, Math.floor((nowMs - valueMs) / 1000));
}

function formatAge(value: number | null): string {
  if (value === null) {
    return 'unknown';
  }

  if (value < 2) {
    return 'now';
  }

  return `${formatDuration(value)} ago`;
}

function formatDuration(value: number | null): string {
  if (value === null) {
    return 'unknown';
  }

  if (value < 60) {
    return `${value}s`;
  }

  const minutes = Math.floor(value / 60);
  const seconds = value % 60;
  return seconds === 0 ? `${minutes}m` : `${minutes}m ${seconds}s`;
}

function formatConnectivitySummary(state: ConnectivityCheckState, ageSeconds: number | null): string {
  if (state.loading) {
    return 'checking internet path...';
  }

  if (!state.result) {
    return state.error ? 'check failed' : 'not checked';
  }

  const parts = [
    formatConnectivityStatus(state.result.status),
    state.result.download_mbps === null ? 'speed unknown' : `${state.result.download_mbps} Mbps down`,
    state.result.latency_ms === null ? 'latency unknown' : `${state.result.latency_ms} ms`,
    ageSeconds === null ? null : `checked ${formatAge(ageSeconds)}`
  ].filter(Boolean);

  return parts.join(' | ');
}

function formatConnectivityStatus(value: ConnectivityCheckResult['status']): string {
  switch (value) {
    case 'online':
      return 'online';
    case 'degraded':
      return 'degraded';
    case 'offline':
      return 'offline';
  }
}

function formatHourLabel(hour: number): string {
  return `${String(hour).padStart(2, '0')}:00`;
}

function formatList(values: Array<string | number>): string {
  return values.length === 0 ? 'unknown' : values.join(', ');
}

function formatCounts(values: Record<string, number>): string {
  const entries = Object.entries(values);
  if (entries.length === 0) {
    return 'unknown';
  }

  return entries.map(([name, count]) => `${name}: ${count}`).join(', ');
}

function formatNumericSummary(summary: NumericSummary | null, unit: string): string {
  if (!summary) {
    return 'unknown';
  }

  return `last ${summary.last}${unit}, avg ${summary.avg}${unit}, range ${summary.min}..${summary.max}${unit}`;
}

function firstLine(rawMessage: string): string {
  return (
    rawMessage
      .split(/\r?\n/)
      .map((line) => line.trim())
      .find(Boolean) ?? 'WLAN AutoConfig event'
  );
}
