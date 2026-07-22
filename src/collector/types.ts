export type CollectorSourceName =
  | 'radiochron_native_status'
  | 'radiochron_native_wifi_scan'
  | 'radiochron_native_bss_list'
  | 'radiochron_native_networks'
  | 'platform_history'
  | 'windows_wlan_autoconfig_operational'
  | 'windows_native_bss_list'
  | 'windows_native_wifi_scan'
  | 'netsh_wlan_interfaces'
  | 'netsh_wlan_networks'
  | 'platform_adapter';

export interface CollectorSourceStatus {
  name: CollectorSourceName;
  available: boolean;
  detail: string | null;
}

export interface BaseCollectorEvent {
  schema: string;
  event_type: string;
  ts_utc: string;
  source: 'baseline' | 'system' | 'detector';
  run_id: string;
  host_id: string;
}

export interface WindowsWifiSnapshot extends BaseCollectorEvent {
  schema: 'wifi.windows_baseline.v1';
  event_type: 'windows_wifi_snapshot';
  adapter: string | null;
  interface_name: string | null;
  interface_guid: string | null;
  physical_address: string | null;
  ipv4_addresses?: string[];
  ipv6_addresses?: string[];
  default_gateway?: string | null;
  dns_servers?: string[];
  state: string | null;
  ssid: string | null;
  bssid: string | null;
  band: string | null;
  channel: number | null;
  radio_type: string | null;
  authentication: string | null;
  cipher: string | null;
  receive_mbps: number | null;
  transmit_mbps: number | null;
  signal_percent: number | null;
  rssi_dbm: number | null;
  raw: Record<string, string>;
}

export interface WindowsWifiEvent extends BaseCollectorEvent {
  schema: 'wifi.windows_baseline.v1';
  event_type: 'windows_wifi_event';
  event_id: number;
  record_id: number | null;
  provider_name: string | null;
  level: string | null;
  adapter: string | null;
  interface_guid: string | null;
  local_mac: string | null;
  ssid: string | null;
  bss_type: string | null;
  message_fields: Record<string, string>;
  raw_message: string;
}

export interface WindowsWifiNetwork extends BaseCollectorEvent {
  schema: 'wifi.windows_baseline.v1';
  event_type: 'windows_wifi_network';
  interface_name: string | null;
  ssid: string | null;
  network_type: string | null;
  authentication: string | null;
  encryption: string | null;
  bssid: string | null;
  signal_percent: number | null;
  radio_type: string | null;
  band: string | null;
  channel: number | null;
  basic_rates_mbps: number[];
  other_rates_mbps: number[];
  native_bss?: WindowsNativeBssDetails;
  mac_enrichment?: MacEnrichment;
  security_assessment?: WifiSecurityAssessment;
  vulnerability_intel?: VulnerabilityIntelAssessment;
  raw: Record<string, string>;
}

export interface WindowsNativeBssDetails {
  interface_guid: string | null;
  interface_description: string | null;
  bss_type: string | null;
  phy_type: string | null;
  rssi_dbm: number | null;
  link_quality: number | null;
  center_frequency_khz: number | null;
  beacon_period_tu: number | null;
  in_reg_domain: boolean | null;
  capability_information: number | null;
  timestamp: string | null;
  host_timestamp: string | null;
  rates_mbps: number[];
  information_elements: WifiInformationElementSummary;
}

export interface WifiInformationElementSummary {
  byte_length: number;
  element_count: number;
  element_ids: number[];
  names: string[];
  extension_ids: number[];
  vendor_ouis: string[];
  has_rsn: boolean;
  has_wpa: boolean;
  has_bss_load: boolean;
  has_country: boolean;
  has_ht: boolean;
  has_vht: boolean;
  has_he: boolean;
  has_eht: boolean;
}

export interface WindowsNativeBssEntry {
  interface_guid: string | null;
  interface_description: string | null;
  ssid: string | null;
  bssid: string | null;
  native_bss: WindowsNativeBssDetails;
}

export interface WindowsNativeBssResult {
  source: CollectorSourceStatus;
  entries: WindowsNativeBssEntry[];
}

export interface WifiSecurityAssessment {
  posture: 'open' | 'obsolete' | 'weak' | 'standard' | 'strong' | 'enterprise' | 'unknown';
  attack_difficulty: 'none' | 'low' | 'medium' | 'high' | 'unknown';
  danger_level: 'low' | 'medium' | 'high';
  label: string;
  summary: string;
  notes: string[];
}

export interface VulnerabilityIntelReference {
  label: string;
  url: string;
}

export interface VulnerabilityIntelSignal {
  id: string;
  label: string;
  severity: 'info' | 'low' | 'medium' | 'high';
  confidence: 'low' | 'medium' | 'high';
  summary: string;
  evidence: string[];
  references: VulnerabilityIntelReference[];
}

export interface VulnerabilityIntelAssessment {
  source: 'local_vulnerability_seed.v1';
  exposure_level: 'none' | 'watch' | 'review' | 'priority';
  confidence: 'low' | 'medium' | 'high';
  summary: string;
  signals: VulnerabilityIntelSignal[];
  notes: string[];
}

export type VulnerabilityLookupMode = 'passive';

export interface VulnerabilityScanPlanCheck {
  id: string;
  label: string;
  description: string;
  selected: boolean;
  available: boolean;
  impact: 'none' | 'local_only' | 'low' | 'manual_disruptive';
  network_effect: string;
  blocked_reason: string | null;
}

export interface VulnerabilityScanPlan {
  mode: VulnerabilityLookupMode;
  selected_check_ids: string[];
  checks: VulnerabilityScanPlanCheck[];
  operator_note: string | null;
}

export interface DeviceInventoryAlert {
  alert_type: 'identity_mac_changed';
  severity: 'low' | 'medium' | 'high';
  summary: string;
  ssid: string | null;
  current_bssid: string | null;
  previous_bssid: string | null;
  evidence: string[];
  created_at_utc: string;
}

export interface DeviceInventoryPersistenceResult {
  stored_devices: number;
  stored_observations: number;
  stored_vendors: number;
  scan_location: ScanLocationRecord | null;
  alerts: DeviceInventoryAlert[];
}

export interface DeviceVulnerabilityLookupResult {
  mode: VulnerabilityLookupMode;
  saved: boolean;
  scan_id: string;
  status: 'saved' | 'failed';
  summary: string;
  scan_plan: VulnerabilityScanPlan | null;
  vulnerability_intel: VulnerabilityIntelAssessment | null;
  alerts: DeviceInventoryAlert[];
  database_file: string | null;
  error: string | null;
}

export interface DeviceHistoryHourBucket {
  hour: number;
  count: number;
}

export interface DeviceHistoryRecord {
  bssid: string;
  ssid: string | null;
  vendor: string | null;
  device_hint: string | null;
  mac_scope: string | null;
  oui: string | null;
  first_seen_utc: string;
  last_seen_utc: string;
  seen_count: number;
  observation_count: number;
  active_hours: DeviceHistoryHourBucket[];
  channels: number[];
  bands: string[];
  latest_channel: number | null;
  latest_band: string | null;
  latest_signal_percent: number | null;
  strongest_signal_percent: number | null;
  average_signal_percent: number | null;
  radio_location_label: string;
  is_new: boolean;
  vulnerability_exposure: VulnerabilityIntelAssessment['exposure_level'] | null;
  security_label: string | null;
}

export interface ScanLocationInput {
  latitude: number;
  longitude: number;
  source: 'browser' | 'manual';
  label?: string | null;
}

export interface ScanLocationRecord {
  id: number;
  location_key: string;
  label: string | null;
  latitude: number;
  longitude: number;
  source: 'browser' | 'manual';
  first_seen_utc: string;
  last_seen_utc: string;
  scan_count: number;
}

export interface DeviceMetricRecord {
  bssid: string;
  location_id: number | null;
  location_key: string;
  ssid: string | null;
  first_seen_utc: string;
  last_seen_utc: string;
  seen_count: number;
  signal_min_percent: number | null;
  signal_max_percent: number | null;
  signal_avg_percent: number | null;
  latest_signal_percent: number | null;
  strongest_signal_percent: number | null;
  average_signal_percent: number | null;
  latest_channel: number | null;
  channels: number[];
  bands: string[];
  authentication: string | null;
  encryption: string | null;
  last_payload_hash: string | null;
  latest_network?: WindowsWifiNetwork | null;
}

export interface DeviceHistoryResult {
  database_file: string | null;
  generated_at_utc: string;
  new_window_hours: number;
  total_devices: number;
  records: DeviceHistoryRecord[];
}

export interface ScanLocationsResult {
  database_file: string | null;
  generated_at_utc: string;
  locations: ScanLocationRecord[];
  metrics: DeviceMetricRecord[];
}

export interface MacEnrichment {
  normalized_mac: string | null;
  oui: string | null;
  vendor: string | null;
  address_scope: 'global' | 'local' | 'multicast' | 'invalid' | 'unknown';
  device_hint: string | null;
  confidence: 'low' | 'medium' | 'high';
  source: string;
  notes: string[];
}

export interface MacIntelligenceBucket {
  value: string;
  count: number;
}

export interface MacIntelligenceSummary {
  source: string;
  known_vendor_count: number;
  unknown_vendor_count: number;
  global_mac_count: number;
  local_mac_count: number;
  multicast_mac_count: number;
  invalid_mac_count: number;
  confidence_counts: Record<MacEnrichment['confidence'], number>;
  vendors: MacIntelligenceBucket[];
  device_hints: MacIntelligenceBucket[];
  unknown_ouis: MacIntelligenceBucket[];
  notes: string[];
}

export interface DeviceIntelligenceOverride {
  id: number | null;
  match_type: 'bssid' | 'oui' | 'ssid';
  match_value: string;
  ssid: string | null;
  bssid: string | null;
  oui: string | null;
  vendor: string | null;
  device_hint: string | null;
  device_role: string | null;
  model: string | null;
  confidence: 'low' | 'medium' | 'high';
  is_mesh: boolean | null;
  exposure_level: VulnerabilityIntelAssessment['exposure_level'] | null;
  vulnerability_summary: string | null;
  vulnerability_references: string[];
  notes: string[];
  source: string;
  raw_json: Record<string, unknown> | null;
  created_at_utc: string | null;
  updated_at_utc: string;
}

export type AiExternalProvider = 'codex' | 'claude';
export type DeviceIntelligenceUpdateProvider = 'smart' | AiExternalProvider;

export interface DeviceIntelligenceUpdateResult {
  provider: DeviceIntelligenceUpdateProvider;
  available: boolean;
  saved: boolean;
  override: DeviceIntelligenceOverride | null;
  job: AiProviderJob;
  raw_output: string | null;
  error: string | null;
}

export type AiProviderJobStatus = 'queued' | 'running' | 'saved' | 'failed' | 'timeout' | 'cancelled';

export interface AiProviderJob {
  job_id: string;
  status: AiProviderJobStatus;
  provider: DeviceIntelligenceUpdateResult['provider'];
  command: string | null;
  started_at_utc: string;
  finished_at_utc: string | null;
  duration_ms: number | null;
  timeout_ms: number;
  stdout_summary: string | null;
  stderr_summary: string | null;
}

export type AiThreatReviewScope = 'map' | 'detector';

export interface AiThreatFinding {
  label: string;
  severity: 'info' | 'low' | 'medium' | 'high';
  summary: string;
  evidence: string[];
}

export interface AiThreatReview {
  scope: AiThreatReviewScope;
  verdict: 'clean' | 'watch' | 'suspicious' | 'unknown';
  severity: 'low' | 'medium' | 'high';
  confidence: 'low' | 'medium' | 'high';
  summary: string;
  findings: AiThreatFinding[];
  recommended_next_steps: string[];
  false_positive_notes: string[];
  created_at_utc: string;
}

export interface AiThreatReviewResult {
  provider: AiExternalProvider;
  available: boolean;
  review: AiThreatReview | null;
  job?: AiProviderJob;
  raw_output: string | null;
  error: string | null;
}

export interface WifiProfileSecretResult {
  source: 'netsh_wlan_profile_key_clear';
  ssid: string | null;
  available: boolean;
  password: string | null;
  security_key_present: boolean | null;
  authentication: string | null;
  key_type: string | null;
  strength: WifiPasswordStrengthAssessment | null;
  error: string | null;
}

export interface WifiPasswordStrengthAssessment {
  length: number | null;
  score: number;
  label: 'none' | 'weak' | 'fair' | 'good' | 'strong' | 'unknown';
  break_in_difficulty: 'none' | 'low' | 'medium' | 'high' | 'unknown';
  notes: string[];
}

export interface CollectorStateEvent extends BaseCollectorEvent {
  schema: 'wifi.collector_state.v1';
  event_type: 'collector_state';
  state: 'started' | 'stopped' | 'source_status' | 'error' | 'cancelled';
  message: string;
  sources?: CollectorSourceStatus[];
  error?: string;
}

export type CollectorEvent = WindowsWifiSnapshot | WindowsWifiEvent | WindowsWifiNetwork | CollectorStateEvent;

export type ClientLifecycleAction =
  | 'connected'
  | 'disconnected'
  | 'association_started'
  | 'association_succeeded'
  | 'association_failed'
  | 'security_started'
  | 'security_succeeded'
  | 'security_stopped'
  | 'other';

export interface ClientTimelineEvent extends BaseCollectorEvent {
  schema: 'wifi.client_timeline.v1';
  event_type: 'client_lifecycle';
  action: ClientLifecycleAction;
  client: string | null;
  ssid: string | null;
  adapter: string | null;
  event_id: number;
  record_id: number | null;
  summary: string;
  evidence_event_ids: string[];
}

export interface DetectorAlert extends BaseCollectorEvent {
  schema: 'wifi.alert.v1';
  event_type: 'alert';
  alert_type: 'reconnect_loop';
  severity: 'low' | 'medium' | 'high';
  score: number;
  client: string | null;
  ssid: string | null;
  summary: string;
  window_start_utc: string;
  window_end_utc: string;
  cycle_count: number;
  evidence_event_ids: string[];
  false_positive_notes: string[];
}

export type BaselineRunObservationType =
  | 'state_change'
  | 'bssid_change'
  | 'channel_change'
  | 'rssi_drop'
  | 'weak_signal'
  | 'nearby_bssid_added'
  | 'nearby_bssid_removed'
  | 'nearby_security_changed'
  | 'nearby_channel_changed'
  | 'nearby_signal_drop'
  | 'nearby_high_utilization';

export interface BaselineRunObservation extends BaseCollectorEvent {
  schema: 'wifi.run_observation.v1';
  event_type: 'run_observation';
  observation_type: BaselineRunObservationType;
  severity: 'low' | 'medium' | 'high';
  score: number;
  summary: string;
  adapter: string | null;
  interface_name: string | null;
  ssid: string | null;
  bssid: string | null;
  channel: number | null;
  rssi_dbm: number | null;
  signal_percent: number | null;
  previous_value: string | number | null;
  current_value: string | number | null;
  evidence_event_ids: string[];
  false_positive_notes: string[];
}

export interface BaselineStatus {
  platform: NodeJS.Platform;
  host_id: string;
  ts_utc: string;
  sources: CollectorSourceStatus[];
  snapshots: WindowsWifiSnapshot[];
}

export interface ConnectivityCheckResult {
  schema: 'monitor.connectivity_check.v1';
  ts_utc: string;
  provider: 'cloudflare';
  status: 'online' | 'degraded' | 'offline';
  public_ip: string | null;
  latency_ms: number | null;
  download_mbps: number | null;
  download_bytes: number;
  download_elapsed_ms: number | null;
  error: string | null;
}

export type LocalNetworkScanMode = 'passive' | 'poll' | 'active';

export interface LocalNetworkDevice {
  ip_address: string;
  mac_address: string | null;
  hostname: string | null;
  latency_ms: number | null;
  state: 'active' | 'stale' | 'unknown';
  interface_alias: string | null;
  is_gateway: boolean;
  source: 'net_neighbor' | 'reachability_probe' | 'direct_probe';
  notes: string[];
}

export interface LocalNetworkExposureCheck {
  id: string;
  label: string;
  status: 'info' | 'watch' | 'review';
  summary: string;
  evidence: string[];
}

export interface LocalNetworkScanResult {
  schema: 'monitor.local_network_scan.v1';
  ts_utc: string;
  mode: LocalNetworkScanMode;
  status: 'saved' | 'failed';
  local_ip: string | null;
  local_mac: string | null;
  gateway: string | null;
  prefix: string | null;
  device_count: number;
  active_count: number;
  stale_count: number;
  devices: LocalNetworkDevice[];
  exposure_checks: LocalNetworkExposureCheck[];
  error: string | null;
}

export type ScanIdentityAction = 'apply' | 'restore';

export interface ScanIdentityState {
  schema: 'monitor.scan_identity.v1';
  ts_utc: string;
  supported: boolean;
  requires_admin: boolean;
  interface_name: string | null;
  adapter_name: string | null;
  current_computer_name: string | null;
  current_mac_address: string | null;
  active_mac_override: string | null;
  suggested_computer_name: string;
  suggested_mac_address: string | null;
  stored_original_computer_name: string | null;
  stored_original_mac_address: string | null;
  pending_reboot: boolean;
  warnings: string[];
  error: string | null;
}

export interface ScanIdentityChangeRequest {
  interfaceName?: string | null;
  adapterName?: string | null;
  computerName?: string | null;
  macAddress?: string | null;
  restartAdapter?: boolean;
}

export interface ScanIdentityChangeResult extends ScanIdentityState {
  action: ScanIdentityAction;
  changed_computer_name: boolean;
  changed_mac_address: boolean;
  command: string;
  stdout: string;
  stderr: string;
}

export interface BaselinePlatformAdapter {
  getSourceStatus(): Promise<CollectorSourceStatus[]>;
  getWlanEventSourceStatus?(): Promise<CollectorSourceStatus[]>;
  getWifiSnapshots(context: EventContext): Promise<WindowsWifiSnapshot[]>;
  requestNearbyWifiScan?(context: EventContext): Promise<CollectorSourceStatus>;
  getNearbyWifiBssEntries?(context: EventContext): Promise<WindowsNativeBssResult>;
  getNearbyWifiNetworks?(context: EventContext): Promise<WindowsWifiNetwork[]>;
  getRecentWlanEvents(context: EventContext, maxEvents: number): Promise<WindowsWifiEvent[]>;
}

export interface EventContext {
  runId: string;
  hostId: string;
  now?: Date;
}

export interface CollectOptions {
  durationSeconds: number;
  intervalSeconds: number;
  outDir: string | null;
  maxEvents: number;
  databaseFile?: string | null;
  abortSignal?: AbortSignal;
}

export interface HistoryOptions {
  last: number;
}

export interface RunHistoryOptions {
  last: number;
  runsDir: string | null;
  databaseFile?: string | null;
}

export interface RunAnalysisOptions {
  runId: string;
  runsDir: string | null;
  windowMinutes: number;
  minCycles: number;
  databaseFile?: string | null;
}

export interface RunComparisonOptions {
  baselineRunId: string;
  candidateRunId: string;
  runsDir: string | null;
  windowMinutes: number;
  minCycles: number;
  databaseFile?: string | null;
}

export interface TimelineOptions {
  last: number;
  windowMinutes: number;
  minCycles: number;
}

export interface DiagnosticsOptions {
  outDir: string | null;
  runsDir: string | null;
  lastRuns: number;
  lastEvents: number;
  windowMinutes: number;
  minCycles: number;
  databaseFile?: string | null;
}

export interface DiagnosticsHistoryOptions {
  last: number;
  diagnosticsDir: string | null;
}

export interface BaselineNetworksOptions {
  refreshScan?: boolean;
  scanSettleMs?: number;
  databaseFile?: string | null;
  useDeviceIntelligence?: boolean;
  persistInventory?: boolean;
  location?: ScanLocationInput | null;
}

export interface CollectResult {
  run_id: string;
  out_dir: string;
  events_file: string;
  summary_file: string;
  storage?: 'sqlite' | 'jsonl';
  database_file?: string | null;
  started_at_utc: string;
  stopped_at_utc: string;
  cancelled: boolean;
  event_count: number;
  snapshot_count: number;
  network_scan_count: number;
  network_bssid_count: number;
  wlan_event_count: number;
  sources: CollectorSourceStatus[];
}

export interface BaselineCollectionCancelResult {
  cancelled: boolean;
  message: string;
}

export interface BaselineEventsResult {
  run_id: string;
  host_id: string;
  ts_utc: string;
  sources: CollectorSourceStatus[];
  order: 'chronological';
  events: WindowsWifiEvent[];
}

export interface BaselineTimelineResult {
  run_id: string;
  host_id: string;
  ts_utc: string;
  sources: CollectorSourceStatus[];
  event_count: number;
  timeline_count: number;
  alert_count: number;
  timeline: ClientTimelineEvent[];
  alerts: DetectorAlert[];
}

export interface BaselineDiagnosticsBundleResult {
  schema: 'wifi.baseline_diagnostics.v1';
  bundle_id: string;
  out_dir: string;
  created_at_utc: string;
  inputs: {
    runs_dir: string | null;
    last_runs: number;
    last_events: number;
    window_minutes: number;
    min_cycles: number;
  };
  runtime: {
    platform: NodeJS.Platform;
    arch: string;
    node_version: string;
    app_version: string | null;
  };
  files: {
    manifest: string;
    readme: string;
    status: string;
    networks: string;
    runs: string;
    events: string;
    timeline: string;
  };
  counts: {
    snapshots: number;
    networks: number;
    bssids: number;
    runs: number;
    events: number;
    timeline: number;
    alerts: number;
  };
}

export interface BaselineDiagnosticsBundleRecord {
  bundle_id: string;
  out_dir: string;
  manifest_file: string | null;
  readme_file: string | null;
  created_at_utc: string | null;
  counts: BaselineDiagnosticsBundleResult['counts'] | null;
  status: 'complete' | 'missing_manifest' | 'invalid_manifest';
  error: string | null;
}

export interface BaselineDiagnosticsBundlesResult {
  ts_utc: string;
  diagnostics_dir: string;
  bundle_count: number;
  bundles: BaselineDiagnosticsBundleRecord[];
}

export interface BaselineNetworksResult {
  platform: NodeJS.Platform;
  host_id: string;
  ts_utc: string;
  sources: CollectorSourceStatus[];
  network_count: number;
  bssid_count: number;
  mac_summary: MacIntelligenceSummary;
  scan_location: ScanLocationRecord | null;
  networks: WindowsWifiNetwork[];
}

export interface LocationFilteredNetworksResult extends BaselineNetworksResult {
  selected_location: ScanLocationRecord | null;
}

export interface BaselineRunRecord {
  run_id: string;
  out_dir: string;
  events_file: string | null;
  summary_file: string;
  storage?: 'sqlite' | 'jsonl';
  database_file?: string | null;
  started_at_utc: string | null;
  stopped_at_utc: string | null;
  duration_seconds: number | null;
  cancelled: boolean | null;
  event_count: number | null;
  snapshot_count: number | null;
  network_scan_count: number | null;
  network_bssid_count: number | null;
  wlan_event_count: number | null;
  sources: CollectorSourceStatus[];
  status: 'complete' | 'missing_summary' | 'invalid_summary';
  error: string | null;
}

export interface BaselineRunsResult {
  ts_utc: string;
  runs_dir: string;
  run_count: number;
  runs: BaselineRunRecord[];
}

export interface NumericSummary {
  min: number;
  max: number;
  avg: number;
  last: number;
}

export interface BaselineRunSnapshotSummary {
  count: number;
  first_ts_utc: string | null;
  last_ts_utc: string | null;
  adapters: string[];
  interfaces: string[];
  states: Record<string, number>;
  ssids: string[];
  bssids: string[];
  bands: string[];
  channels: number[];
  rssi_dbm: NumericSummary | null;
  signal_percent: NumericSummary | null;
}

export interface BaselineRunNetworkSummary {
  count: number;
  ssid_count: number;
  ssids: string[];
  bssids: string[];
  bands: string[];
  channels: number[];
  authentications: string[];
  encryptions: string[];
  mac_summary: MacIntelligenceSummary;
}

export interface BaselineRunEvidenceReport {
  verdict: 'clean_baseline' | 'watch' | 'suspicious';
  confidence: 'low' | 'medium' | 'high';
  score: number;
  summary: string;
  evidence: string[];
  limitations: string[];
  next_steps: string[];
}

export interface BaselineRunAnalysisResult {
  run_id: string;
  host_id: string;
  ts_utc: string;
  out_dir: string;
  events_file: string;
  summary_file: string;
  started_at_utc: string | null;
  stopped_at_utc: string | null;
  duration_seconds: number | null;
  parsed_event_count: number;
  invalid_line_count: number;
  event_type_counts: Record<string, number>;
  collector_errors: CollectorStateEvent[];
  sources: CollectorSourceStatus[];
  snapshots: BaselineRunSnapshotSummary;
  networks: BaselineRunNetworkSummary;
  report: BaselineRunEvidenceReport;
  observation_count: number;
  observations: BaselineRunObservation[];
  wlan_event_count: number;
  timeline_count: number;
  alert_count: number;
  timeline: ClientTimelineEvent[];
  alerts: DetectorAlert[];
}

export interface BaselineRunComparisonMetric {
  baseline: number;
  candidate: number;
  delta: number;
}

export interface StringSetDelta {
  added: string[];
  removed: string[];
  shared: string[];
}

export interface NumberSetDelta {
  added: number[];
  removed: number[];
  shared: number[];
}

export interface BaselineRunComparisonResult {
  ts_utc: string;
  baseline_run_id: string;
  candidate_run_id: string;
  baseline_report: BaselineRunEvidenceReport;
  candidate_report: BaselineRunEvidenceReport;
  score_delta: number;
  verdict_changed: boolean;
  confidence_changed: boolean;
  metrics: {
    parsed_events: BaselineRunComparisonMetric;
    snapshots: BaselineRunComparisonMetric;
    wlan_events: BaselineRunComparisonMetric;
    timeline: BaselineRunComparisonMetric;
    alerts: BaselineRunComparisonMetric;
    observations: BaselineRunComparisonMetric;
    nearby_records: BaselineRunComparisonMetric;
    nearby_ssids: BaselineRunComparisonMetric;
    nearby_bssids: BaselineRunComparisonMetric;
    nearby_vendors: BaselineRunComparisonMetric;
    nearby_device_hints: BaselineRunComparisonMetric;
    nearby_unknown_ouis: BaselineRunComparisonMetric;
  };
  observation_types: Record<string, BaselineRunComparisonMetric>;
  snapshots: {
    ssids: StringSetDelta;
    bssids: StringSetDelta;
    channels: NumberSetDelta;
  };
  nearby: {
    ssids: StringSetDelta;
    bssids: StringSetDelta;
    channels: NumberSetDelta;
    vendors: StringSetDelta;
    device_hints: StringSetDelta;
    unknown_ouis: StringSetDelta;
  };
  summary: string;
  evidence: string[];
  limitations: string[];
  next_steps: string[];
}
