import { ensureNetworkMacEnrichment, summarizeMacIntelligence } from '../collector/macLookup';
import { ensureNetworkVulnerabilityIntel } from '../collector/vulnerabilityIntel';
import { ensureNetworkSecurityAssessment } from '../collector/wifiSecurity';
import type {
  BaselineDiagnosticsBundlesResult,
  BaselineEventsResult,
  BaselineNetworksResult,
  BaselineRunsResult,
  BaselineStatus,
  BaselineTimelineResult,
  DeviceHistoryResult,
  ScanIdentityState,
  ScanLocationsResult,
  WindowsWifiNetwork,
  WindowsWifiSnapshot
} from '../collector/types';

const DEMO_NOW = new Date();
const TS = DEMO_NOW.toISOString();
const HOST = 'radiochron-demo-box';
const LOCATION = {
  id: 1,
  location_key: 'demo-lab-0000',
  label: 'Synthetic Test Lab',
  latitude: 0.0004,
  longitude: -0.0003,
  source: 'manual' as const,
  first_seen_utc: isoAgo(3),
  last_seen_utc: TS,
  scan_count: 18
};

const NETWORKS = [
  makeNetwork('Lab Mesh 6E', '02:11:22:33:44:51', -43, 94, '6GHz', 37, 'WPA3-Personal', 'CCMP', '802.11be', true),
  makeNetwork('Lab Mesh 6E', '02:11:22:33:44:52', -55, 82, '5GHz', 149, 'WPA3-Personal', 'CCMP', '802.11ax', true),
  makeNetwork('Workshop-IoT', '02:20:24:00:00:31', -63, 68, '2.4GHz', 6, 'WPA2-Personal', 'CCMP', '802.11n', false),
  makeNetwork('Guest Sandbox', '02:30:40:50:60:71', -71, 54, '2.4GHz', 11, 'Open', 'None', '802.11n', false),
  makeNetwork('FieldBox-Setup', '02:42:ac:11:00:09', -78, 38, '5GHz', 44, 'WPA2-Personal', 'CCMP', '802.11ac', false)
];

const SNAPSHOT: WindowsWifiSnapshot = {
  schema: 'wifi.windows_baseline.v1',
  event_type: 'windows_wifi_snapshot',
  ts_utc: TS,
  source: 'baseline',
  run_id: 'demo-status',
  host_id: HOST,
  adapter: 'RadioChron Demo Adapter',
  interface_name: process.platform === 'darwin' ? 'en0' : 'Wi-Fi',
  interface_guid: process.platform === 'darwin' ? 'en0' : '{00000000-0000-4000-8000-000000000001}',
  physical_address: '02:00:00:00:00:01',
  ipv4_addresses: ['192.0.2.24'],
  ipv6_addresses: ['2001:db8::24'],
  default_gateway: '192.0.2.1',
  dns_servers: ['192.0.2.53', '2001:db8::53'],
  state: 'connected',
  ssid: 'Lab Mesh 6E',
  bssid: '02:11:22:33:44:51',
  band: '6GHz',
  channel: 37,
  radio_type: '802.11be',
  authentication: 'WPA3-Personal',
  cipher: 'CCMP',
  receive_mbps: 1441,
  transmit_mbps: 1201,
  signal_percent: 94,
  rssi_dbm: -43,
  raw: {
    collector: 'radiochron',
    transport: 'radiochron_js',
    fixture: 'synthetic'
  }
};

const SOURCES = [
  {
    name: 'radiochron_native_status' as const,
    available: true,
    detail: 'interfaces=1;transport=radiochron_js;fixture=synthetic'
  },
  {
    name: 'radiochron_native_wifi_scan' as const,
    available: true,
    detail: 'interfaces_scanning=1;fixture=synthetic'
  },
  {
    name: 'radiochron_native_bss_list' as const,
    available: true,
    detail: 'bssid_count=5;ie_bytes=934;transport=radiochron_js;fixture=synthetic'
  },
  {
    name: 'radiochron_native_networks' as const,
    available: true,
    detail: 'bssid_count=5;fixture=synthetic'
  }
];

export function demoBaselineStatus(): BaselineStatus {
  return {
    platform: process.platform,
    host_id: HOST,
    ts_utc: TS,
    sources: SOURCES,
    snapshots: [SNAPSHOT]
  };
}

export function demoBaselineNetworks(): BaselineNetworksResult {
  return {
    platform: process.platform,
    host_id: HOST,
    ts_utc: TS,
    sources: SOURCES,
    network_count: 4,
    bssid_count: NETWORKS.length,
    mac_summary: summarizeMacIntelligence(NETWORKS),
    scan_location: LOCATION,
    networks: NETWORKS
  };
}

export function demoBaselineRuns(): BaselineRunsResult {
  return { ts_utc: TS, runs_dir: 'synthetic://runs', run_count: 0, runs: [] };
}

export function demoBaselineEvents(): BaselineEventsResult {
  return {
    run_id: 'demo-events',
    host_id: HOST,
    ts_utc: TS,
    sources: [{ name: 'platform_history', available: false, detail: 'Synthetic demo uses saved baselines.' }],
    order: 'chronological',
    events: []
  };
}

export function demoBaselineTimeline(): BaselineTimelineResult {
  return {
    run_id: 'demo-timeline',
    host_id: HOST,
    ts_utc: TS,
    sources: SOURCES,
    event_count: 0,
    timeline_count: 0,
    alert_count: 0,
    timeline: [],
    alerts: []
  };
}

export function demoDiagnosticsBundles(): BaselineDiagnosticsBundlesResult {
  return { ts_utc: TS, diagnostics_dir: 'synthetic://diagnostics', bundle_count: 0, bundles: [] };
}

export function demoDeviceHistory(): DeviceHistoryResult {
  return {
    database_file: null,
    generated_at_utc: TS,
    new_window_hours: 24,
    total_devices: NETWORKS.length,
    records: NETWORKS.map((network, index) => ({
      bssid: network.bssid ?? `02:00:00:00:00:${String(index).padStart(2, '0')}`,
      ssid: network.ssid,
      vendor: network.mac_enrichment?.vendor ?? null,
      device_hint: index < 2 ? 'mesh access point' : network.mac_enrichment?.device_hint ?? null,
      mac_scope: network.mac_enrichment?.address_scope ?? 'local',
      oui: network.mac_enrichment?.oui ?? null,
      first_seen_utc: isoAgo(3 - Math.min(index, 2)),
      last_seen_utc: TS,
      seen_count: 18 - index * 2,
      observation_count: 18 - index * 2,
      active_hours: [{ hour: 9, count: 5 }],
      channels: network.channel === null ? [] : [network.channel],
      bands: network.band === null ? [] : [network.band],
      latest_channel: network.channel,
      latest_band: network.band,
      latest_signal_percent: network.signal_percent,
      strongest_signal_percent: network.signal_percent,
      average_signal_percent: network.signal_percent === null ? null : Math.max(0, network.signal_percent - 4),
      radio_location_label: LOCATION.label,
      is_new: index === NETWORKS.length - 1,
      vulnerability_exposure: network.vulnerability_intel?.exposure_level ?? null,
      security_label: network.security_assessment?.label ?? null
    }))
  };
}

export function demoScanLocations(): ScanLocationsResult {
  return {
    database_file: null,
    generated_at_utc: TS,
    locations: [LOCATION],
    metrics: NETWORKS.map((network) => ({
      bssid: network.bssid ?? '',
      location_id: LOCATION.id,
      location_key: LOCATION.location_key,
      ssid: network.ssid,
      first_seen_utc: isoAgo(3),
      last_seen_utc: TS,
      seen_count: 18,
      signal_min_percent: network.signal_percent === null ? null : Math.max(0, network.signal_percent - 8),
      signal_max_percent: network.signal_percent,
      signal_avg_percent: network.signal_percent === null ? null : Math.max(0, network.signal_percent - 4),
      latest_signal_percent: network.signal_percent,
      strongest_signal_percent: network.signal_percent,
      average_signal_percent: network.signal_percent === null ? null : Math.max(0, network.signal_percent - 4),
      latest_channel: network.channel,
      channels: network.channel === null ? [] : [network.channel],
      bands: network.band === null ? [] : [network.band],
      authentication: network.authentication,
      encryption: network.encryption,
      last_payload_hash: `synthetic-${network.bssid}`,
      latest_network: network
    }))
  };
}

export function demoScanIdentityState(): ScanIdentityState {
  return {
    schema: 'monitor.scan_identity.v1',
    ts_utc: TS,
    supported: process.platform === 'win32',
    requires_admin: false,
    interface_name: process.platform === 'win32' ? 'Wi-Fi' : null,
    adapter_name: process.platform === 'win32' ? 'RadioChron Demo Adapter' : null,
    current_computer_name: 'RADIOCHRON-DEMO',
    current_mac_address: '02:00:00:00:00:01',
    active_mac_override: null,
    suggested_computer_name: 'RADIOCHRON-SCOUT',
    suggested_mac_address: '02:00:00:00:00:02',
    stored_original_computer_name: 'RADIOCHRON-DEMO',
    stored_original_mac_address: '02:00:00:00:00:01',
    pending_reboot: false,
    warnings: ['Synthetic demo mode: no system identity is read or changed.'],
    error: process.platform === 'win32' ? null : 'Scan identity changes are only available on Windows.'
  };
}

function makeNetwork(
  ssid: string,
  bssid: string,
  rssi: number,
  signal: number,
  band: string,
  channel: number,
  authentication: string,
  encryption: string,
  radioType: string,
  mesh: boolean
): WindowsWifiNetwork {
  const frequency = band === '6GHz' ? 6_135_000 : band === '5GHz' ? (channel === 149 ? 5_745_000 : 5_220_000) : channel === 6 ? 2_437_000 : 2_462_000;
  const open = authentication === 'Open';
  const network: WindowsWifiNetwork = {
    schema: 'wifi.windows_baseline.v1',
    event_type: 'windows_wifi_network',
    ts_utc: TS,
    source: 'baseline',
    run_id: 'demo-networks',
    host_id: HOST,
    interface_name: process.platform === 'darwin' ? 'en0' : 'Wi-Fi',
    ssid,
    network_type: 'infrastructure',
    authentication,
    encryption,
    bssid,
    signal_percent: signal,
    radio_type: radioType,
    band,
    channel,
    basic_rates_mbps: [6, 12, 24],
    other_rates_mbps: [54, 300, 1201],
    native_bss: {
      interface_guid: process.platform === 'darwin' ? 'en0' : '{00000000-0000-4000-8000-000000000001}',
      interface_description: 'RadioChron Demo Adapter',
      bss_type: 'infrastructure',
      phy_type: radioType,
      rssi_dbm: rssi,
      link_quality: signal,
      center_frequency_khz: frequency,
      beacon_period_tu: 100,
      in_reg_domain: true,
      capability_information: open ? 0x0001 : 0x0011,
      timestamp: '424242',
      host_timestamp: '424242',
      rates_mbps: [6, 12, 24, 54, 300, 1201],
      information_elements: {
        byte_length: open ? 92 : 187,
        element_count: mesh ? 19 : 13,
        element_ids: [0, 1, 3, 5, 7, 11, 45, 48, 61, 191, 255],
        names: ['SSID', 'Supported Rates', 'DS Parameter Set', 'Country', 'RSN', 'HT Capabilities', 'HE Capabilities'],
        extension_ids: mesh ? [35, 108] : [35],
        vendor_ouis: [],
        has_rsn: !open,
        has_wpa: false,
        has_bss_load: true,
        has_country: true,
        has_ht: true,
        has_vht: band !== '2.4GHz',
        has_he: radioType === '802.11ax' || radioType === '802.11be',
        has_eht: radioType === '802.11be'
      }
    },
    raw: {
      collector: 'radiochron',
      transport: 'radiochron_js',
      fixture: 'synthetic'
    }
  };

  return ensureNetworkVulnerabilityIntel(
    ensureNetworkSecurityAssessment(ensureNetworkMacEnrichment(network))
  );
}

function isoAgo(hours: number): string {
  return new Date(DEMO_NOW.getTime() - hours * 60 * 60 * 1_000).toISOString();
}
