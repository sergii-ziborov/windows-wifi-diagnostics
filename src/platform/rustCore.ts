import type {
  CollectorSourceStatus,
  EventContext,
  WifiInformationElementSummary,
  WindowsNativeBssEntry,
  WindowsNativeBssResult,
  WindowsWifiNetwork,
  WindowsWifiSnapshot
} from '../collector/types';
import { getRadioChronCoreClient } from 'radiochron';
import type { RadioChronWifiStatus } from 'radiochron';

const BSS_TIMEOUT_MS = 20_000;
const SCAN_TIMEOUT_MS = 20_000;
const BSS_CACHE_MS = 1_000;

type CoreWifiStatus = RadioChronWifiStatus;

interface CoreRsnDetails {
  group_cipher?: string | null;
  pairwise_ciphers?: string[] | null;
  akm_suites?: string[] | null;
  pmf_capable?: boolean;
  pmf_required?: boolean;
}

interface CoreNetwork {
  interface_guid?: string | null;
  ssid?: string | null;
  bssid?: string | null;
  bss_type?: string | null;
  phy_type?: string | null;
  rssi_dbm?: number | null;
  link_quality?: number | null;
  center_frequency_khz?: number | null;
  band?: string | null;
  channel?: number | null;
  beacon_period_tu?: number | null;
  in_reg_domain?: boolean | null;
  capability_information?: number | null;
  timestamp?: number | string | null;
  host_timestamp?: number | string | null;
  rates_mbps?: number[] | null;
  ie_data_complete?: boolean;
  information_elements?: (Partial<WifiInformationElementSummary> & {
    has_wps?: boolean;
    rsn?: CoreRsnDetails | null;
  }) | null;
}

interface CoreNetworksResponse {
  count?: number;
  refreshed?: boolean;
  networks?: CoreNetwork[];
  interface_errors?: Array<{ interface_guid?: string; error_code?: number }>;
}

let bssCache: { createdAtMs: number; payload: CoreNetworksResponse } | null = null;
let bssInFlight: Promise<CoreNetworksResponse> | null = null;

export async function getCoreSourceStatus(): Promise<CollectorSourceStatus> {
  try {
    const statuses = await getCoreWifiStatuses();
    return {
      name: 'radiochron_native_status',
      available: true,
      detail: `interfaces=${statuses.length};transport=radiochron_js`
    };
  } catch (error) {
    return {
      name: 'radiochron_native_status',
      available: false,
      detail: formatError(error)
    };
  }
}

export async function getCoreWifiStatuses(): Promise<CoreWifiStatus[]> {
  return getRadioChronCoreClient().status();
}

export async function getCoreWifiSnapshots(context: EventContext): Promise<WindowsWifiSnapshot[]> {
  return mapCoreStatuses(await getCoreWifiStatuses(), context);
}

export async function requestNativeWifiScan(): Promise<CollectorSourceStatus> {
  try {
    const payload = await getRadioChronCoreClient().scan(SCAN_TIMEOUT_MS);
    const interfaces = payload.interfaces_scanning;
    bssCache = null;
    return {
      name: 'radiochron_native_wifi_scan',
      available: interfaces > 0,
      detail: `interfaces_scanning=${interfaces}`
    };
  } catch (error) {
    return {
      name: 'radiochron_native_wifi_scan',
      available: false,
      detail: formatError(error)
    };
  }
}

export async function getNativeWifiBssEntries(_context: EventContext): Promise<WindowsNativeBssResult> {
  try {
    const payload = await getCoreNetworks();
    const entries = mapRadioChronNetworks(payload);
    return {
      source: {
        name: 'radiochron_native_bss_list',
        available: true,
        detail: `bssid_count=${entries.length};ie_bytes=${sumIeBytes(entries)};transport=radiochron_js`
      },
      entries
    };
  } catch (error) {
    return {
      source: {
        name: 'radiochron_native_bss_list',
        available: false,
        detail: formatError(error)
      },
      entries: []
    };
  }
}

export async function getCoreNearbyWifiNetworks(context: EventContext): Promise<WindowsWifiNetwork[]> {
  const payload = await getCoreNetworks();
  return mapCoreNetworksToBaseline(payload, context);
}

async function getCoreNetworks(): Promise<CoreNetworksResponse> {
  if (bssCache && Date.now() - bssCache.createdAtMs <= BSS_CACHE_MS) {
    return bssCache.payload;
  }
  if (bssInFlight) {
    return bssInFlight;
  }

  bssInFlight = getRadioChronCoreClient()
    .networks({ timeoutMs: BSS_TIMEOUT_MS })
    .then((payload) => payload as CoreNetworksResponse)
    .then((payload) => {
      bssCache = { createdAtMs: Date.now(), payload };
      return payload;
    })
    .finally(() => {
      bssInFlight = null;
    });
  return bssInFlight;
}

/** Translate native core BSS entries into the desktop's stable evidence shape. */
export function mapRadioChronNetworks(payload: CoreNetworksResponse | null): WindowsNativeBssEntry[] {
  const networks = payload?.networks;
  if (!Array.isArray(networks)) {
    return [];
  }

  return networks.map((network) => ({
    interface_guid: normalizeString(network.interface_guid),
    interface_description: null,
    ssid: normalizeString(network.ssid),
    bssid: normalizeMac(network.bssid),
    native_bss: nativeDetails(network)
  }));
}

export function mapCoreStatuses(statuses: CoreWifiStatus[], context: EventContext): WindowsWifiSnapshot[] {
  const tsUtc = (context.now ?? new Date()).toISOString();
  return statuses.map((status) => {
    const connection = status.connection ?? null;
    return {
      schema: 'wifi.windows_baseline.v1',
      event_type: 'windows_wifi_snapshot',
      ts_utc: tsUtc,
      source: 'baseline',
      run_id: context.runId,
      host_id: context.hostId,
      adapter: normalizeString(status.interface.description),
      interface_name: normalizeString(status.interface.guid),
      interface_guid: normalizeString(status.interface.guid),
      physical_address: null,
      ipv4_addresses: [],
      ipv6_addresses: [],
      default_gateway: null,
      dns_servers: [],
      state: normalizeString(status.interface.state),
      ssid: normalizeString(connection?.ssid),
      bssid: normalizeMac(connection?.bssid),
      band: null,
      channel: null,
      radio_type: normalizeString(connection?.phy_type),
      authentication: connection ? 'associated' : null,
      cipher: null,
      receive_mbps: kbpsToMbps(connection?.rx_rate_kbps),
      transmit_mbps: kbpsToMbps(connection?.tx_rate_kbps),
      signal_percent: numberOrNull(connection?.signal_quality),
      rssi_dbm: numberOrNull(connection?.rssi_dbm_estimate),
      raw: {
        collector: 'radiochron',
        transport: 'radiochron_js',
        connection_error: status.connection_error ?? ''
      }
    };
  });
}

export function mapCoreNetworksToBaseline(
  payload: CoreNetworksResponse | null,
  context: EventContext
): WindowsWifiNetwork[] {
  const tsUtc = (context.now ?? new Date()).toISOString();
  return (payload?.networks ?? []).map((network) => {
    const security = inferSecurity(network);
    return {
      schema: 'wifi.windows_baseline.v1',
      event_type: 'windows_wifi_network',
      ts_utc: tsUtc,
      source: 'baseline',
      run_id: context.runId,
      host_id: context.hostId,
      interface_name: normalizeString(network.interface_guid),
      ssid: normalizeString(network.ssid),
      network_type: normalizeString(network.bss_type),
      authentication: security.authentication,
      encryption: security.encryption,
      bssid: normalizeMac(network.bssid),
      signal_percent: numberOrNull(network.link_quality),
      radio_type: normalizeString(network.phy_type),
      band: normalizeString(network.band) ?? bandFromFrequency(numberOrNull(network.center_frequency_khz)),
      channel: numberOrNull(network.channel),
      basic_rates_mbps: [],
      other_rates_mbps: Array.isArray(network.rates_mbps) ? network.rates_mbps.filter(Number.isFinite) : [],
      native_bss: nativeDetails(network),
      raw: {
        collector: 'radiochron',
        transport: 'radiochron_js',
        ie_data_complete: String(network.ie_data_complete ?? false)
      }
    };
  });
}

function nativeDetails(network: CoreNetwork) {
  return {
    interface_guid: normalizeString(network.interface_guid),
    interface_description: null,
    bss_type: normalizeString(network.bss_type),
    phy_type: normalizeString(network.phy_type),
    rssi_dbm: numberOrNull(network.rssi_dbm),
    link_quality: numberOrNull(network.link_quality),
    center_frequency_khz: numberOrNull(network.center_frequency_khz),
    beacon_period_tu: numberOrNull(network.beacon_period_tu),
    in_reg_domain: typeof network.in_reg_domain === 'boolean' ? network.in_reg_domain : null,
    capability_information: numberOrNull(network.capability_information),
    timestamp: stringOrNull(network.timestamp),
    host_timestamp: stringOrNull(network.host_timestamp),
    rates_mbps: Array.isArray(network.rates_mbps) ? network.rates_mbps.filter(Number.isFinite) : [],
    information_elements: normalizeInformationElements(network.information_elements)
  };
}

function inferSecurity(network: CoreNetwork): { authentication: string | null; encryption: string | null } {
  const ie = network.information_elements;
  const akm = ie?.rsn?.akm_suites ?? [];
  const ciphers = ie?.rsn?.pairwise_ciphers ?? [];
  const has = (name: string) => akm.includes(name);

  if (has('sae') || has('ft-sae')) {
    return { authentication: 'WPA3-Personal', encryption: ciphers.join(', ') || 'CCMP' };
  }
  if (has('802.1x') || has('ft-802.1x') || has('802.1x-sha256')) {
    return { authentication: 'WPA2-Enterprise', encryption: ciphers.join(', ') || 'CCMP' };
  }
  if (has('psk') || has('ft-psk') || has('psk-sha256')) {
    return { authentication: 'WPA2-Personal', encryption: ciphers.join(', ') || 'CCMP' };
  }
  if (ie?.has_rsn) {
    return { authentication: 'RSN', encryption: ciphers.join(', ') || null };
  }
  if (ie?.has_wpa) {
    return { authentication: 'WPA', encryption: null };
  }
  if ((numberOrNull(network.capability_information) ?? 0) & 0x0010) {
    return { authentication: 'WEP or protected', encryption: null };
  }
  if (network.ie_data_complete === true) {
    return { authentication: 'Open', encryption: 'None' };
  }
  return { authentication: null, encryption: null };
}

function normalizeInformationElements(
  ie: CoreNetwork['information_elements']
): WifiInformationElementSummary {
  return {
    byte_length: numberOrNull(ie?.byte_length) ?? 0,
    element_count: numberOrNull(ie?.element_count) ?? 0,
    element_ids: Array.isArray(ie?.element_ids) ? ie.element_ids : [],
    names: Array.isArray(ie?.names) ? ie.names : [],
    extension_ids: Array.isArray(ie?.extension_ids) ? ie.extension_ids : [],
    vendor_ouis: Array.isArray(ie?.vendor_ouis) ? ie.vendor_ouis : [],
    has_rsn: Boolean(ie?.has_rsn),
    has_wpa: Boolean(ie?.has_wpa),
    has_bss_load: Boolean(ie?.has_bss_load),
    has_country: Boolean(ie?.has_country),
    has_ht: Boolean(ie?.has_ht),
    has_vht: Boolean(ie?.has_vht),
    has_he: Boolean(ie?.has_he),
    has_eht: Boolean(ie?.has_eht)
  };
}

function sumIeBytes(entries: WindowsNativeBssEntry[]): number {
  return entries.reduce((total, entry) => total + entry.native_bss.information_elements.byte_length, 0);
}

function kbpsToMbps(value: number | null | undefined): number | null {
  const normalized = numberOrNull(value);
  return normalized === null ? null : normalized / 1_000;
}

function bandFromFrequency(centerKhz: number | null): string | null {
  if (centerKhz === null) return null;
  if (centerKhz >= 2_400_000 && centerKhz < 2_500_000) return '2.4GHz';
  if (centerKhz >= 5_000_000 && centerKhz < 5_925_000) return '5GHz';
  if (centerKhz >= 5_925_000 && centerKhz <= 7_125_000) return '6GHz';
  return null;
}

function normalizeString(value: string | null | undefined): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function normalizeMac(value: string | null | undefined): string | null {
  return normalizeString(value)?.replace(/-/g, ':').toLowerCase() ?? null;
}

function numberOrNull(value: number | null | undefined): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function stringOrNull(value: number | string | null | undefined): string | null {
  if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  return normalizeString(typeof value === 'string' ? value : null);
}

function formatError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
