import type {
  CollectorSourceStatus,
  EventContext,
  WifiInformationElementSummary,
  WindowsNativeBssEntry,
  WindowsNativeBssResult
} from '../../collector/types';
import { getBeaconTrailClient } from '../../mcp/client';

/**
 * Nearby-BSS collection through the BeaconTrail MCP server.
 *
 * This replaces the two modules that used to emit C# and compile it at runtime
 * via PowerShell `Add-Type` to reach `wlanapi.dll`. The Rust server calls
 * `WlanScan` and `WlanGetNetworkBssList` as direct FFI, so this app no longer
 * needs PowerShell, the .NET CSC compiler, or a runtime code-generation step
 * for any of its radio data.
 */

const BSS_TIMEOUT_MS = 20_000;
const SCAN_TIMEOUT_MS = 20_000;

/** Shape of one entry in a `detail: "full"` wifi_networks response. */
interface BeaconTrailNetwork {
  interface_guid?: string | null;
  ssid?: string | null;
  bssid?: string | null;
  bss_type?: string | null;
  phy_type?: string | null;
  rssi_dbm?: number | null;
  link_quality?: number | null;
  center_frequency_khz?: number | null;
  beacon_period_tu?: number | null;
  in_reg_domain?: boolean | null;
  capability_information?: number | null;
  timestamp?: number | string | null;
  host_timestamp?: number | string | null;
  rates_mbps?: number[] | null;
  information_elements?: Partial<WifiInformationElementSummary> | null;
}

interface BeaconTrailNetworksResponse {
  count?: number;
  refreshed?: boolean;
  networks?: BeaconTrailNetwork[];
}

export async function requestNearbyWifiScan(): Promise<CollectorSourceStatus> {
  try {
    const payload = (await getBeaconTrailClient().callTool('wifi_scan', {}, SCAN_TIMEOUT_MS)) as {
      interfaces_scanning?: number;
    } | null;

    const interfaces = payload?.interfaces_scanning ?? 0;

    return {
      name: 'windows_native_wifi_scan',
      available: interfaces > 0,
      detail: `interfaces_scanning=${interfaces}`
    };
  } catch (error) {
    return {
      name: 'windows_native_wifi_scan',
      available: false,
      detail: formatError(error)
    };
  }
}

export async function getNearbyWifiBssEntries(_context: EventContext): Promise<WindowsNativeBssResult> {
  try {
    const payload = (await getBeaconTrailClient().callTool(
      'wifi_networks',
      { detail: 'full' },
      BSS_TIMEOUT_MS
    )) as BeaconTrailNetworksResponse | null;

    const entries = mapBeaconTrailNetworks(payload);

    return {
      source: {
        name: 'windows_native_bss_list',
        available: true,
        detail: `bssid_count=${entries.length};ie_bytes=${sumIeBytes(entries)};refreshed=${payload?.refreshed ?? false}`
      },
      entries
    };
  } catch (error) {
    return {
      source: {
        name: 'windows_native_bss_list',
        available: false,
        detail: formatError(error)
      },
      entries: []
    };
  }
}

/**
 * Translate a BeaconTrail `wifi_networks` payload into this app's BSS shape.
 *
 * Pure and exported so it can be tested without a running server.
 */
export function mapBeaconTrailNetworks(payload: BeaconTrailNetworksResponse | null): WindowsNativeBssEntry[] {
  const networks = payload?.networks;
  if (!Array.isArray(networks)) {
    return [];
  }

  return networks.map((network) => ({
    interface_guid: normalizeString(network.interface_guid),
    // The server reports the GUID, not the friendly adapter name.
    interface_description: null,
    ssid: normalizeString(network.ssid),
    bssid: normalizeMac(network.bssid),
    native_bss: {
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
    }
  }));
}

function normalizeInformationElements(
  ie: Partial<WifiInformationElementSummary> | null | undefined
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

function normalizeString(value: string | null | undefined): string | null {
  if (typeof value !== 'string') {
    return null;
  }

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
  if (typeof value === 'number' && Number.isFinite(value)) {
    return String(value);
  }

  return normalizeString(typeof value === 'string' ? value : null);
}

function formatError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
