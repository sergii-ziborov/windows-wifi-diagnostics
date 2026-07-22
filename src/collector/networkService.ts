import { hostname } from 'node:os';
import { createPlatformAdapter } from '../platform';
import { applyDeviceIntelligenceOverrides } from './deviceIntelligence';
import { applyInventoryThreatSignals, persistNetworkInventory } from './deviceInventory';
import { ensureNetworkMacEnrichment, summarizeMacIntelligence } from './macLookup';
import { mergeNativeBssDetails } from './nativeBss';
import { ensureNetworkVulnerabilityIntel } from './vulnerabilityIntel';
import { ensureNetworkSecurityAssessment } from './wifiSecurity';
import type {
  BaselineNetworksOptions,
  BaselineNetworksResult,
  BaselinePlatformAdapter,
  CollectorSourceStatus,
  EventContext,
  WindowsNativeBssEntry,
  WindowsWifiNetwork
} from './types';

const DEFAULT_SCAN_SETTLE_MS = 4500;

export async function getBaselineNetworks(
  options: BaselineNetworksOptions = {},
  adapter: BaselinePlatformAdapter = createPlatformAdapter()
): Promise<BaselineNetworksResult> {
  const context = createEventContext('networks');

  if (!adapter.getNearbyWifiNetworks) {
    return result(context, [platformUnavailable()], []);
  }

  const sources: CollectorSourceStatus[] = [];
  let nativeBssEntries: WindowsNativeBssEntry[] = [];

  if (options.refreshScan && adapter.requestNearbyWifiScan) {
    const scanSource = await adapter.requestNearbyWifiScan(context);
    sources.push(scanSource);

    if (scanSource.available) {
      await delay(boundedScanSettleMs(options.scanSettleMs));
    }
  }

  if (adapter.getNearbyWifiBssEntries) {
    const nativeBssResult = await adapter.getNearbyWifiBssEntries(context);
    sources.push(nativeBssResult.source);
    nativeBssEntries = nativeBssResult.entries;
  }

  try {
    let networks = mergeNativeBssDetails(await adapter.getNearbyWifiNetworks(context), nativeBssEntries)
      .map(ensureNetworkMacEnrichment)
      .map(annotateMeshGroupHint)
      .map(ensureNetworkSecurityAssessment)
      .map(ensureNetworkVulnerabilityIntel);

    if (options.useDeviceIntelligence !== false) {
      networks = await applyDeviceIntelligenceOverrides(networks, options.databaseFile);
    }

    if (options.persistInventory !== false) {
      networks = await applyInventoryThreatSignals(networks, options.databaseFile);
      const persisted = await persistNetworkInventory(networks, {
        databaseFile: options.databaseFile,
        location: options.location ?? null
      });
      return result(context, [...sources, networkListAvailable(sources, networks)], networks, persisted.scan_location);
    }

    return result(context, [...sources, networkListAvailable(sources, networks)], networks, null);
  } catch (error) {
    return result(context, [...sources, networkListUnavailable(sources, error)], [], null);
  }
}

function annotateMeshGroupHint(
  network: WindowsWifiNetwork,
  index: number,
  networks: WindowsWifiNetwork[]
): WindowsWifiNetwork {
  if (!network.mac_enrichment) {
    return network;
  }

  const ssid = network.ssid?.trim().toLowerCase() ?? '';
  const sameSsidCount = networks.filter((candidate) => candidate.ssid?.trim().toLowerCase() === ssid).length;
  const protectedNetwork = Boolean(network.authentication && !network.authentication.toLowerCase().includes('open'));
  const localBssid = network.mac_enrichment.address_scope === 'local';
  const ssidLooksRouter =
    ssid.includes('mesh') ||
    ssid.includes('router') ||
    ssid.includes('gateway');

  if (!ssid || sameSsidCount < 2 || !protectedNetwork || (!localBssid && !ssidLooksRouter)) {
    return network;
  }

  const existingHint = network.mac_enrichment.device_hint?.toLowerCase() ?? '';
  if (existingHint.includes('mesh') || existingHint.includes('router')) {
    return network;
  }

  return {
    ...network,
    mac_enrichment: {
      ...network.mac_enrichment,
      device_hint: 'home router / mesh node',
      confidence: network.mac_enrichment.confidence === 'high' ? 'high' : 'medium',
      notes: [
        ...network.mac_enrichment.notes,
        'Multiple BSSIDs share this SSID; local/private BSSID evidence suggests a router or mesh node'
      ]
    }
  };
}

function result(
  context: EventContext,
  sources: CollectorSourceStatus[],
  networks: WindowsWifiNetwork[],
  scanLocation: BaselineNetworksResult['scan_location'] = null
): BaselineNetworksResult {
  return {
    platform: process.platform,
    host_id: context.hostId,
    ts_utc: new Date().toISOString(),
    sources,
    network_count: new Set(networks.map((network) => network.ssid).filter(Boolean)).size,
    bssid_count: networks.length,
    mac_summary: summarizeMacIntelligence(networks),
    scan_location: scanLocation,
    networks
  };
}

function createEventContext(runId: string): EventContext {
  return {
    runId,
    hostId: hostname()
  };
}

function platformUnavailable(): CollectorSourceStatus {
  return {
    name: 'platform_adapter',
    available: false,
    detail: 'Nearby network scan is not implemented on this platform in phase 1'
  };
}

function networkListAvailable(
  sources: CollectorSourceStatus[],
  networks: WindowsWifiNetwork[]
): CollectorSourceStatus {
  return {
    name: networkListSourceName(sources),
    available: true,
    detail: `bssid_count=${networks.length}`
  };
}

function networkListUnavailable(sources: CollectorSourceStatus[], error: unknown): CollectorSourceStatus {
  return {
    name: networkListSourceName(sources),
    available: false,
    detail: error instanceof Error ? error.message : String(error)
  };
}

function networkListSourceName(sources: CollectorSourceStatus[]): CollectorSourceStatus['name'] {
  return sources.some((source) => source.name === 'radiochron_native_bss_list')
    ? 'radiochron_native_networks'
    : 'netsh_wlan_networks';
}

function boundedScanSettleMs(value: number | undefined): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return DEFAULT_SCAN_SETTLE_MS;
  }

  return Math.min(10_000, Math.max(0, Math.trunc(value)));
}

async function delay(durationMs: number): Promise<void> {
  if (durationMs <= 0) {
    return;
  }

  await new Promise((resolve) => {
    setTimeout(resolve, durationMs);
  });
}
