import type {
  BaselinePlatformAdapter,
  CollectorSourceStatus,
  EventContext,
  WindowsWifiEvent,
  WindowsWifiNetwork,
  WindowsWifiSnapshot
} from '../../collector/types';
import { buildNetIpConfigurationScript, enrichSnapshotsWithIpConfiguration } from './ipConfig';
import {
  getNearbyWifiBssEntries as getRadioChronBssEntries,
  requestNearbyWifiScan as requestRadioChronScan
} from './radiochron';
import { parseNetshWlanInterfaces, parseNetshWlanNetworks } from './netsh';
import { runPowerShell } from './powershell';
import { buildWlanEventsScript, parseWlanAutoConfigEvents, WLAN_AUTOCONFIG_LOG } from './wlanEvents';

const WLAN_EVENT_BATCH_DELAY_MS = 25;
const WLAN_EVENT_CACHE_TTL_MS = 1_000;
const WLAN_LOG_STATUS_CACHE_TTL_MS = 10_000;

interface PendingWlanEventRequest {
  maxEvents: number;
  resolve: (stdout: string) => void;
  reject: (error: unknown) => void;
}

interface PendingWlanEventBatch {
  maxEvents: number;
  requests: PendingWlanEventRequest[];
  timer: ReturnType<typeof setTimeout>;
}

let pendingWlanEventBatch: PendingWlanEventBatch | null = null;
let wlanEventOutputCache: { maxEvents: number; stdout: string; createdAtMs: number } | null = null;
let wlanLogStatusCache: { status: CollectorSourceStatus; createdAtMs: number } | null = null;
let wlanLogStatusInFlight: Promise<CollectorSourceStatus> | null = null;

export function createWindowsPlatformAdapter(): BaselinePlatformAdapter {
  return {
    async getSourceStatus(): Promise<CollectorSourceStatus[]> {
      const [wlanLog, netsh, networks] = await Promise.all([
        checkWlanLog(),
        checkNetsh(),
        checkNetshNetworks()
      ]);
      return [wlanLog, netsh, networks];
    },

    async getWlanEventSourceStatus(): Promise<CollectorSourceStatus[]> {
      return [await checkWlanLog()];
    },

    async getWifiSnapshots(context: EventContext): Promise<WindowsWifiSnapshot[]> {
      const { stdout } = await runPowerShell('netsh wlan show interfaces');
      const snapshots = parseNetshWlanInterfaces(stdout, context);
      try {
        const { stdout: ipConfigOutput } = await runPowerShell(buildNetIpConfigurationScript());
        return enrichSnapshotsWithIpConfiguration(snapshots, ipConfigOutput);
      } catch {
        return snapshots;
      }
    },

    async requestNearbyWifiScan(): Promise<CollectorSourceStatus> {
      return requestRadioChronScan();
    },

    async getNearbyWifiBssEntries(context: EventContext) {
      return getRadioChronBssEntries(context);
    },

    async getNearbyWifiNetworks(context: EventContext): Promise<WindowsWifiNetwork[]> {
      const { stdout } = await runPowerShell('netsh wlan show networks mode=bssid');
      return parseNetshWlanNetworks(stdout, context);
    },

    async getRecentWlanEvents(
      context: EventContext,
      maxEvents: number
    ): Promise<WindowsWifiEvent[]> {
      const safeMaxEvents = boundedWlanEventCount(maxEvents);
      const stdout = await getRecentWlanEventOutput(safeMaxEvents);
      return parseWlanAutoConfigEvents(stdout, context).slice(0, safeMaxEvents);
    }
  };
}

export async function getWindowsNetworkScanSourceStatus(): Promise<CollectorSourceStatus[]> {
  return [await checkNetshNetworks()];
}

async function checkWlanLog(): Promise<CollectorSourceStatus> {
  const now = Date.now();
  if (wlanLogStatusCache && now - wlanLogStatusCache.createdAtMs <= WLAN_LOG_STATUS_CACHE_TTL_MS) {
    return wlanLogStatusCache.status;
  }

  if (wlanLogStatusInFlight) {
    return wlanLogStatusInFlight;
  }

  wlanLogStatusInFlight = readWlanLogStatus().then((status) => {
    wlanLogStatusCache = {
      status,
      createdAtMs: Date.now()
    };
    return status;
  }).finally(() => {
    wlanLogStatusInFlight = null;
  });

  return wlanLogStatusInFlight;
}

async function readWlanLogStatus(): Promise<CollectorSourceStatus> {
  try {
    const script = [
      `$log = Get-WinEvent -ListLog '${WLAN_AUTOCONFIG_LOG}' -ErrorAction Stop;`,
      '[PSCustomObject]@{ IsEnabled = $log.IsEnabled; RecordCount = $log.RecordCount } |',
      'ConvertTo-Json -Compress'
    ].join(' ');
    const { stdout } = await runPowerShell(script);
    const parsed = JSON.parse(stdout.trim()) as { IsEnabled?: boolean; RecordCount?: number };

    return {
      name: 'windows_wlan_autoconfig_operational',
      available: Boolean(parsed.IsEnabled),
      detail: `record_count=${parsed.RecordCount ?? 'unknown'}`
    };
  } catch (error) {
    return {
      name: 'windows_wlan_autoconfig_operational',
      available: false,
      detail: formatError(error)
    };
  }
}

function getRecentWlanEventOutput(maxEvents: number): Promise<string> {
  const cached = wlanEventOutputCache;
  const now = Date.now();
  if (cached && cached.maxEvents >= maxEvents && now - cached.createdAtMs <= WLAN_EVENT_CACHE_TTL_MS) {
    return Promise.resolve(cached.stdout);
  }

  return new Promise((resolve, reject) => {
    const request: PendingWlanEventRequest = { maxEvents, resolve, reject };
    if (pendingWlanEventBatch) {
      pendingWlanEventBatch.maxEvents = Math.max(pendingWlanEventBatch.maxEvents, maxEvents);
      pendingWlanEventBatch.requests.push(request);
      return;
    }

    pendingWlanEventBatch = {
      maxEvents,
      requests: [request],
      timer: setTimeout(flushPendingWlanEventBatch, WLAN_EVENT_BATCH_DELAY_MS)
    };
  });
}

async function flushPendingWlanEventBatch(): Promise<void> {
  const batch = pendingWlanEventBatch;
  if (!batch) {
    return;
  }

  pendingWlanEventBatch = null;

  try {
    const { stdout } = await runPowerShell(buildWlanEventsScript(batch.maxEvents));
    wlanEventOutputCache = {
      maxEvents: batch.maxEvents,
      stdout,
      createdAtMs: Date.now()
    };

    for (const request of batch.requests) {
      request.resolve(stdout);
    }
  } catch (error) {
    for (const request of batch.requests) {
      request.reject(error);
    }
  }
}

function boundedWlanEventCount(value: number): number {
  return Math.max(1, Math.floor(value));
}

async function checkNetsh(): Promise<CollectorSourceStatus> {
  try {
    await runPowerShell('netsh wlan show interfaces');
    return {
      name: 'netsh_wlan_interfaces',
      available: true,
      detail: null
    };
  } catch (error) {
    return {
      name: 'netsh_wlan_interfaces',
      available: false,
      detail: formatError(error)
    };
  }
}

async function checkNetshNetworks(): Promise<CollectorSourceStatus> {
  try {
    await runPowerShell('netsh wlan show networks mode=bssid');
    return {
      name: 'netsh_wlan_networks',
      available: true,
      detail: null
    };
  } catch (error) {
    return {
      name: 'netsh_wlan_networks',
      available: false,
      detail: formatError(error)
    };
  }
}

function formatError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
