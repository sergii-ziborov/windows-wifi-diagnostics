import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { collectBaseline } from '../src/collector/baselineService';
import { analyzeBaselineRun } from '../src/collector/runAnalysis';
import { listBaselineRuns } from '../src/collector/runHistory';
import type {
  BaselinePlatformAdapter,
  EventContext,
  WindowsWifiNetwork,
  WindowsWifiSnapshot
} from '../src/collector/types';

let tempDirs: string[] = [];

afterEach(async () => {
  await Promise.all(tempDirs.map((dir) => rm(dir, { recursive: true, force: true })));
  tempDirs = [];
});

describe('collectBaseline', () => {
  it('writes nearby network records and summary counters when the adapter supports scanning', async () => {
    const outDir = join(tmpdir(), `monitor-collect-${Date.now()}`);
    tempDirs.push(outDir);

    const result = await collectBaseline(
      {
        durationSeconds: 1,
        intervalSeconds: 1,
        outDir,
        maxEvents: 5
      },
      fakeAdapter()
    );

    const eventLines = (await readFile(result.events_file, 'utf8')).trim().split(/\r?\n/);
    const events = eventLines.map((line) => JSON.parse(line) as { event_type: string; mac_enrichment?: unknown });
    const networkEvent = events.find((event) => event.event_type === 'windows_wifi_network');
    const summary = JSON.parse(await readFile(result.summary_file, 'utf8')) as typeof result;

    expect(result).toMatchObject({
      cancelled: false,
      snapshot_count: 1,
      network_scan_count: 1,
      network_bssid_count: 1,
      wlan_event_count: 0
    });
    expect(summary).toMatchObject({
      cancelled: false,
      snapshot_count: 1,
      network_scan_count: 1,
      network_bssid_count: 1,
      wlan_event_count: 0
    });
    expect(events.map((event) => event.event_type)).toEqual([
      'collector_state',
      'collector_state',
      'windows_wifi_snapshot',
      'windows_wifi_network',
      'collector_state'
    ]);
    expect(networkEvent?.mac_enrichment).toMatchObject({
      oui: '48:4a:e9',
      vendor: 'Hewlett Packard Enterprise',
      device_hint: 'enterprise access point / network equipment'
    });
  });

  it('writes a cancelled collector state and summary flag when aborted during collection', async () => {
    const outDir = join(tmpdir(), `monitor-collect-cancel-${Date.now()}`);
    tempDirs.push(outDir);
    const abortController = new AbortController();

    const collection = collectBaseline(
      {
        durationSeconds: 30,
        intervalSeconds: 1,
        outDir,
        maxEvents: 5,
        abortSignal: abortController.signal
      },
      fakeAdapter()
    );

    setTimeout(() => abortController.abort(), 10);
    const result = await collection;

    const eventLines = (await readFile(result.events_file, 'utf8')).trim().split(/\r?\n/);
    const events = eventLines.map((line) => JSON.parse(line) as { event_type: string; state?: string });
    const summary = JSON.parse(await readFile(result.summary_file, 'utf8')) as typeof result;

    expect(result.cancelled).toBe(true);
    expect(summary.cancelled).toBe(true);
    expect(events.filter((event) => event.event_type === 'collector_state').map((event) => event.state)).toEqual([
      'started',
      'source_status',
      'cancelled',
      'stopped'
    ]);
  });

  it('uses SQLite storage by default when no JSONL output directory is requested', async () => {
    const tempDir = await mkdtemp(join(tmpdir(), 'monitor-sqlite-'));
    tempDirs.push(tempDir);
    const databaseFile = join(tempDir, 'monitor.sqlite');

    const result = await collectBaseline(
      {
        durationSeconds: 1,
        intervalSeconds: 1,
        outDir: null,
        databaseFile,
        maxEvents: 5
      },
      fakeAdapter()
    );

    const runs = await listBaselineRuns({ last: 5, runsDir: null, databaseFile });
    const analysis = await analyzeBaselineRun({
      runId: result.run_id,
      runsDir: null,
      databaseFile,
      windowMinutes: 10,
      minCycles: 2
    });

    expect(result.storage).toBe('sqlite');
    expect(result.database_file).toBe(databaseFile);
    expect(result.events_file).toContain('sqlite:');
    expect(runs.runs[0]).toMatchObject({
      run_id: result.run_id,
      storage: 'sqlite',
      database_file: databaseFile,
      event_count: 5,
      snapshot_count: 1,
      network_scan_count: 1,
      network_bssid_count: 1
    });
    expect(analysis).toMatchObject({
      run_id: result.run_id,
      parsed_event_count: 5,
      invalid_line_count: 0,
      snapshots: { count: 1 },
      networks: { count: 1 }
    });
  });
});

function fakeAdapter(): BaselinePlatformAdapter {
  return {
    async getSourceStatus() {
      return [
        {
          name: 'netsh_wlan_interfaces',
          available: true,
          detail: null
        },
        {
          name: 'netsh_wlan_networks',
          available: true,
          detail: 'bssid_count=1'
        }
      ];
    },
    async getWifiSnapshots(context: EventContext) {
      return [makeSnapshot(context)];
    },
    async getNearbyWifiNetworks(context: EventContext) {
      return [makeNetwork(context)];
    },
    async getRecentWlanEvents() {
      return [];
    }
  };
}

function makeSnapshot(context: EventContext): WindowsWifiSnapshot {
  return {
    schema: 'wifi.windows_baseline.v1',
    event_type: 'windows_wifi_snapshot',
    ts_utc: new Date().toISOString(),
    source: 'baseline',
    run_id: context.runId,
    host_id: context.hostId,
    adapter: 'Intel(R) Wi-Fi 6E AX211 160MHz',
    interface_name: 'Wi-Fi',
    interface_guid: '4b763cb5-55ae-452c-a5e0-0f737af605b1',
    physical_address: '02:00:00:00:00:01',
    state: 'connected',
    ssid: 'Test Network',
    bssid: '48:4a:e9:00:00:01',
    band: '5 GHz',
    channel: 64,
    radio_type: '802.11ac',
    authentication: 'WPA2-Personal',
    cipher: 'CCMP',
    receive_mbps: 173.3,
    transmit_mbps: 173.3,
    signal_percent: 90,
    rssi_dbm: -45,
    raw: {}
  };
}

function makeNetwork(context: EventContext): WindowsWifiNetwork {
  return {
    schema: 'wifi.windows_baseline.v1',
    event_type: 'windows_wifi_network',
    ts_utc: new Date().toISOString(),
    source: 'baseline',
    run_id: context.runId,
    host_id: context.hostId,
    interface_name: 'Wi-Fi',
    ssid: 'Test Network',
    network_type: 'Infrastructure',
    authentication: 'WPA2-Personal',
    encryption: 'CCMP',
    bssid: '48:4a:e9:00:00:01',
    signal_percent: 90,
    radio_type: '802.11ac',
    band: '5 GHz',
    channel: 64,
    basic_rates_mbps: [6, 12, 24],
    other_rates_mbps: [9, 18, 36, 48, 54],
    raw: {}
  };
}
