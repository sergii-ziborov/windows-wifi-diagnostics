import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { compareBaselineRuns } from '../src/collector/runComparison';
import type {
  CollectResult,
  CollectorStateEvent,
  WindowsWifiNetwork,
  WindowsWifiSnapshot
} from '../src/collector/types';

let tempDirs: string[] = [];

afterEach(async () => {
  await Promise.all(tempDirs.map((dir) => rm(dir, { recursive: true, force: true })));
  tempDirs = [];
});

describe('compareBaselineRuns', () => {
  it('compares two saved analyses and reports candidate deltas', async () => {
    const runsDir = await createTempRunsDir();
    await writeRun(runsDir, 'normal-run', [
      makeSourceStatus('normal-run'),
      makeSnapshot('normal-run', '2026-06-02T10:00:00.000Z', -45),
      makeSnapshot('normal-run', '2026-06-02T10:01:00.000Z', -46),
      makeNetwork('normal-run', '2026-06-02T10:01:01.000Z')
    ]);
    await writeRun(runsDir, 'incident-run', [
      makeSourceStatus('incident-run'),
      makeSnapshot('incident-run', '2026-06-02T11:00:00.000Z', -45),
      makeSnapshot('incident-run', '2026-06-02T11:01:00.000Z', -80, {
        signal_percent: 30
      }),
      makeSnapshot('incident-run', '2026-06-02T11:02:00.000Z', -80, {
        bssid: '48:4a:e9:00:00:02',
        channel: 100,
        state: 'disconnected',
        signal_percent: 30
      }),
      makeNetwork('incident-run', '2026-06-02T11:01:01.000Z'),
      makeNetwork('incident-run', '2026-06-02T11:01:01.000Z', {
        bssid: '40:ae:30:00:00:02',
        channel: 100,
        signal_percent: 88
      })
    ]);

    const comparison = await compareBaselineRuns({
      baselineRunId: 'normal-run',
      candidateRunId: 'incident-run',
      runsDir,
      windowMinutes: 10,
      minCycles: 2
    });

    expect(comparison).toMatchObject({
      baseline_run_id: 'normal-run',
      candidate_run_id: 'incident-run',
      score_delta: 35,
      verdict_changed: true,
      metrics: {
        observations: {
          baseline: 0,
          candidate: 5,
          delta: 5
        },
        nearby_bssids: {
          baseline: 1,
          candidate: 2,
          delta: 1
        },
        nearby_vendors: {
          baseline: 1,
          candidate: 2,
          delta: 1
        },
        nearby_device_hints: {
          baseline: 1,
          candidate: 2,
          delta: 1
        }
      },
      snapshots: {
        bssids: {
          added: ['48:4a:e9:00:00:02'],
          removed: [],
          shared: ['48:4a:e9:00:00:01']
        },
        channels: {
          added: [100],
          removed: [],
          shared: [64]
        }
      },
      nearby: {
        bssids: {
          added: ['40:ae:30:00:00:02'],
          removed: [],
          shared: ['48:4a:e9:00:00:01']
        },
        vendors: {
          added: ['TP-Link Systems Inc'],
          removed: [],
          shared: ['Hewlett Packard Enterprise']
        },
        device_hints: {
          added: ['consumer router / range extender'],
          removed: [],
          shared: ['enterprise access point / network equipment']
        },
        unknown_ouis: {
          added: [],
          removed: [],
          shared: []
        }
      }
    });
    expect(comparison.observation_types).toMatchObject({
      rssi_drop: { baseline: 0, candidate: 1, delta: 1 },
      weak_signal: { baseline: 0, candidate: 1, delta: 1 },
      state_change: { baseline: 0, candidate: 1, delta: 1 }
    });
    expect(comparison.limitations.join(' ')).toContain('raw 802.11 management frames');
    expect(comparison.evidence.join(' ')).toContain('Nearby vendors 1 -> 2');
  });
});

async function createTempRunsDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'monitor-compare-'));
  tempDirs.push(dir);
  return dir;
}

async function writeRun(
  runsDir: string,
  runId: string,
  events: Array<CollectorStateEvent | WindowsWifiSnapshot | WindowsWifiNetwork>
): Promise<void> {
  const runDir = join(runsDir, runId);
  const eventsFile = join(runDir, 'events.jsonl');
  const summaryFile = join(runDir, 'summary.json');
  await mkdir(runDir, { recursive: true });
  await writeFile(summaryFile, `${JSON.stringify(makeSummary(runId, runDir, eventsFile, summaryFile, events))}\n`);
  await writeFile(eventsFile, events.map((event) => JSON.stringify(event)).join('\n'), 'utf8');
}

function makeSummary(
  runId: string,
  runDir: string,
  eventsFile: string,
  summaryFile: string,
  events: Array<CollectorStateEvent | WindowsWifiSnapshot | WindowsWifiNetwork>
): CollectResult {
  return {
    run_id: runId,
    out_dir: runDir,
    events_file: eventsFile,
    summary_file: summaryFile,
    started_at_utc: events[0]?.ts_utc ?? '2026-06-02T10:00:00.000Z',
    stopped_at_utc: events[events.length - 1]?.ts_utc ?? '2026-06-02T10:01:00.000Z',
    cancelled: false,
    event_count: events.length,
    snapshot_count: events.filter((event) => event.event_type === 'windows_wifi_snapshot').length,
    network_scan_count: 1,
    network_bssid_count: events.filter((event) => event.event_type === 'windows_wifi_network').length,
    wlan_event_count: 0,
    sources: [
      {
        name: 'windows_wlan_autoconfig_operational',
        available: true,
        detail: 'record_count=10'
      },
      {
        name: 'netsh_wlan_interfaces',
        available: true,
        detail: null
      },
      {
        name: 'netsh_wlan_networks',
        available: true,
        detail: null
      }
    ]
  };
}

function makeSourceStatus(runId: string): CollectorStateEvent {
  return {
    schema: 'wifi.collector_state.v1',
    event_type: 'collector_state',
    ts_utc: '2026-06-02T10:00:00.000Z',
    source: 'system',
    run_id: runId,
    host_id: 'test-host',
    state: 'source_status',
    message: 'Collector source status',
    sources: [
      {
        name: 'windows_wlan_autoconfig_operational',
        available: true,
        detail: 'record_count=10'
      },
      {
        name: 'netsh_wlan_interfaces',
        available: true,
        detail: null
      },
      {
        name: 'netsh_wlan_networks',
        available: true,
        detail: null
      }
    ]
  };
}

function makeSnapshot(
  runId: string,
  tsUtc: string,
  rssiDbm: number,
  overrides: Partial<WindowsWifiSnapshot> = {}
): WindowsWifiSnapshot {
  return {
    schema: 'wifi.windows_baseline.v1',
    event_type: 'windows_wifi_snapshot',
    ts_utc: tsUtc,
    source: 'baseline',
    run_id: runId,
    host_id: 'test-host',
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
    rssi_dbm: rssiDbm,
    raw: {},
    ...overrides
  };
}

function makeNetwork(
  runId: string,
  tsUtc: string,
  overrides: Partial<WindowsWifiNetwork> = {}
): WindowsWifiNetwork {
  return {
    schema: 'wifi.windows_baseline.v1',
    event_type: 'windows_wifi_network',
    ts_utc: tsUtc,
    source: 'baseline',
    run_id: runId,
    host_id: 'test-host',
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
    raw: {},
    ...overrides
  };
}
