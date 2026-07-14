import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { analyzeBaselineRun } from '../src/collector/runAnalysis';
import type {
  CollectResult,
  CollectorStateEvent,
  WindowsWifiEvent,
  WindowsWifiNetwork,
  WindowsWifiSnapshot
} from '../src/collector/types';

let tempDirs: string[] = [];

afterEach(async () => {
  await Promise.all(tempDirs.map((dir) => rm(dir, { recursive: true, force: true })));
  tempDirs = [];
});

describe('analyzeBaselineRun', () => {
  it('summarizes saved JSONL evidence and derives alerts from saved WLAN events', async () => {
    const runsDir = await createTempRunsDir();
    const runId = 'test-run';
    const runDir = join(runsDir, runId);
    const eventsFile = join(runDir, 'events.jsonl');
    const summaryFile = join(runDir, 'summary.json');
    await mkdir(runDir, { recursive: true });
    await writeFile(summaryFile, `${JSON.stringify(makeSummary(runId, runDir, eventsFile, summaryFile))}\n`);
    await writeFile(
      eventsFile,
      [
        JSON.stringify(makeSourceStatus(runId)),
        JSON.stringify(makeSnapshot(runId, '2026-06-02T10:00:00.000Z', -50)),
        JSON.stringify(makeSnapshot(runId, '2026-06-02T10:01:00.000Z', -47)),
        JSON.stringify(makeNetwork(runId, '2026-06-02T10:01:01.000Z')),
        JSON.stringify(makeWlanEvent(runId, 11010, 1, '2026-06-02T10:03:00.000Z')),
        JSON.stringify(makeWlanEvent(runId, 11005, 2, '2026-06-02T10:03:05.000Z')),
        JSON.stringify(makeWlanEvent(runId, 11004, 3, '2026-06-02T10:06:00.000Z')),
        JSON.stringify(makeWlanEvent(runId, 11010, 4, '2026-06-02T10:06:05.000Z')),
        JSON.stringify(makeWlanEvent(runId, 11005, 5, '2026-06-02T10:06:10.000Z')),
        '{bad json'
      ].join('\n'),
      'utf8'
    );

    const analysis = await analyzeBaselineRun({
      runId,
      runsDir,
      windowMinutes: 10,
      minCycles: 2
    });

    expect(analysis).toMatchObject({
      run_id: runId,
      host_id: 'test-host',
      parsed_event_count: 9,
      invalid_line_count: 1,
      observation_count: 0,
      wlan_event_count: 5,
      timeline_count: 5,
      alert_count: 1,
      report: {
        verdict: 'watch',
        confidence: 'low',
        score: 28
      }
    });
    expect(analysis.event_type_counts).toEqual({
      collector_state: 1,
      windows_wifi_snapshot: 2,
      windows_wifi_network: 1,
      windows_wifi_event: 5
    });
    expect(analysis.snapshots).toMatchObject({
      count: 2,
      states: { connected: 2 },
      ssids: ['Test Network'],
      channels: [64],
      rssi_dbm: {
        min: -50,
        max: -47,
        avg: -48.5,
        last: -47
      }
    });
    expect(analysis.alerts[0]).toMatchObject({
      alert_type: 'reconnect_loop',
      severity: 'medium',
      cycle_count: 2
    });
    expect(analysis.report.evidence.join(' ')).toContain('Reconnect-loop alerts');
    expect(analysis.networks).toMatchObject({
      count: 1,
      ssid_count: 1,
      ssids: ['Test Network'],
      bssids: ['48:4a:e9:00:00:01'],
      channels: [64]
    });
    expect(analysis.networks.mac_summary).toMatchObject({
      known_vendor_count: 1,
      unknown_vendor_count: 0,
      global_mac_count: 1,
      vendors: [{ value: 'Hewlett Packard Enterprise', count: 1 }],
      device_hints: [{ value: 'enterprise access point / network equipment', count: 1 }]
    });
    expect(analysis.report.evidence.join(' ')).toContain('MAC intelligence known vendors 1');
  });

  it('derives snapshot observations from saved baseline snapshots', async () => {
    const runsDir = await createTempRunsDir();
    const runId = 'snapshot-run';
    const runDir = join(runsDir, runId);
    const eventsFile = join(runDir, 'events.jsonl');
    const summaryFile = join(runDir, 'summary.json');
    await mkdir(runDir, { recursive: true });
    await writeFile(summaryFile, `${JSON.stringify(makeSummary(runId, runDir, eventsFile, summaryFile))}\n`);
    await writeFile(
      eventsFile,
      [
        JSON.stringify(makeSourceStatus(runId)),
        JSON.stringify(makeSnapshot(runId, '2026-06-02T10:00:00.000Z', -45)),
        JSON.stringify(makeSnapshot(runId, '2026-06-02T10:01:00.000Z', -80, { signal_percent: 30 })),
        JSON.stringify(makeSnapshot(runId, '2026-06-02T10:02:00.000Z', -72, { bssid: '48:4a:e9:00:00:02' })),
        JSON.stringify(
          makeSnapshot(runId, '2026-06-02T10:03:00.000Z', -72, {
            bssid: '48:4a:e9:00:00:02',
            channel: 100,
            state: 'disconnected'
          })
        )
      ].join('\n'),
      'utf8'
    );

    const analysis = await analyzeBaselineRun({
      runId,
      runsDir,
      windowMinutes: 10,
      minCycles: 2
    });

    expect(analysis.observation_count).toBe(5);
    expect(analysis.observations.map((observation) => observation.observation_type)).toEqual([
      'rssi_drop',
      'weak_signal',
      'bssid_change',
      'state_change',
      'channel_change'
    ]);
    expect(analysis.observations[0]).toMatchObject({
      severity: 'high',
      summary: 'RSSI dropped by 35 dB',
      previous_value: -45,
      current_value: -80
    });
    expect(analysis.observations[3]).toMatchObject({
      severity: 'high',
      previous_value: 'connected',
      current_value: 'disconnected'
    });
    expect(analysis.report).toMatchObject({
      verdict: 'watch',
      score: 35
    });
  });

  it('derives passive nearby AP observations from saved network scans', async () => {
    const runsDir = await createTempRunsDir();
    const runId = 'network-run';
    const runDir = join(runsDir, runId);
    const eventsFile = join(runDir, 'events.jsonl');
    const summaryFile = join(runDir, 'summary.json');
    await mkdir(runDir, { recursive: true });
    await writeFile(summaryFile, `${JSON.stringify(makeSummary(runId, runDir, eventsFile, summaryFile))}\n`);
    await writeFile(
      eventsFile,
      [
        JSON.stringify(makeSourceStatus(runId)),
        JSON.stringify(makeNetwork(runId, '2026-06-02T10:00:00.000Z', { signal_percent: 92 })),
        JSON.stringify(
          makeNetwork(runId, '2026-06-02T10:01:00.000Z', {
            channel: 100,
            signal_percent: 50,
            raw: { 'Channel Utilization': '220 (86 %)' }
          })
        ),
        JSON.stringify(
          makeNetwork(runId, '2026-06-02T10:01:00.000Z', {
            authentication: 'Open',
            encryption: 'None',
            bssid: '48:4a:e9:00:00:02',
            signal_percent: 94,
            raw: { 'Channel Utilization': '40 (15 %)' }
          })
        ),
        JSON.stringify(
          makeNetwork(runId, '2026-06-02T10:02:00.000Z', {
            ssid: 'Other Network',
            bssid: '48:4a:e9:00:00:03',
            signal_percent: 93
          })
        )
      ].join('\n'),
      'utf8'
    );

    const analysis = await analyzeBaselineRun({
      runId,
      runsDir,
      windowMinutes: 10,
      minCycles: 2
    });

    expect(analysis.networks).toMatchObject({
      count: 4,
      ssid_count: 2,
      bssids: ['48:4a:e9:00:00:01', '48:4a:e9:00:00:02', '48:4a:e9:00:00:03'],
      channels: [64, 100],
      authentications: ['Open', 'WPA2-Personal']
    });
    expect(analysis.networks.mac_summary).toMatchObject({
      known_vendor_count: 4,
      unknown_vendor_count: 0,
      vendors: [{ value: 'Hewlett Packard Enterprise', count: 4 }]
    });
    expect(analysis.observations.map((observation) => observation.observation_type)).toEqual(
      expect.arrayContaining([
        'nearby_signal_drop',
        'nearby_channel_changed',
        'nearby_bssid_added',
        'nearby_bssid_removed',
        'nearby_security_changed',
        'nearby_high_utilization'
      ])
    );
    expect(analysis.observations.find((observation) => observation.observation_type === 'nearby_signal_drop')).toMatchObject({
      summary: 'Nearby BSSID 48:4a:e9:00:00:01 signal dropped by 42%',
      previous_value: 92,
      current_value: 50
    });
    expect(
      analysis.observations.find((observation) => observation.observation_type === 'nearby_security_changed')
    ).toMatchObject({
      severity: 'high',
      current_value: 'Open / None, WPA2-Personal / CCMP'
    });
    expect(analysis.report).toMatchObject({
      verdict: 'watch',
      score: 35
    });
    expect(analysis.report.limitations.join(' ')).toContain('Windows Event Log and netsh snapshots only');
  });

  it('rejects missing runs clearly', async () => {
    const runsDir = await createTempRunsDir();

    await expect(
      analyzeBaselineRun({
        runId: 'missing',
        runsDir,
        windowMinutes: 10,
        minCycles: 2
      })
    ).rejects.toThrow('Baseline run not found: missing');
  });
});

async function createTempRunsDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'monitor-analysis-'));
  tempDirs.push(dir);
  return dir;
}

function makeSummary(
  runId: string,
  runDir: string,
  eventsFile: string,
  summaryFile: string
): CollectResult {
  return {
    run_id: runId,
    out_dir: runDir,
    events_file: eventsFile,
    summary_file: summaryFile,
    started_at_utc: '2026-06-02T10:00:00.000Z',
    stopped_at_utc: '2026-06-02T10:10:00.000Z',
    cancelled: false,
    event_count: 9,
    snapshot_count: 2,
    network_scan_count: 1,
    network_bssid_count: 1,
    wlan_event_count: 5,
    sources: [
      {
        name: 'windows_wlan_autoconfig_operational',
        available: true,
        detail: 'record_count=10'
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
    signal_percent: 91,
    radio_type: '802.11ac',
    band: '5 GHz',
    channel: 64,
    basic_rates_mbps: [6, 12, 24],
    other_rates_mbps: [9, 18, 36, 48, 54],
    raw: {},
    ...overrides
  };
}

function makeWlanEvent(runId: string, eventId: number, recordId: number, tsUtc: string): WindowsWifiEvent {
  const messageByEvent: Record<number, string> = {
    11004: 'Wireless security stopped.',
    11005: 'Wireless security succeeded.',
    11010: 'Wireless security started.'
  };

  return {
    schema: 'wifi.windows_baseline.v1',
    event_type: 'windows_wifi_event',
    ts_utc: tsUtc,
    source: 'baseline',
    run_id: runId,
    host_id: 'test-host',
    event_id: eventId,
    record_id: recordId,
    provider_name: 'Microsoft-Windows-WLAN-AutoConfig',
    level: 'Information',
    adapter: 'Intel(R) Wi-Fi 6E AX211 160MHz',
    interface_guid: '{4b763cb5-55ae-452c-a5e0-0f737af605b1}',
    local_mac: '02:00:00:00:00:01',
    ssid: 'Test Network',
    bss_type: 'Infrastructure',
    message_fields: {},
    raw_message: messageByEvent[eventId] ?? 'WLAN AutoConfig event'
  };
}
