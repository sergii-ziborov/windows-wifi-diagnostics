import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  createBaselineDiagnosticsBundle,
  listBaselineDiagnosticsBundles
} from '../src/collector/diagnosticsService';
import type {
  BaselineEventsResult,
  BaselineNetworksResult,
  BaselineRunsResult,
  BaselineStatus,
  BaselineTimelineResult
} from '../src/collector/types';

let tempDirs: string[] = [];

afterEach(async () => {
  await Promise.all(tempDirs.map((dir) => rm(dir, { recursive: true, force: true })));
  tempDirs = [];
});

describe('createBaselineDiagnosticsBundle', () => {
  it('writes a read-only baseline diagnostics bundle', async () => {
    const outDir = await mkdtemp(join(tmpdir(), 'monitor-diagnostics-'));
    tempDirs.push(outDir);
    const calls: Record<string, unknown> = {};

    const result = await createBaselineDiagnosticsBundle(
      {
        outDir,
        runsDir: 'data/custom-runs',
        lastRuns: 3,
        lastEvents: 25,
        windowMinutes: 15,
        minCycles: 4
      },
      {
        async getStatus() {
          return statusFixture();
        },
        async getNetworks() {
          return networksFixture();
        },
        async listRuns(options) {
          calls.listRuns = options;
          return runsFixture();
        },
        async getEvents(options) {
          calls.getEvents = options;
          return eventsFixture();
        },
        async getTimeline(options) {
          calls.getTimeline = options;
          return timelineFixture();
        }
      }
    );

    const manifest = JSON.parse(await readFile(result.files.manifest, 'utf8')) as typeof result;
    const readme = await readFile(result.files.readme, 'utf8');
    const status = JSON.parse(await readFile(result.files.status, 'utf8')) as BaselineStatus;

    expect(result).toMatchObject({
      schema: 'wifi.baseline_diagnostics.v1',
      out_dir: outDir,
      inputs: {
        runs_dir: 'data/custom-runs',
        last_runs: 3,
        last_events: 25,
        window_minutes: 15,
        min_cycles: 4
      },
      runtime: {
        platform: process.platform,
        arch: process.arch,
        node_version: process.version
      },
      counts: {
        snapshots: 1,
        networks: 1,
        bssids: 2,
        runs: 2,
        events: 1,
        timeline: 1,
        alerts: 1
      }
    });
    expect(manifest).toMatchObject(result);
    expect(status.snapshots).toHaveLength(1);
    expect(readme).toContain('read-only Windows telemetry');
    expect(readme).toContain('It does not enable monitor mode.');
    expect(calls).toEqual({
      listRuns: {
        last: 3,
        runsDir: 'data/custom-runs'
      },
      getEvents: {
        last: 25
      },
      getTimeline: {
        last: 25,
        windowMinutes: 15,
        minCycles: 4
      }
    });
  });

  it('lists saved diagnostics bundles newest first and reports broken manifests', async () => {
    const diagnosticsDir = await mkdtemp(join(tmpdir(), 'monitor-diagnostics-list-'));
    tempDirs.push(diagnosticsDir);
    await writeManifest(diagnosticsDir, makeManifest('old-bundle', '2026-06-02T10:00:00.000Z'));
    await writeManifest(diagnosticsDir, makeManifest('new-bundle', '2026-06-02T11:00:00.000Z'));
    await mkdir(join(diagnosticsDir, 'missing-manifest'), { recursive: true });
    await mkdir(join(diagnosticsDir, 'invalid-manifest'), { recursive: true });
    await writeFile(join(diagnosticsDir, 'invalid-manifest', 'manifest.json'), '{bad json', 'utf8');

    const result = await listBaselineDiagnosticsBundles({
      last: 10,
      diagnosticsDir
    });
    const byId = new Map(result.bundles.map((bundle) => [bundle.bundle_id, bundle]));

    expect(result.diagnostics_dir).toBe(diagnosticsDir);
    expect(result.bundle_count).toBe(4);
    expect(result.bundles.slice(0, 2).map((bundle) => bundle.bundle_id)).toEqual(['new-bundle', 'old-bundle']);
    expect(byId.get('new-bundle')).toMatchObject({
      status: 'complete',
      counts: {
        snapshots: 1,
        events: 5,
        alerts: 0
      }
    });
    expect(byId.get('missing-manifest')).toMatchObject({
      status: 'missing_manifest',
      error: null
    });
    expect(byId.get('invalid-manifest')).toMatchObject({
      status: 'invalid_manifest'
    });
    expect(byId.get('invalid-manifest')?.error).toContain('JSON');
  });
});

async function writeManifest(
  diagnosticsDir: string,
  manifest: ReturnType<typeof makeManifest>
): Promise<void> {
  const bundleDir = join(diagnosticsDir, manifest.bundle_id);
  await mkdir(bundleDir, { recursive: true });
  await writeFile(join(bundleDir, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
}

function makeManifest(bundleId: string, createdAt: string) {
  const outDir = join('data', 'diagnostics', bundleId);

  return {
    schema: 'wifi.baseline_diagnostics.v1',
    bundle_id: bundleId,
    out_dir: outDir,
    created_at_utc: createdAt,
    files: {
      manifest: join(outDir, 'manifest.json'),
      readme: join(outDir, 'README.txt'),
      status: join(outDir, 'status.json'),
      networks: join(outDir, 'networks.json'),
      runs: join(outDir, 'runs.json'),
      events: join(outDir, 'events.json'),
      timeline: join(outDir, 'timeline.json')
    },
    counts: {
      snapshots: 1,
      networks: 1,
      bssids: 2,
      runs: 2,
      events: 5,
      timeline: 4,
      alerts: 0
    },
    inputs: {
      runs_dir: null,
      last_runs: 20,
      last_events: 200,
      window_minutes: 10,
      min_cycles: 2
    },
    runtime: {
      platform: 'win32',
      arch: 'x64',
      node_version: 'v24.15.0',
      app_version: '0.1.0'
    }
  } as const;
}

function statusFixture(): BaselineStatus {
  return {
    platform: 'win32',
    host_id: 'test-host',
    ts_utc: '2026-06-02T12:00:00.000Z',
    sources: [
      {
        name: 'netsh_wlan_interfaces',
        available: true,
        detail: null
      }
    ],
    snapshots: [
      {
        schema: 'wifi.windows_baseline.v1',
        event_type: 'windows_wifi_snapshot',
        ts_utc: '2026-06-02T12:00:00.000Z',
        source: 'baseline',
        run_id: 'status',
        host_id: 'test-host',
        adapter: 'Intel(R) Wi-Fi 6E AX211 160MHz',
        interface_name: 'Wi-Fi',
        interface_guid: 'guid',
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
      }
    ]
  };
}

function networksFixture(): BaselineNetworksResult {
  return {
    platform: 'win32',
    host_id: 'test-host',
    ts_utc: '2026-06-02T12:00:00.000Z',
    sources: [
      {
        name: 'netsh_wlan_networks',
        available: true,
        detail: 'bssid_count=2'
      }
    ],
    network_count: 1,
    bssid_count: 2,
    mac_summary: {
      source: 'local_oui_seed.v1',
      known_vendor_count: 0,
      unknown_vendor_count: 0,
      global_mac_count: 0,
      local_mac_count: 0,
      multicast_mac_count: 0,
      invalid_mac_count: 0,
      confidence_counts: {
        low: 0,
        medium: 0,
        high: 0
      },
      vendors: [],
      device_hints: [],
      unknown_ouis: [],
      notes: []
    },
    scan_location: null,
    networks: []
  };
}

function runsFixture(): BaselineRunsResult {
  return {
    ts_utc: '2026-06-02T12:00:00.000Z',
    runs_dir: 'data/custom-runs',
    run_count: 2,
    runs: []
  };
}

function eventsFixture(): BaselineEventsResult {
  return {
    run_id: 'events',
    host_id: 'test-host',
    ts_utc: '2026-06-02T12:00:00.000Z',
    sources: [
      {
        name: 'windows_wlan_autoconfig_operational',
        available: true,
        detail: 'record_count=1'
      }
    ],
    order: 'chronological',
    events: [
      {
        schema: 'wifi.windows_baseline.v1',
        event_type: 'windows_wifi_event',
        ts_utc: '2026-06-02T12:00:00.000Z',
        source: 'baseline',
        run_id: 'events',
        host_id: 'test-host',
        event_id: 11010,
        record_id: 1,
        provider_name: 'Microsoft-Windows-WLAN-AutoConfig',
        level: 'Information',
        adapter: 'Intel(R) Wi-Fi 6E AX211 160MHz',
        interface_guid: 'guid',
        local_mac: '02:00:00:00:00:01',
        ssid: 'Test Network',
        bss_type: 'Infrastructure',
        message_fields: {},
        raw_message: 'Wireless security started.'
      }
    ]
  };
}

function timelineFixture(): BaselineTimelineResult {
  return {
    run_id: 'timeline',
    host_id: 'test-host',
    ts_utc: '2026-06-02T12:00:00.000Z',
    sources: [],
    event_count: 1,
    timeline_count: 1,
    alert_count: 1,
    timeline: [
      {
        schema: 'wifi.client_timeline.v1',
        event_type: 'client_lifecycle',
        ts_utc: '2026-06-02T12:00:00.000Z',
        source: 'detector',
        run_id: 'timeline',
        host_id: 'test-host',
        action: 'security_started',
        client: '02:00:00:00:00:01',
        ssid: 'Test Network',
        adapter: 'Intel(R) Wi-Fi 6E AX211 160MHz',
        event_id: 11010,
        record_id: 1,
        summary: 'Wireless security started.',
        evidence_event_ids: ['event:1']
      }
    ],
    alerts: [
      {
        schema: 'wifi.alert.v1',
        event_type: 'alert',
        ts_utc: '2026-06-02T12:00:00.000Z',
        source: 'detector',
        run_id: 'timeline',
        host_id: 'test-host',
        alert_type: 'reconnect_loop',
        severity: 'low',
        score: 10,
        client: '02:00:00:00:00:01',
        ssid: 'Test Network',
        summary: 'Reconnect-loop symptoms observed.',
        window_start_utc: '2026-06-02T12:00:00.000Z',
        window_end_utc: '2026-06-02T12:05:00.000Z',
        cycle_count: 2,
        evidence_event_ids: ['event:1'],
        false_positive_notes: []
      }
    ]
  };
}
