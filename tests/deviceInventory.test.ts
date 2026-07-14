import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { listDeviceHistory, persistNetworkInventory, runDeviceVulnerabilityLookup } from '../src/collector/deviceInventory';
import type { WindowsWifiNetwork } from '../src/collector/types';

describe('device inventory persistence', () => {
  it('saves AP observations and flags a matching identity with a changed BSSID', async () => {
    const tempDir = await mkdtemp(join(tmpdir(), 'monitor-inventory-'));
    const databaseFile = join(tempDir, 'monitor.sqlite');

    try {
      const first = makeNetwork({ bssid: '48:4a:e9:00:00:01' });
      const second = makeNetwork({ bssid: '48:4a:e9:00:00:02' });

      const persisted = await persistNetworkInventory([first], databaseFile);
      expect(persisted.stored_devices).toBe(1);
      expect(persisted.stored_observations).toBe(1);

      const lookup = await runDeviceVulnerabilityLookup({
        mode: 'passive',
        network: second,
        selectedCheckIds: ['inventory_correlation', 'identity_drift_review'],
        operatorNote: 'check router logs',
        databaseFile
      });

      expect(lookup.saved).toBe(true);
      expect(lookup.scan_plan?.selected_check_ids).toEqual(['inventory_correlation', 'identity_drift_review']);
      expect(lookup.scan_plan?.operator_note).toBe('check router logs');
      expect(lookup.vulnerability_intel?.signals.some((signal) => signal.id === 'lookup.scan_plan.passive')).toBe(true);
      expect(lookup.alerts).toHaveLength(1);
      expect(lookup.alerts[0]).toMatchObject({
        alert_type: 'identity_mac_changed',
        previous_bssid: '48:4a:e9:00:00:01',
        current_bssid: '48:4a:e9:00:00:02'
      });
      expect(lookup.vulnerability_intel?.signals.some((signal) => signal.id.startsWith('inventory.identity_mac_changed'))).toBe(true);
    } finally {
      await rm(tempDir, { recursive: true, force: true });
    }
  });

  it('does not treat expected mesh BSSID peers as a MAC identity change', async () => {
    const tempDir = await mkdtemp(join(tmpdir(), 'monitor-inventory-mesh-'));
    const databaseFile = join(tempDir, 'monitor.sqlite');

    try {
      const first = makeNetwork({
        bssid: '02:11:22:33:44:50',
        ssid: 'Example Mesh',
        mac_enrichment: meshEnrichment('02:11:22:33:44:50')
      });
      const second = makeNetwork({
        bssid: '02:11:22:33:44:51',
        ssid: 'Example Mesh',
        mac_enrichment: meshEnrichment('02:11:22:33:44:51')
      });

      await persistNetworkInventory([first], databaseFile);
      const lookup = await runDeviceVulnerabilityLookup({
        mode: 'passive',
        network: second,
        selectedCheckIds: ['inventory_correlation', 'identity_drift_review'],
        databaseFile
      });

      expect(lookup.alerts).toHaveLength(0);
      expect(lookup.vulnerability_intel?.signals.some((signal) => signal.id.startsWith('inventory.identity_mac_changed'))).toBe(false);
    } finally {
      await rm(tempDir, { recursive: true, force: true });
    }
  });

  it('returns learned AP history with active hours and radio location', async () => {
    const tempDir = await mkdtemp(join(tmpdir(), 'monitor-history-'));
    const databaseFile = join(tempDir, 'monitor.sqlite');

    try {
      await persistNetworkInventory([
        makeNetwork({
          ts_utc: '2026-06-04T08:15:00.000Z',
          bssid: '48:4a:e9:00:00:01',
          band: '2.4 GHz',
          channel: 1,
          signal_percent: 70
        }),
        makeNetwork({
          ts_utc: '2026-06-04T20:30:00.000Z',
          bssid: '48:4a:e9:00:00:01',
          band: '2.4 GHz',
          channel: 1,
          signal_percent: 90
        })
      ], databaseFile);

      const history = await listDeviceHistory({ databaseFile, newWindowHours: 24 * 30 });
      const record = history.records.find((item) => item.bssid === '48:4a:e9:00:00:01');

      expect(record).toBeTruthy();
      expect(record?.observation_count).toBe(2);
      expect(record?.radio_location_label).toBe('2.4 GHz ch 1');
      expect(record?.active_hours.map((bucket) => bucket.hour)).toEqual([
        new Date('2026-06-04T08:15:00.000Z').getHours(),
        new Date('2026-06-04T20:30:00.000Z').getHours()
      ]);
      expect(record?.strongest_signal_percent).toBe(90);
    } finally {
      await rm(tempDir, { recursive: true, force: true });
    }
  });
});

function makeNetwork(overrides: Partial<WindowsWifiNetwork> = {}): WindowsWifiNetwork {
  return {
    schema: 'wifi.windows_baseline.v1',
    event_type: 'windows_wifi_network',
    ts_utc: '2026-06-04T10:00:00.000Z',
    source: 'baseline',
    run_id: 'test-run',
    host_id: 'test-host',
    interface_name: 'Wi-Fi',
    ssid: 'Example Office',
    network_type: 'Infrastructure',
    authentication: 'WPA2-Personal',
    encryption: 'CCMP',
    bssid: '48:4a:e9:00:00:01',
    signal_percent: 82,
    radio_type: '802.11n',
    band: '2.4 GHz',
    channel: 1,
    basic_rates_mbps: [1, 2],
    other_rates_mbps: [5.5, 11, 24],
    mac_enrichment: {
      normalized_mac: '48:4a:e9:00:00:01',
      oui: '48:4a:e9',
      vendor: 'Hewlett Packard Enterprise',
      address_scope: 'global',
      device_hint: 'enterprise access point / network equipment',
      confidence: 'medium',
      source: 'local_oui_seed.v1',
      notes: []
    },
    security_assessment: {
      posture: 'standard',
      attack_difficulty: 'medium',
      danger_level: 'low',
      label: 'WPA2 protected',
      summary: 'Password-dependent WPA2 protection; weak passwords are the real break point.',
      notes: []
    },
    raw: {},
    ...overrides
  };
}

function meshEnrichment(mac: string): WindowsWifiNetwork['mac_enrichment'] {
  return {
    normalized_mac: mac,
    oui: mac.split(':').slice(0, 3).join(':'),
    vendor: null,
    address_scope: 'local',
    device_hint: 'home router / mesh node',
    confidence: 'medium',
    source: 'local_oui_seed.v1',
    notes: ['Multiple BSSIDs share this SSID; local/private BSSID evidence suggests a router or mesh node']
  };
}
