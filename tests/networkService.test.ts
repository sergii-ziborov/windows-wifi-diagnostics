import { describe, expect, it } from 'vitest';
import { getBaselineNetworks } from '../src/collector/networkService';
import type {
  BaselinePlatformAdapter,
  CollectorSourceStatus,
  EventContext,
  WindowsWifiEvent,
  WindowsWifiNetwork,
  WindowsWifiSnapshot
} from '../src/collector/types';

describe('getBaselineNetworks', () => {
  it('requests a native scan before reading nearby APs when manual refresh is requested', async () => {
    const calls: string[] = [];

    const result = await getBaselineNetworks(
      { refreshScan: true, scanSettleMs: 0, useDeviceIntelligence: false, persistInventory: false },
      fakeAdapter(calls)
    );

    expect(calls).toEqual(['scan', 'networks']);
    expect(result.sources.map((source) => source.name)).toEqual([
      'windows_native_wifi_scan',
      'netsh_wlan_networks'
    ]);
    expect(result.sources[0]).toMatchObject({
      available: true,
      detail: 'interface_count=1;scan_results=0:test-guid:Test Adapter'
    });
    expect(result.bssid_count).toBe(1);
    expect(result.networks[0].mac_enrichment).toMatchObject({
      oui: '48:4a:e9',
      vendor: 'Hewlett Packard Enterprise',
      device_hint: 'enterprise access point / network equipment',
      confidence: 'medium'
    });
    expect(result.networks[0].security_assessment).toMatchObject({
      posture: 'standard',
      attack_difficulty: 'medium',
      danger_level: 'low',
      label: 'WPA2 protected'
    });
    expect(result.mac_summary).toMatchObject({
      known_vendor_count: 1,
      unknown_vendor_count: 0,
      global_mac_count: 1,
      confidence_counts: {
        medium: 1
      },
      vendors: [{ value: 'Hewlett Packard Enterprise', count: 1 }]
    });
  });

  it('still reads netsh networks when the native scan request fails', async () => {
    const calls: string[] = [];

    const result = await getBaselineNetworks(
      { refreshScan: true, scanSettleMs: 0, useDeviceIntelligence: false, persistInventory: false },
      fakeAdapter(calls, {
        available: false,
        detail: 'scan failed'
      })
    );

    expect(calls).toEqual(['scan', 'networks']);
    expect(result.sources).toHaveLength(2);
    expect(result.sources[0]).toMatchObject({
      name: 'windows_native_wifi_scan',
      available: false
    });
    expect(result.sources[1]).toMatchObject({
      name: 'netsh_wlan_networks',
      available: true,
      detail: 'bssid_count=1'
    });
    expect(result.networks).toHaveLength(1);
  });
});

function fakeAdapter(
  calls: string[],
  scanSource: Pick<CollectorSourceStatus, 'available' | 'detail'> = {
    available: true,
    detail: 'interface_count=1;scan_results=0:test-guid:Test Adapter'
  }
): BaselinePlatformAdapter {
  return {
    async getSourceStatus() {
      return [];
    },
    async getWifiSnapshots(_context: EventContext): Promise<WindowsWifiSnapshot[]> {
      return [];
    },
    async requestNearbyWifiScan(_context: EventContext): Promise<CollectorSourceStatus> {
      calls.push('scan');
      return {
        name: 'windows_native_wifi_scan',
        ...scanSource
      };
    },
    async getNearbyWifiNetworks(context: EventContext): Promise<WindowsWifiNetwork[]> {
      calls.push('networks');
      return [makeNetwork(context)];
    },
    async getRecentWlanEvents(_context: EventContext, _maxEvents: number): Promise<WindowsWifiEvent[]> {
      return [];
    }
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
