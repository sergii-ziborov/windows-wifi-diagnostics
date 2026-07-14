import { describe, expect, it } from 'vitest';
import { patchNetworkListWithDeviceIntelligence } from '../src/renderer/src/deviceIntelligencePatch';
import type { DeviceIntelligenceOverride, WindowsWifiNetwork } from '../src/collector/types';

describe('device intelligence renderer patch', () => {
  it('applies a saved override only to the target AP', () => {
    const target = makeNetwork({
      ssid: 'Target',
      bssid: '48:4a:e9:00:00:01',
      mac_enrichment: makeMacEnrichment('Vendor unknown')
    });
    const other = makeNetwork({
      ssid: 'Other',
      bssid: '48:4a:e9:00:00:02',
      mac_enrichment: makeMacEnrichment('Other Vendor')
    });

    const patched = patchNetworkListWithDeviceIntelligence([target, other], target, makeOverride());

    expect(patched[0].mac_enrichment?.vendor).toBe('Hewlett Packard Enterprise');
    expect(patched[0].mac_enrichment?.device_hint).toBe('enterprise managed access point');
    expect(patched[1]).toBe(other);
    expect(patched[1].mac_enrichment?.vendor).toBe('Other Vendor');
  });
});

function makeOverride(): DeviceIntelligenceOverride {
  return {
    id: 1,
    match_type: 'bssid',
    match_value: '48:4a:e9:00:00:01',
    ssid: 'Target',
    bssid: '48:4a:e9:00:00:01',
    oui: '48:4a:e9',
    vendor: 'Hewlett Packard Enterprise',
    device_hint: 'enterprise managed access point',
    device_role: 'access_point',
    model: null,
    confidence: 'high',
    is_mesh: false,
    exposure_level: 'review',
    vulnerability_summary: 'Inventory the AP model and firmware.',
    vulnerability_references: [],
    notes: ['BSSID and SSID evidence match an enterprise AP.'],
    source: 'ai.codex',
    raw_json: null,
    created_at_utc: '2026-06-04T10:00:00.000Z',
    updated_at_utc: '2026-06-04T10:00:00.000Z'
  };
}

function makeNetwork(overrides: Partial<WindowsWifiNetwork> = {}): WindowsWifiNetwork {
  return {
    schema: 'wifi.windows_baseline.v1',
    event_type: 'windows_wifi_network',
    ts_utc: '2026-06-04T10:00:00.000Z',
    source: 'baseline',
    run_id: 'test-run',
    host_id: 'test-host',
    interface_name: 'Wi-Fi',
    ssid: 'Test AP',
    network_type: 'Infrastructure',
    authentication: 'WPA2-Personal',
    encryption: 'CCMP',
    bssid: '48:4a:e9:00:00:01',
    signal_percent: 80,
    radio_type: '802.11ac',
    band: '5 GHz',
    channel: 36,
    basic_rates_mbps: [],
    other_rates_mbps: [],
    raw: {},
    ...overrides
  };
}

function makeMacEnrichment(vendor: string) {
  return {
    normalized_mac: null,
    oui: null,
    vendor,
    address_scope: 'global' as const,
    device_hint: null,
    confidence: 'low' as const,
    source: 'test',
    notes: []
  };
}
