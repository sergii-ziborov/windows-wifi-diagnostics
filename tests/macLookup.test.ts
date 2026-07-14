import { describe, expect, it } from 'vitest';
import { enrichMacAddress, summarizeMacIntelligence } from '../src/collector/macLookup';
import type { WindowsWifiNetwork } from '../src/collector/types';

describe('enrichMacAddress', () => {
  it('looks up a global OUI from the local seed', () => {
    const enrichment = enrichMacAddress('48:4a:e9:00:00:01', 'Example Office');

    expect(enrichment).toMatchObject({
      normalized_mac: '48:4a:e9:00:00:01',
      oui: '48:4a:e9',
      vendor: 'Hewlett Packard Enterprise',
      address_scope: 'global',
      device_hint: 'enterprise access point / network equipment',
      confidence: 'medium',
      source: 'local_oui_seed.v1'
    });
    expect(enrichment.notes).not.toContain('Device hint includes SSID pattern evidence');
  });

  it('marks locally administered MACs and can still infer by SSID', () => {
    const enrichment = enrichMacAddress('02:00:00:00:10:01', 'Polk MagniFi Demo');

    expect(enrichment).toMatchObject({
      normalized_mac: '02:00:00:00:10:01',
      oui: '02:00:00',
      vendor: null,
      address_scope: 'local',
      device_hint: 'Polk MagniFi soundbar / speaker',
      confidence: 'medium'
    });
    expect(enrichment.notes).toContain('Locally administered MAC; OUI vendor lookup is unreliable');
    expect(enrichment.notes).toContain('Device hint includes SSID pattern evidence');
  });

  it('uses the local seed for known extender/router vendors', () => {
    const enrichment = enrichMacAddress('40:ae:30:00:00:02', 'Example Mesh 5GHz');

    expect(enrichment).toMatchObject({
      normalized_mac: '40:ae:30:00:00:02',
      oui: '40:ae:30',
      vendor: 'TP-Link Systems Inc',
      address_scope: 'global',
      device_hint: 'home router / mesh node',
      confidence: 'high'
    });
  });

  it('handles invalid MAC addresses', () => {
    const enrichment = enrichMacAddress('not-a-mac', 'DIRECT-HP OfficeJet');

    expect(enrichment).toMatchObject({
      normalized_mac: null,
      oui: null,
      vendor: null,
      address_scope: 'invalid',
      device_hint: 'HP printer Wi-Fi Direct',
      confidence: 'low'
    });
  });

  it('summarizes vendors, scopes, confidence and unknown OUIs', () => {
    const networks = [
      makeNetwork('Example Office', '48:4a:e9:00:00:01'),
      makeNetwork('Example Mesh 5GHz', '40:ae:30:00:00:02'),
      makeNetwork('Polk MagniFi Demo', '02:00:00:00:10:01'),
      makeNetwork('Unknown', '10:34:56:78:90:ab')
    ];

    const summary = summarizeMacIntelligence(networks);

    expect(summary).toMatchObject({
      source: 'local_oui_seed.v1',
      known_vendor_count: 2,
      unknown_vendor_count: 2,
      global_mac_count: 3,
      local_mac_count: 1,
      multicast_mac_count: 0,
      invalid_mac_count: 0,
      confidence_counts: {
        low: 1,
        medium: 2,
        high: 1
      }
    });
    expect(summary.vendors).toEqual([
      { value: 'Hewlett Packard Enterprise', count: 1 },
      { value: 'TP-Link Systems Inc', count: 1 }
    ]);
    expect(summary.device_hints).toContainEqual({ value: 'enterprise access point / network equipment', count: 1 });
    expect(summary.device_hints).toContainEqual({ value: 'home router / mesh node', count: 1 });
    expect(summary.unknown_ouis).toEqual([{ value: '10:34:56', count: 1 }]);
  });
});

function makeNetwork(ssid: string, bssid: string): WindowsWifiNetwork {
  return {
    schema: 'wifi.windows_baseline.v1',
    event_type: 'windows_wifi_network',
    ts_utc: '2026-06-02T12:00:00.000Z',
    source: 'baseline',
    run_id: 'test-run',
    host_id: 'test-host',
    interface_name: 'Wi-Fi',
    ssid,
    network_type: 'Infrastructure',
    authentication: 'WPA2-Personal',
    encryption: 'CCMP',
    bssid,
    signal_percent: 90,
    radio_type: '802.11ac',
    band: '5 GHz',
    channel: 64,
    basic_rates_mbps: [],
    other_rates_mbps: [],
    mac_enrichment: enrichMacAddress(bssid, ssid),
    raw: {}
  };
}
