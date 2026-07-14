import { describe, expect, it } from 'vitest';
import { enrichMacAddress } from '../src/collector/macLookup';
import { assessWifiNetworkSecurity, ensureNetworkSecurityAssessment } from '../src/collector/wifiSecurity';
import type { WindowsWifiNetwork } from '../src/collector/types';

describe('assessWifiNetworkSecurity', () => {
  it('marks open networks as dangerous with no Wi-Fi password', () => {
    const assessment = assessWifiNetworkSecurity(makeNetwork({ authentication: 'Open', encryption: 'None' }));

    expect(assessment).toMatchObject({
      posture: 'open',
      attack_difficulty: 'none',
      danger_level: 'high',
      label: 'Open network'
    });
  });

  it('marks WPA2 CCMP as password-dependent baseline protection', () => {
    const assessment = assessWifiNetworkSecurity(
      makeNetwork({ authentication: 'WPA2-Personal', encryption: 'CCMP' })
    );

    expect(assessment).toMatchObject({
      posture: 'standard',
      attack_difficulty: 'medium',
      danger_level: 'low',
      label: 'WPA2 protected'
    });
  });

  it('raises direct printer/device exposure even when WPA2 is present', () => {
    const assessment = assessWifiNetworkSecurity(
      makeNetwork({
        ssid: 'DIRECT-demoXerox Printer',
        bssid: '02:00:00:00:20:01',
        authentication: 'WPA2-Personal',
        encryption: 'CCMP'
      })
    );

    expect(assessment).toMatchObject({
      posture: 'standard',
      attack_difficulty: 'medium',
      danger_level: 'medium',
      label: 'WPA2 protected'
    });
    expect(assessment.notes.join(' ')).toContain('direct device/AP exposure');
  });

  it('uses native BSS RSN metadata when netsh authentication fields are missing', () => {
    const assessment = assessWifiNetworkSecurity(
      makeNetwork({
        authentication: null,
        encryption: null,
        native_bss: makeNativeBss({ has_rsn: true, has_he: true })
      })
    );

    expect(assessment).toMatchObject({
      posture: 'standard',
      attack_difficulty: 'medium',
      danger_level: 'low',
      label: 'RSN protected'
    });
    expect(assessment.notes.join(' ')).toContain('Native BSS information elements include RSN');
  });

  it('keeps existing assessments untouched', () => {
    const network = makeNetwork({
      security_assessment: {
        posture: 'strong',
        attack_difficulty: 'high',
        danger_level: 'low',
        label: 'custom',
        summary: 'existing',
        notes: []
      }
    });

    expect(ensureNetworkSecurityAssessment(network).security_assessment?.label).toBe('custom');
  });
});

function makeNetwork(overrides: Partial<WindowsWifiNetwork> = {}): WindowsWifiNetwork {
  const ssid = overrides.ssid ?? 'Test Network';
  const bssid = overrides.bssid ?? '48:4a:e9:00:00:01';

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
    raw: {},
    ...overrides
  };
}

function makeNativeBss(overrides: Partial<NonNullable<WindowsWifiNetwork['native_bss']>['information_elements']>) {
  return {
    interface_guid: 'guid',
    interface_description: 'Intel(R) Wi-Fi 6E AX211 160MHz',
    bss_type: 'infrastructure',
    phy_type: 'he',
    rssi_dbm: -52,
    link_quality: 88,
    center_frequency_khz: 5180000,
    beacon_period_tu: 100,
    in_reg_domain: true,
    capability_information: 1041,
    timestamp: '123456',
    host_timestamp: '2026-06-03T12:00:00.0000000Z',
    rates_mbps: [6, 12, 24],
    information_elements: {
      byte_length: 128,
      element_count: 8,
      element_ids: [48],
      names: ['RSN'],
      extension_ids: [],
      vendor_ouis: [],
      has_rsn: false,
      has_wpa: false,
      has_bss_load: false,
      has_country: false,
      has_ht: false,
      has_vht: false,
      has_he: false,
      has_eht: false,
      ...overrides
    }
  };
}
