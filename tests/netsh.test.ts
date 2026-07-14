import { describe, expect, it } from 'vitest';
import { parseNetshWlanInterfaces, parseNetshWlanNetworks } from '../src/platform/windows/netsh';

const context = {
  runId: 'test-run',
  hostId: 'test-host'
};

describe('parseNetshWlanInterfaces', () => {
  it('parses connected Wi-Fi interface snapshots', () => {
    const output = `
There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 6E AX211 160MHz
    GUID                   : 4b763cb5-55ae-452c-a5e0-0f737af605b1
    Physical address       : 02:00:00:00:00:01
    State                  : connected
    SSID                   : Test Network
    AP BSSID               : 48:4a:e9:00:00:01
    Band                   : 5 GHz
    Channel                : 64
    Radio type             : 802.11ac
    Authentication         : WPA2-Personal
    Cipher                 : CCMP
    Receive rate (Mbps)    : 173.3
    Transmit rate (Mbps)   : 173.3
    Signal                 : 94%
    Rssi                   : -46
`;

    const [snapshot] = parseNetshWlanInterfaces(output, context, new Date('2026-06-02T12:00:00Z'));

    expect(snapshot).toMatchObject({
      schema: 'wifi.windows_baseline.v1',
      event_type: 'windows_wifi_snapshot',
      source: 'baseline',
      run_id: 'test-run',
      host_id: 'test-host',
      adapter: 'Intel(R) Wi-Fi 6E AX211 160MHz',
      interface_name: 'Wi-Fi',
      state: 'connected',
      ssid: 'Test Network',
      bssid: '48:4a:e9:00:00:01',
      channel: 64,
      receive_mbps: 173.3,
      transmit_mbps: 173.3,
      signal_percent: 94,
      rssi_dbm: -46
    });
  });
});

describe('parseNetshWlanNetworks', () => {
  it('parses nearby SSID/BSSID network scan output', () => {
    const output = `
Interface name : Wi-Fi
There are 2 networks currently visible.

SSID 1 : Test Network
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : 48:4a:e9:00:00:01
         Signal             : 94%
         Radio type         : 802.11ac
         Band               : 5 GHz
         Channel            : 64
         Basic rates (Mbps) : 6 12 24
         Other rates (Mbps) : 9 18 36 48 54
    BSSID 2                 : 48:4a:e9:00:00:02
         Signal             : 64%
         Radio type         : 802.11n
         Band               : 2.4 GHz
         Channel            : 6
         Basic rates (Mbps) : 1 2 5.5 11
         Other rates (Mbps) : 6 9 12 18 24 36 48 54

SSID 2 : Guest Network
    Network type            : Infrastructure
    Authentication          : Open
    Encryption              : None
    BSSID 1                 : aa:bb:cc:dd:ee:ff
         Signal             : 30%
         Radio type         : 802.11g
         Channel            : 11
`;

    const networks = parseNetshWlanNetworks(output, context, new Date('2026-06-02T12:00:00Z'));

    expect(networks).toHaveLength(3);
    expect(networks[0]).toMatchObject({
      schema: 'wifi.windows_baseline.v1',
      event_type: 'windows_wifi_network',
      source: 'baseline',
      run_id: 'test-run',
      host_id: 'test-host',
      interface_name: 'Wi-Fi',
      ssid: 'Test Network',
      network_type: 'Infrastructure',
      authentication: 'WPA2-Personal',
      encryption: 'CCMP',
      bssid: '48:4a:e9:00:00:01',
      signal_percent: 94,
      radio_type: '802.11ac',
      band: '5 GHz',
      channel: 64,
      basic_rates_mbps: [6, 12, 24],
      other_rates_mbps: [9, 18, 36, 48, 54],
      mac_enrichment: {
        normalized_mac: '48:4a:e9:00:00:01',
        oui: '48:4a:e9',
        vendor: 'Hewlett Packard Enterprise',
        address_scope: 'global',
        device_hint: 'enterprise access point / network equipment',
        confidence: 'medium',
        source: 'local_oui_seed.v1'
      },
      security_assessment: {
        posture: 'standard',
        attack_difficulty: 'medium',
        danger_level: 'low',
        label: 'WPA2 protected'
      }
    });
    expect(networks[2]).toMatchObject({
      ssid: 'Guest Network',
      authentication: 'Open',
      encryption: 'None',
      bssid: 'aa:bb:cc:dd:ee:ff',
      signal_percent: 30,
      channel: 11,
      mac_enrichment: {
        normalized_mac: 'aa:bb:cc:dd:ee:ff',
        oui: 'aa:bb:cc',
        vendor: null,
        address_scope: 'local',
        confidence: 'low'
      },
      security_assessment: {
        posture: 'open',
        attack_difficulty: 'none',
        danger_level: 'high',
        label: 'Open network'
      }
    });
  });
});
