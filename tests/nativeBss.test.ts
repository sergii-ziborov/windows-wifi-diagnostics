import { describe, expect, it } from 'vitest';
import { mergeNativeBssDetails } from '../src/collector/nativeBss';
import type { EventContext, WindowsNativeBssEntry, WindowsWifiNetwork } from '../src/collector/types';
import { mapRadioChronNetworks } from '../src/platform/windows/radiochron';

const context: EventContext = {
  runId: 'test-run',
  hostId: 'test-host'
};

describe('mapRadioChronNetworks', () => {
  it('maps a full-detail wifi_networks payload onto the BSS shape', () => {
    const entries = mapRadioChronNetworks({
      count: 1,
      refreshed: true,
      networks: [
        {
          interface_guid: '4b763cb5-55ae-452c-a5e0-0f737af605b1',
          ssid: 'Test Network',
          bssid: '48-4A-E9-00-00-01',
          bss_type: 'infrastructure',
          phy_type: 'he',
          rssi_dbm: -52,
          link_quality: 88,
          center_frequency_khz: 5180000,
          beacon_period_tu: 100,
          in_reg_domain: true,
          capability_information: 1041,
          timestamp: 123456,
          host_timestamp: 133000000000000000,
          rates_mbps: [6, 12, 24],
          information_elements: {
            byte_length: 128,
            element_count: 8,
            element_ids: [0, 1, 48, 255],
            names: ['SSID', 'RSN', 'Extension 35'],
            extension_ids: [35],
            vendor_ouis: ['00:50:f2'],
            has_rsn: true,
            has_wpa: false,
            has_bss_load: false,
            has_country: true,
            has_ht: true,
            has_vht: true,
            has_he: true,
            has_eht: false
          }
        }
      ]
    });

    expect(entries).toHaveLength(1);
    expect(entries[0]).toMatchObject({
      interface_guid: '4b763cb5-55ae-452c-a5e0-0f737af605b1',
      ssid: 'Test Network',
      // Dash-separated MACs are normalized the same way the old parser did.
      bssid: '48:4a:e9:00:00:01',
      native_bss: {
        phy_type: 'he',
        rssi_dbm: -52,
        link_quality: 88,
        center_frequency_khz: 5180000,
        // The server reports numeric timestamps; the record carries strings.
        timestamp: '123456',
        information_elements: {
          has_rsn: true,
          has_he: true,
          vendor_ouis: ['00:50:f2']
        }
      }
    });
  });

  it('survives an empty, malformed or summary-shaped payload', () => {
    expect(mapRadioChronNetworks(null)).toEqual([]);
    expect(mapRadioChronNetworks({ count: 0, networks: [] })).toEqual([]);
    expect(mapRadioChronNetworks({} as never)).toEqual([]);
  });

  it('defaults missing information elements instead of throwing', () => {
    const [entry] = mapRadioChronNetworks({
      networks: [{ bssid: 'aa:bb:cc:dd:ee:ff' }]
    });

    expect(entry.native_bss.information_elements).toMatchObject({
      byte_length: 0,
      element_count: 0,
      has_rsn: false,
      element_ids: []
    });
    expect(entry.native_bss.rssi_dbm).toBeNull();
  });
});

describe('mergeNativeBssDetails', () => {
  it('adds native BSS details to netsh network records by BSSID', () => {
    const merged = mergeNativeBssDetails([makeNetwork()], [makeBssEntry()]);

    expect(merged[0].native_bss).toMatchObject({
      rssi_dbm: -47,
      link_quality: 92,
      information_elements: {
        has_rsn: true,
        has_bss_load: true
      }
    });
    expect(merged[0].raw).toMatchObject({
      'Native BSS RSSI': '-47',
      'Native BSS Link Quality': '92',
      'Native BSS IE Names': 'RSN, BSS load'
    });
  });
});

function makeNetwork(): WindowsWifiNetwork {
  return {
    schema: 'wifi.windows_baseline.v1',
    event_type: 'windows_wifi_network',
    ts_utc: '2026-06-03T12:00:00.000Z',
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
    radio_type: '802.11ax',
    band: '5 GHz',
    channel: 36,
    basic_rates_mbps: [6, 12, 24],
    other_rates_mbps: [9, 18, 36, 48, 54],
    raw: {}
  };
}

function makeBssEntry(): WindowsNativeBssEntry {
  return {
    interface_guid: 'guid',
    interface_description: 'Intel(R) Wi-Fi 6E AX211 160MHz',
    ssid: 'Test Network',
    bssid: '48:4a:e9:00:00:01',
    native_bss: {
      interface_guid: 'guid',
      interface_description: 'Intel(R) Wi-Fi 6E AX211 160MHz',
      bss_type: 'infrastructure',
      phy_type: 'he',
      rssi_dbm: -47,
      link_quality: 92,
      center_frequency_khz: 5180000,
      beacon_period_tu: 100,
      in_reg_domain: true,
      capability_information: 1041,
      timestamp: '123456',
      host_timestamp: '2026-06-03T12:00:00.0000000Z',
      rates_mbps: [6, 12, 24],
      information_elements: {
        byte_length: 64,
        element_count: 2,
        element_ids: [11, 48],
        names: ['RSN', 'BSS load'],
        extension_ids: [],
        vendor_ouis: [],
        has_rsn: true,
        has_wpa: false,
        has_bss_load: true,
        has_country: false,
        has_ht: false,
        has_vht: false,
        has_he: false,
        has_eht: false
      }
    }
  };
}
