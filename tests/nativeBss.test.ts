import { describe, expect, it } from 'vitest';
import { mergeNativeBssDetails } from '../src/collector/nativeBss';
import type { EventContext, WindowsNativeBssEntry, WindowsWifiNetwork } from '../src/collector/types';
import { parseNativeWifiBssEntries } from '../src/platform/windows/nativeWifiBss';

const context: EventContext = {
  runId: 'test-run',
  hostId: 'test-host'
};

describe('parseNativeWifiBssEntries', () => {
  it('normalizes native WLAN BSS records', () => {
    const entries = parseNativeWifiBssEntries(JSON.stringify([
      {
        InterfaceGuid: 'guid',
        InterfaceDescription: 'Intel(R) Wi-Fi 6E AX211 160MHz',
        Ssid: 'Test Network',
        Bssid: '48-4A-E9-00-00-01',
        BssType: 'infrastructure',
        PhyType: 'he',
        RssiDbm: -52,
        LinkQuality: 88,
        CenterFrequencyKHz: 5180000,
        BeaconPeriodTu: 100,
        InRegDomain: true,
        CapabilityInformation: 1041,
        Timestamp: '123456',
        HostTimestamp: '2026-06-03T12:00:00.0000000Z',
        RatesMbps: [6, 12, 24],
        InformationElements: {
          ByteLength: 128,
          ElementCount: 8,
          ElementIds: [0, 1, 48, 255],
          Names: ['SSID', 'RSN', 'Extension 35'],
          ExtensionIds: [35],
          VendorOuis: ['00:50:f2'],
          HasRsn: true,
          HasWpa: false,
          HasBssLoad: false,
          HasCountry: true,
          HasHt: true,
          HasVht: true,
          HasHe: true,
          HasEht: false
        }
      }
    ]));

    expect(entries).toHaveLength(1);
    expect(entries[0]).toMatchObject({
      interface_guid: 'guid',
      ssid: 'Test Network',
      bssid: '48:4a:e9:00:00:01',
      native_bss: {
        phy_type: 'he',
        rssi_dbm: -52,
        link_quality: 88,
        center_frequency_khz: 5180000,
        information_elements: {
          has_rsn: true,
          has_he: true,
          vendor_ouis: ['00:50:f2']
        }
      }
    });
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
