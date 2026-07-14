import { describe, expect, it } from 'vitest';
import { enrichSnapshotsWithIpConfiguration } from '../src/platform/windows/ipConfig';
import type { WindowsWifiSnapshot } from '../src/collector/types';

describe('enrichSnapshotsWithIpConfiguration', () => {
  it('adds local IP details by interface alias', () => {
    const [snapshot] = enrichSnapshotsWithIpConfiguration([makeSnapshot()], JSON.stringify({
      InterfaceAlias: 'Wi-Fi',
      InterfaceDescription: 'Intel(R) Wi-Fi 6E AX211 160MHz',
      IPv4Address: { IPAddress: '192.168.1.20' },
      IPv6Address: [{ IPAddress: 'fe80::1' }, { IPAddress: '2001:db8::20' }],
      IPv4DefaultGateway: { NextHop: '192.168.1.1' },
      DNSServer: { ServerAddresses: ['192.168.1.1', '1.1.1.1'] }
    }));

    expect(snapshot).toMatchObject({
      ipv4_addresses: ['192.168.1.20'],
      ipv6_addresses: ['2001:db8::20'],
      default_gateway: '192.168.1.1',
      dns_servers: ['192.168.1.1', '1.1.1.1']
    });
  });

  it('matches flattened Windows IP config by interface GUID', () => {
    const [snapshot] = enrichSnapshotsWithIpConfiguration([makeSnapshot()], JSON.stringify({
      InterfaceAlias: 'Wireless',
      InterfaceGuid: '{4B763CB5-55AE-452C-A5E0-0F737AF605B1}',
      InterfaceDescription: 'different description',
      MacAddress: '02-00-00-00-00-01',
      IPv4Address: ['192.168.50.23'],
      IPv6Address: ['fe80::1'],
      IPv4DefaultGateway: ['192.168.50.1'],
      IPv6DefaultGateway: [null],
      DNSServer: ['192.168.50.1']
    }));

    expect(snapshot).toMatchObject({
      ipv4_addresses: ['192.168.50.23'],
      ipv6_addresses: [],
      default_gateway: '192.168.50.1',
      dns_servers: ['192.168.50.1']
    });
  });
});

function makeSnapshot(): WindowsWifiSnapshot {
  return {
    schema: 'wifi.windows_baseline.v1',
    event_type: 'windows_wifi_snapshot',
    ts_utc: '2026-06-04T08:00:00.000Z',
    source: 'baseline',
    run_id: 'test-run',
    host_id: 'test-host',
    adapter: 'Intel(R) Wi-Fi 6E AX211 160MHz',
    interface_name: 'Wi-Fi',
    interface_guid: '4b763cb5-55ae-452c-a5e0-0f737af605b1',
    physical_address: '02:00:00:00:00:01',
    state: 'connected',
    ssid: 'Test Network',
    bssid: '48:4a:e9:00:00:01',
    band: '5 GHz',
    channel: 36,
    radio_type: '802.11ax',
    authentication: 'WPA2-Personal',
    cipher: 'CCMP',
    receive_mbps: 400,
    transmit_mbps: 400,
    signal_percent: 91,
    rssi_dbm: -46,
    raw: {}
  };
}
