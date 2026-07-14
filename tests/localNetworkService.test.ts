import { describe, expect, it } from 'vitest';
import { scanLocalNetwork } from '../src/collector/localNetworkService';
import type { WindowsWifiSnapshot } from '../src/collector/types';

const snapshot: WindowsWifiSnapshot = {
  schema: 'wifi.windows_baseline.v1',
  event_type: 'windows_wifi_snapshot',
  ts_utc: '2026-06-04T10:00:00.000Z',
  source: 'baseline',
  run_id: 'test',
  host_id: 'host',
  adapter: 'Intel',
  interface_name: 'Wi-Fi',
  interface_guid: 'guid',
  physical_address: '02-00-00-00-00-01',
  ipv4_addresses: ['192.168.1.20'],
  ipv6_addresses: [],
  default_gateway: '192.168.1.1',
  dns_servers: ['192.168.1.1'],
  state: 'connected',
  ssid: 'Office',
  bssid: '48:4a:e9:00:00:01',
  band: '5 GHz',
  channel: 36,
  radio_type: '802.11ac',
  authentication: 'WPA2-Personal',
  cipher: 'CCMP',
  receive_mbps: 400,
  transmit_mbps: 400,
  signal_percent: 91,
  rssi_dbm: -46,
  raw: {}
};

describe('scanLocalNetwork', () => {
  it('reads passive neighbor table and marks gateway', async () => {
    const result = await scanLocalNetwork({
      mode: 'passive',
      snapshot,
      now: new Date('2026-06-04T10:00:00.000Z'),
      commandRunner: async () => ({
        stdout: JSON.stringify([
          {
            IPAddress: '192.168.1.1',
            LinkLayerAddress: 'aa-bb-cc-dd-ee-ff',
            State: 'Reachable',
            InterfaceAlias: 'Wi-Fi'
          },
          {
            IPAddress: '192.168.1.55',
            LinkLayerAddress: '10-20-30-40-50-60',
            State: 'Stale',
            InterfaceAlias: 'Wi-Fi'
          }
        ]),
        stderr: ''
      })
    });

    expect(result).toMatchObject({
      schema: 'monitor.local_network_scan.v1',
      mode: 'passive',
      status: 'saved',
      local_ip: '192.168.1.20',
      local_mac: '02:00:00:00:00:01',
      gateway: '192.168.1.1',
      prefix: '192.168.1',
      device_count: 2,
      active_count: 1,
      stale_count: 1
    });
    expect(result.devices[0]).toMatchObject({
      ip_address: '192.168.1.1',
      mac_address: 'aa:bb:cc:dd:ee:ff',
      is_gateway: true
    });
    expect(result.exposure_checks.map((check) => check.id)).toContain('local_network.gateway_presence');
  });

  it('poll mode updates visible neighbor state', async () => {
    let callCount = 0;
    const result = await scanLocalNetwork({
      mode: 'poll',
      snapshot,
      commandRunner: async () => {
        callCount += 1;
        if (callCount === 1) {
          return {
            stdout: JSON.stringify([
              { IPAddress: '192.168.1.1', LinkLayerAddress: 'aa-bb-cc-dd-ee-ff', State: 'Stale', InterfaceAlias: 'Wi-Fi' }
            ]),
            stderr: ''
          };
        }

        return {
          stdout: JSON.stringify([{ IPAddress: '192.168.1.1', Reachable: true, LatencyMs: 3 }]),
          stderr: ''
        };
      }
    });

    expect(result.status).toBe('saved');
    expect(result.devices[0]).toMatchObject({
      state: 'active',
      source: 'reachability_probe',
      latency_ms: 3
    });
  });

  it('active mode resolves host names for already visible neighbors', async () => {
    let callCount = 0;
    const result = await scanLocalNetwork({
      mode: 'active',
      snapshot,
      commandRunner: async () => {
        callCount += 1;
        if (callCount === 1) {
          return {
            stdout: JSON.stringify([
              { IPAddress: '192.168.1.55', LinkLayerAddress: '10-20-30-40-50-60', State: 'Stale', InterfaceAlias: 'Wi-Fi' }
            ]),
            stderr: ''
          };
        }
        if (callCount === 2) {
          return {
            stdout: JSON.stringify([{ IPAddress: '192.168.1.55', Reachable: true, LatencyMs: 8 }]),
            stderr: ''
          };
        }

        return {
          stdout: JSON.stringify([{ IPAddress: '192.168.1.55', Hostname: 'printer.office.local' }]),
          stderr: ''
        };
      }
    });

    const device = result.devices.find((item) => item.ip_address === '192.168.1.55');
    expect(callCount).toBe(3);
    expect(device).toMatchObject({
      hostname: 'printer.office.local',
      latency_ms: 8,
      state: 'active',
      source: 'direct_probe'
    });
  });
});
