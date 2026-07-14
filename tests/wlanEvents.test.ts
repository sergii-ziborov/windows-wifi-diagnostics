import { describe, expect, it } from 'vitest';
import { parseMessageFields, parseWlanAutoConfigEvents } from '../src/platform/windows/wlanEvents';

const context = {
  runId: 'test-run',
  hostId: 'test-host'
};

describe('parseMessageFields', () => {
  it('extracts key value pairs from WLAN messages', () => {
    const message = `
Wireless security started.

Network Adapter: Intel(R) Wi-Fi 6E AX211 160MHz
Interface GUID: {4b763cb5-55ae-452c-a5e0-0f737af605b1}
Local MAC Address: 02:00:00:00:00:01
Network SSID: Test Network
BSS Type: Infrastructure
Authentication: WPA2-Personal
`;

    expect(parseMessageFields(message)).toMatchObject({
      'Network Adapter': 'Intel(R) Wi-Fi 6E AX211 160MHz',
      'Local MAC Address': '02:00:00:00:00:01',
      'Network SSID': 'Test Network',
      Authentication: 'WPA2-Personal'
    });
  });
});

describe('parseWlanAutoConfigEvents', () => {
  it('normalizes PowerShell JSON events', () => {
    const json = JSON.stringify([
      {
        TimeCreated: '2026-06-02T09:15:52+03:00',
        Id: 11010,
        RecordId: 123,
        ProviderName: 'Microsoft-Windows-WLAN-AutoConfig',
        LevelDisplayName: 'Information',
        Message: [
          'Wireless security started.',
          '',
          'Network Adapter: Intel(R) Wi-Fi 6E AX211 160MHz',
          'Interface GUID: {4b763cb5-55ae-452c-a5e0-0f737af605b1}',
          'Local MAC Address: 02:00:00:00:00:01',
          'Network SSID: Test Network',
          'BSS Type: Infrastructure'
        ].join('\n')
      }
    ]);

    const [event] = parseWlanAutoConfigEvents(json, context);

    expect(event).toMatchObject({
      schema: 'wifi.windows_baseline.v1',
      event_type: 'windows_wifi_event',
      ts_utc: '2026-06-02T06:15:52.000Z',
      event_id: 11010,
      record_id: 123,
      adapter: 'Intel(R) Wi-Fi 6E AX211 160MHz',
      local_mac: '02:00:00:00:00:01',
      ssid: 'Test Network',
      bss_type: 'Infrastructure'
    });
  });
});
