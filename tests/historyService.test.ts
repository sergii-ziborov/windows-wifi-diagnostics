import { describe, expect, it } from 'vitest';
import { getBaselineEvents, getBaselineTimeline } from '../src/collector/historyService';
import type { BaselinePlatformAdapter, EventContext, WindowsWifiEvent } from '../src/collector/types';

describe('history service source status', () => {
  it('uses WLAN event source status without probing snapshot sources', async () => {
    const calls = {
      allSources: 0,
      eventSources: 0,
      recentEvents: 0
    };
    const adapter: BaselinePlatformAdapter = {
      async getSourceStatus() {
        calls.allSources += 1;
        return [
          {
            name: 'netsh_wlan_interfaces',
            available: false,
            detail: 'snapshot source should not be used for history'
          }
        ];
      },
      async getWlanEventSourceStatus() {
        calls.eventSources += 1;
        return [
          {
            name: 'windows_wlan_autoconfig_operational',
            available: true,
            detail: 'record_count=10'
          }
        ];
      },
      async getWifiSnapshots() {
        return [];
      },
      async getRecentWlanEvents(context: EventContext, maxEvents: number) {
        calls.recentEvents += 1;
        return [makeEvent(context, maxEvents)];
      }
    };

    const events = await getBaselineEvents({ last: 5 }, adapter);
    const timeline = await getBaselineTimeline(
      { last: 5, windowMinutes: 10, minCycles: 2 },
      adapter
    );

    expect(calls).toEqual({
      allSources: 0,
      eventSources: 2,
      recentEvents: 2
    });
    expect(events.sources).toEqual([
      {
        name: 'windows_wlan_autoconfig_operational',
        available: true,
        detail: 'record_count=10'
      }
    ]);
    expect(timeline.sources).toEqual(events.sources);
  });
});

function makeEvent(context: EventContext, eventId: number): WindowsWifiEvent {
  return {
    schema: 'wifi.windows_baseline.v1',
    event_type: 'windows_wifi_event',
    ts_utc: '2026-06-02T10:00:00.000Z',
    source: 'baseline',
    run_id: context.runId,
    host_id: context.hostId,
    event_id: eventId,
    record_id: eventId,
    provider_name: 'Microsoft-Windows-WLAN-AutoConfig',
    level: 'Information',
    adapter: 'Intel(R) Wi-Fi 6E AX211 160MHz',
    interface_guid: '{4b763cb5-55ae-452c-a5e0-0f737af605b1}',
    local_mac: '02:00:00:00:00:01',
    ssid: 'Test Network',
    bss_type: 'Infrastructure',
    message_fields: {},
    raw_message: 'Wireless security started.'
  };
}
