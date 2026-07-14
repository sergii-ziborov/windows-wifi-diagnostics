import { describe, expect, it } from 'vitest';
import {
  buildClientTimeline,
  classifyWlanEvent,
  detectReconnectLoops,
  sortWlanEventsChronologically
} from '../src/analysis/timeline';
import type { EventContext, WindowsWifiEvent } from '../src/collector/types';

const context: EventContext = {
  runId: 'test-run',
  hostId: 'test-host'
};

describe('classifyWlanEvent', () => {
  it('classifies known WLAN AutoConfig event ids', () => {
    expect(classifyWlanEvent({ event_id: 8001, raw_message: '' })).toBe('connected');
    expect(classifyWlanEvent({ event_id: 11001, raw_message: '' })).toBe('association_succeeded');
    expect(classifyWlanEvent({ event_id: 11004, raw_message: '' })).toBe('security_stopped');
    expect(classifyWlanEvent({ event_id: 11005, raw_message: '' })).toBe('security_succeeded');
    expect(classifyWlanEvent({ event_id: 11010, raw_message: '' })).toBe('security_started');
  });
});

describe('timeline analysis', () => {
  it('sorts events chronologically and builds timeline entries', () => {
    const events = [
      makeEvent(11005, 2, '2026-06-02T10:01:00.000Z', 'Wireless security succeeded.'),
      makeEvent(11010, 1, '2026-06-02T10:00:00.000Z', 'Wireless security started.')
    ];

    const ordered = sortWlanEventsChronologically(events);
    const timeline = buildClientTimeline(ordered, context);

    expect(ordered.map((event) => event.record_id)).toEqual([1, 2]);
    expect(timeline.map((event) => event.action)).toEqual(['security_started', 'security_succeeded']);
    expect(timeline[0]).toMatchObject({
      schema: 'wifi.client_timeline.v1',
      source: 'detector',
      evidence_event_ids: ['wlan:1']
    });
  });

  it('detects repeated Windows Wi-Fi reconnect-like cycles', () => {
    const events = [
      makeEvent(11010, 1, '2026-06-02T10:00:00.000Z', 'Wireless security started.'),
      makeEvent(11005, 2, '2026-06-02T10:00:05.000Z', 'Wireless security succeeded.'),
      makeEvent(11004, 3, '2026-06-02T10:03:00.000Z', 'Wireless security stopped.'),
      makeEvent(11010, 4, '2026-06-02T10:03:05.000Z', 'Wireless security started.'),
      makeEvent(11005, 5, '2026-06-02T10:03:10.000Z', 'Wireless security succeeded.')
    ];
    const timeline = buildClientTimeline(events, context);
    const alerts = detectReconnectLoops(timeline, context, {
      windowMinutes: 10,
      minCycles: 2
    });

    expect(alerts).toHaveLength(1);
    expect(alerts[0]).toMatchObject({
      schema: 'wifi.alert.v1',
      alert_type: 'reconnect_loop',
      severity: 'medium',
      cycle_count: 2,
      client: '02:00:00:00:00:01',
      ssid: 'Test Network'
    });
    expect(alerts[0].evidence_event_ids).toEqual(['wlan:1', 'wlan:2', 'wlan:3', 'wlan:4', 'wlan:5']);
  });
});

function makeEvent(
  eventId: number,
  recordId: number,
  tsUtc: string,
  rawMessage: string
): WindowsWifiEvent {
  return {
    schema: 'wifi.windows_baseline.v1',
    event_type: 'windows_wifi_event',
    ts_utc: tsUtc,
    source: 'baseline',
    run_id: 'test-run',
    host_id: 'test-host',
    event_id: eventId,
    record_id: recordId,
    provider_name: 'Microsoft-Windows-WLAN-AutoConfig',
    level: 'Information',
    adapter: 'Intel(R) Wi-Fi 6E AX211 160MHz',
    interface_guid: '{4b763cb5-55ae-452c-a5e0-0f737af605b1}',
    local_mac: '02:00:00:00:00:01',
    ssid: 'Test Network',
    bss_type: 'Infrastructure',
    message_fields: {},
    raw_message: rawMessage
  };
}
