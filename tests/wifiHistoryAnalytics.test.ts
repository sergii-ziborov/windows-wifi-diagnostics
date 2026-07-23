import { describe, expect, it } from 'vitest';
import type { WindowsWifiNetwork } from '../src/collector/types';
import {
  analyzeWifiHistory,
  type WifiHistoryItem,
  type WifiHistorySnapshotView
} from '../src/renderer/src/wifiHistoryAnalytics';

describe('Wi-Fi history analytics', () => {
  it('derives changes and distributions from retained snapshots only', () => {
    const nowMs = Date.UTC(2026, 6, 23, 12);
    const history = [
      snapshot('one', nowMs - 30 * 60_000, [item('a', 0, 'strong', '5 GHz', 36, 'Apple')], 70),
      snapshot('two', nowMs - 20 * 60_000, [
        item('a', 0, 'strong', '5 GHz', 36, 'Apple'),
        item('b', 0, 'open', '2.4 GHz', 6, null)
      ], 78),
      snapshot('three', nowMs - 10 * 60_000, [item('b', 0, 'open', '2.4 GHz', 6, null)], 62)
    ];

    const analytics = analyzeWifiHistory(history, '1h', nowMs);

    expect(analytics.snapshotCount).toBe(3);
    expect(analytics.latestApCount).toBe(1);
    expect(analytics.apDelta).toBe(0);
    expect(analytics.changes).toEqual([
      { tsMs: nowMs - 20 * 60_000, appeared: 1, disappeared: 0, signalDelta: 8 },
      { tsMs: nowMs - 10 * 60_000, appeared: 0, disappeared: 1, signalDelta: -16 }
    ]);
    expect(analytics.security).toEqual([['open', 1]]);
    expect(analytics.channels).toEqual([['2.4 GHz · ch 6', 1]]);
  });

  it('does not backfill snapshots outside the selected window', () => {
    const nowMs = Date.UTC(2026, 6, 23, 12);
    const history = [
      snapshot('old', nowMs - 2 * 60 * 60_000, [item('a')], 80),
      snapshot('current', nowMs - 5 * 60_000, [item('b')], 55)
    ];

    const analytics = analyzeWifiHistory(history, '1h', nowMs);

    expect(analytics.snapshotCount).toBe(1);
    expect(analytics.changes).toEqual([]);
    expect(analytics.strongestSignal).toBe(55);
  });
});

function snapshot(
  id: string,
  tsMs: number,
  items: WifiHistoryItem[],
  strongestSignal: number
): WifiHistorySnapshotView {
  const liveCount = items.filter((entry) => entry.missedScans === 0).length;
  return {
    id,
    tsUtc: new Date(tsMs).toISOString(),
    items,
    ssidCount: liveCount,
    bssidCount: liveCount,
    liveCount,
    strongestSignal
  };
}

function item(
  key: string,
  missedScans = 0,
  posture = 'strong',
  band = '5 GHz',
  channel = 36,
  vendor: string | null = 'Apple'
): WifiHistoryItem {
  return {
    key,
    missedScans,
    network: {
      schema: 'wifi.windows_baseline.v1',
      event_type: 'windows_wifi_network',
      ts_utc: '2026-07-23T12:00:00.000Z',
      source: 'baseline',
      run_id: 'test',
      host_id: 'test',
      interface_name: 'Wi-Fi',
      ssid: key,
      network_type: 'Infrastructure',
      authentication: posture,
      encryption: 'CCMP',
      bssid: key,
      signal_percent: 70,
      radio_type: '802.11ax',
      band,
      channel,
      basic_rates_mbps: [],
      other_rates_mbps: [],
      mac_enrichment: vendor ? {
        normalized_mac: null,
        oui: null,
        vendor,
        address_scope: 'unknown',
        device_hint: null,
        confidence: 'medium',
        source: 'test',
        notes: []
      } : undefined,
      security_assessment: {
        posture: posture as 'open' | 'strong',
        attack_difficulty: posture === 'open' ? 'none' : 'high',
        danger_level: posture === 'open' ? 'high' : 'low',
        label: posture,
        summary: posture,
        notes: []
      },
      raw: {}
    } as WindowsWifiNetwork
  };
}
