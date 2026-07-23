import { describe, expect, it } from 'vitest';
import type { BleHistoryAnalytics } from '../src/renderer/src/bleAnalytics';
import { analyzeRadioPresence } from '../src/renderer/src/radioHistoryPatterns';
import {
  buildBluetoothHistoryReportHtml,
  buildWifiHistoryReportHtml,
  escapeHtml
} from '../src/renderer/src/radioReportPdf';
import type { WifiHistoryAnalytics } from '../src/renderer/src/wifiHistoryAnalytics';

describe('radio history PDF reports', () => {
  it('renders a Bluetooth evidence report without undefined values', () => {
    const presence = analyzeRadioPresence([100, 200], [100, 200], 200)!;
    const analytics = {
      sessions: [],
      sessionCount: 2,
      observationCount: 3,
      uniqueIdentityCount: 1,
      findingCount: 0,
      highFindingCount: 0,
      uniqueSystemDeviceCount: 1,
      connectedSystemDeviceCount: 1,
      changes: [],
      identities: [],
      presenceRecords: [{
        key: 'mouse',
        label: 'Mouse <desk>',
        source: 'system',
        detail: 'connected',
        connected: true,
        paired: true,
        presence
      }],
      newPresenceCount: 1,
      stablePresenceCount: 0,
      dormantPresenceCount: 0,
      firstSessionMs: 100,
      lastSessionMs: 200
    } satisfies BleHistoryAnalytics;

    const html = buildBluetoothHistoryReportHtml(analytics, '24 hours');

    expect(html).toContain('Bluetooth history report');
    expect(html).toContain('Mouse &lt;desk&gt;');
    expect(html).toContain('1 / 7 / 30 days');
    expect(html).not.toContain('undefined');
  });

  it('renders Wi-Fi distributions, change evidence and sampled patterns', () => {
    const presence = analyzeRadioPresence([100], [100], 100)!;
    const analytics = {
      snapshots: [],
      snapshotCount: 1,
      latestApCount: 1,
      apDelta: 0,
      latestLiveCount: 1,
      liveRatio: 100,
      strongestSignal: 80,
      signalDelta: null,
      changes: [{ tsMs: 100, appeared: 1, disappeared: 0, signalDelta: null }],
      bands: [['5 GHz', 1]],
      security: [['strong', 1]],
      vendors: [['Example & Co', 1]],
      channels: [['5 GHz · ch 36', 1]],
      presenceRecords: [{ key: 'ap', label: 'Lab AP', detail: '5 GHz', vendor: null, presence }],
      newPresenceCount: 1,
      stablePresenceCount: 0,
      dormantPresenceCount: 0
    } satisfies WifiHistoryAnalytics;

    const html = buildWifiHistoryReportHtml(analytics, 'All retained');

    expect(html).toContain('Wi-Fi history report');
    expect(html).toContain('Example &amp; Co');
    expect(html).toContain('Observed changes');
    expect(html).not.toContain('undefined');
  });

  it('escapes all HTML-sensitive characters', () => {
    expect(escapeHtml(`<tag a="b">'&`)).toBe('&lt;tag a=&quot;b&quot;&gt;&#39;&amp;');
  });
});
