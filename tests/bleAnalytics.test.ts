import { describe, expect, it } from 'vitest';
import type {
  DesktopBleHistoryArchive,
  DesktopBleHistoryPoint,
  DesktopBleHistorySession
} from '../src/platform/bleHistory';
import { analyzeBleHistory } from '../src/renderer/src/bleAnalytics';

describe('BLE history analytics', () => {
  it('measures recurrence against eligible real scan sessions', () => {
    const nowMs = Date.UTC(2026, 6, 23, 12);
    const archive = history(nowMs, [
      session('one', nowMs - 30 * 60_000, [point('a', -50)]),
      session('two', nowMs - 20 * 60_000, [point('b', -70)]),
      session('three', nowMs - 10 * 60_000, [point('a', -60), point('b', -66)])
    ]);

    const analytics = analyzeBleHistory(archive, '1h', nowMs);
    const identityA = analytics.identities.find((item) => item.identityKey === 'a')!;
    const identityB = analytics.identities.find((item) => item.identityKey === 'b')!;

    expect(analytics.sessionCount).toBe(3);
    expect(analytics.observationCount).toBe(4);
    expect(identityA.sessionsSeen).toBe(2);
    expect(identityA.eligibleSessions).toBe(3);
    expect(identityA.scanCoveragePercent).toBe(67);
    expect(identityA.rssiMeanDbm).toBe(-55);
    expect(identityA.rssiStandardDeviationDb).toBe(5);
    expect(identityB.scanCoveragePercent).toBe(100);
  });

  it('uses actual timestamps for windows and does not backfill missing scans', () => {
    const nowMs = Date.UTC(2026, 6, 23, 12);
    const archive = history(nowMs, [
      session('old', nowMs - 2 * 60 * 60_000, [point('a', -50)]),
      session('current', nowMs - 5 * 60_000, [])
    ]);

    const analytics = analyzeBleHistory(archive, '1h', nowMs);

    expect(analytics.sessionCount).toBe(1);
    expect(analytics.observationCount).toBe(0);
    expect(analytics.uniqueIdentityCount).toBe(0);
  });

  it('counts evidence findings without turning them into a presence verdict', () => {
    const nowMs = Date.UTC(2026, 6, 23, 12);
    const item = session('finding', nowMs, [point('a', -80)]);
    item.findings.push({
      kind: 'possible_clone',
      severity: 'high',
      identity_key: 'a',
      summary: 'Conflicting payload evidence.'
    });

    const analytics = analyzeBleHistory(history(nowMs, [item]), 'all', nowMs);

    expect(analytics.findingCount).toBe(1);
    expect(analytics.highFindingCount).toBe(1);
    expect(analytics.identities[0].highFindingCount).toBe(1);
  });
});

function history(nowMs: number, sessions: DesktopBleHistorySession[]): DesktopBleHistoryArchive {
  return {
    schema_version: 1,
    generated_at_ms: nowMs,
    storage_warning: null,
    retention: { max_age_days: 30, max_sessions: 512 },
    sessions
  };
}

function session(scanId: string, observedAtMs: number, points: DesktopBleHistoryPoint[]): DesktopBleHistorySession {
  return {
    scan_id: scanId,
    observed_at_ms: observedAtMs,
    zone: 'Test zone',
    elapsed_ms: 500,
    adapter_count: 1,
    advertisement_count: points.length,
    error_count: 0,
    points,
    findings: []
  };
}

function point(identityKey: string, rssiDbm: number): DesktopBleHistoryPoint {
  return {
    identity_key: identityKey,
    identity_confidence: 'static_address',
    protocol: null,
    local_name: `Device ${identityKey}`,
    address_type: 'random_static',
    rssi_dbm: rssiDbm,
    payload_hash: `payload:${identityKey}`
  };
}
