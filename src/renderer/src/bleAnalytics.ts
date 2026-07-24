import type {
  DesktopBleHistoryArchive,
  DesktopBleHistoryPoint,
  DesktopBleHistorySession
} from '../../platform/bleHistory';
import { blePointTrackingKey } from '../../platform/bleIdentityTracking';
import { analyzeRadioPresence, type RadioPresencePattern } from './radioHistoryPatterns';

export type BleAnalyticsWindow = '1h' | '24h' | '7d' | 'all';

export interface BleIdentityAnalytics {
  identityKey: string;
  label: string;
  protocol: string | null;
  confidence: DesktopBleHistoryPoint['identity_confidence'];
  observationCount: number;
  sessionsSeen: number;
  eligibleSessions: number;
  scanCoveragePercent: number;
  firstSeenMs: number;
  lastSeenMs: number;
  zoneCount: number;
  rssiMinDbm: number;
  rssiMaxDbm: number;
  rssiMeanDbm: number;
  rssiStandardDeviationDb: number;
  findingCount: number;
  highFindingCount: number;
  presence: RadioPresencePattern;
}

export interface BlePresenceAnalytics {
  key: string;
  label: string;
  source: 'radio' | 'system';
  detail: string;
  connected: boolean;
  paired: boolean;
  presence: RadioPresencePattern;
}

export interface BleHistoryAnalytics {
  sessions: DesktopBleHistorySession[];
  sessionCount: number;
  observationCount: number;
  uniqueIdentityCount: number;
  findingCount: number;
  highFindingCount: number;
  uniqueSystemDeviceCount: number;
  connectedSystemDeviceCount: number;
  changes: BleHistoryChange[];
  identities: BleIdentityAnalytics[];
  presenceRecords: BlePresenceAnalytics[];
  newPresenceCount: number;
  stablePresenceCount: number;
  dormantPresenceCount: number;
  firstSessionMs: number | null;
  lastSessionMs: number | null;
}

export interface BleHistoryChange {
  tsMs: number;
  appeared: number;
  notObserved: number;
}

const WINDOW_MS: Record<Exclude<BleAnalyticsWindow, 'all'>, number> = {
  '1h': 60 * 60 * 1_000,
  '24h': 24 * 60 * 60 * 1_000,
  '7d': 7 * 24 * 60 * 60 * 1_000
};

export function analyzeBleHistory(
  archive: DesktopBleHistoryArchive | null,
  window: BleAnalyticsWindow,
  nowMs = Date.now()
): BleHistoryAnalytics {
  const allSessions = [...(archive?.sessions ?? [])]
    .filter((session) => session.observed_at_ms <= nowMs)
    .sort((left, right) => left.observed_at_ms - right.observed_at_ms);
  const cutoff = window === 'all' ? Number.NEGATIVE_INFINITY : nowMs - WINDOW_MS[window];
  const sessions = allSessions
    .filter((session) => session.observed_at_ms >= cutoff && session.observed_at_ms <= nowMs)
    .sort((left, right) => left.observed_at_ms - right.observed_at_ms);
  const identityKeys = new Set(sessions.flatMap((session) => session.points.map(blePointTrackingKey)));
  const identities = [...identityKeys]
    .map((identityKey) => analyzeIdentity(identityKey, sessions, nowMs))
    .sort((left, right) =>
      right.highFindingCount - left.highFindingCount
      || right.sessionsSeen - left.sessionsSeen
      || right.observationCount - left.observationCount
    );
  const findings = sessions.flatMap((session) => session.findings);
  const systemIds = new Set(sessions.flatMap((session) => (session.system_devices ?? []).map((device) => device.id)));
  const latestSystemDevices = sessions.at(-1)?.system_devices ?? [];
  const changes = sessions.slice(1).map((session, index) => compareSessions(sessions[index], session));
  const presenceRecords = analyzePresenceRecords(allSessions, nowMs);

  return {
    sessions,
    sessionCount: sessions.length,
    observationCount: sessions.reduce((sum, session) => sum + session.points.length, 0),
    uniqueIdentityCount: identities.length,
    findingCount: findings.length,
    highFindingCount: findings.filter((finding) => finding.severity === 'high').length,
    uniqueSystemDeviceCount: systemIds.size,
    connectedSystemDeviceCount: latestSystemDevices.filter((device) => device.connected === true).length,
    changes,
    identities,
    presenceRecords,
    newPresenceCount: presenceRecords.filter((item) => item.presence.presenceClass === 'new').length,
    stablePresenceCount: presenceRecords.filter((item) => item.presence.presenceClass === 'stable').length,
    dormantPresenceCount: presenceRecords.filter((item) => item.presence.presenceClass === 'dormant').length,
    firstSessionMs: sessions.at(0)?.observed_at_ms ?? null,
    lastSessionMs: sessions.at(-1)?.observed_at_ms ?? null
  };
}

function compareSessions(
  previous: DesktopBleHistorySession,
  current: DesktopBleHistorySession
): BleHistoryChange {
  const previousKeys = new Set(previous.points.map(blePointTrackingKey));
  const currentKeys = new Set(current.points.map(blePointTrackingKey));
  return {
    tsMs: current.observed_at_ms,
    appeared: [...currentKeys].filter((key) => !previousKeys.has(key)).length,
    notObserved: [...previousKeys].filter((key) => !currentKeys.has(key)).length
  };
}

function analyzeIdentity(
  identityKey: string,
  sessions: DesktopBleHistorySession[],
  nowMs: number
): BleIdentityAnalytics {
  const firstSessionIndex = sessions.findIndex((session) =>
    session.points.some((point) => blePointTrackingKey(point) === identityKey)
  );
  const eligibleSessions = firstSessionIndex < 0 ? [] : sessions.slice(firstSessionIndex);
  const sessionsWithIdentity = eligibleSessions.filter((session) =>
    session.points.some((point) => blePointTrackingKey(point) === identityKey)
  );
  const points = sessionsWithIdentity.flatMap((session) =>
    session.points.filter((point) => blePointTrackingKey(point) === identityKey)
  );
  const latest = points.at(-1)!;
  const rssiValues = points.map((point) => point.rssi_dbm);
  const mean = average(rssiValues);
  const observationIdentityKeys = new Set(points.map((point) => point.identity_key));
  const findings = sessions
    .flatMap((session) => session.findings)
    .filter((finding) => finding.identity_key && observationIdentityKeys.has(finding.identity_key));
  const labelPoint = [...points].reverse().find((point) => point.local_name) ?? latest;
  const presence = analyzeRadioPresence(
    sessionsWithIdentity.map((session) => session.observed_at_ms),
    eligibleSessions.map((session) => session.observed_at_ms),
    nowMs
  )!;

  return {
    identityKey,
    label: labelPoint.local_name || labelPoint.protocol || shortBleIdentity(identityKey),
    protocol: latest.protocol,
    confidence: latest.identity_confidence,
    observationCount: points.length,
    sessionsSeen: sessionsWithIdentity.length,
    eligibleSessions: eligibleSessions.length,
    scanCoveragePercent: Math.round(100 * sessionsWithIdentity.length / Math.max(1, eligibleSessions.length)),
    firstSeenMs: sessionsWithIdentity[0].observed_at_ms,
    lastSeenMs: sessionsWithIdentity.at(-1)!.observed_at_ms,
    zoneCount: new Set(sessionsWithIdentity.map((session) => session.zone).filter(Boolean)).size,
    rssiMinDbm: Math.min(...rssiValues),
    rssiMaxDbm: Math.max(...rssiValues),
    rssiMeanDbm: mean,
    rssiStandardDeviationDb: standardDeviation(rssiValues, mean),
    findingCount: findings.length,
    highFindingCount: findings.filter((finding) => finding.severity === 'high').length,
    presence
  };
}

function analyzePresenceRecords(
  sessions: DesktopBleHistorySession[],
  nowMs: number
): BlePresenceAnalytics[] {
  const sessionTimes = sessions.map((session) => session.observed_at_ms);
  const radioKeys = new Set(sessions.flatMap((session) => session.points.map(blePointTrackingKey)));
  const systemIds = new Set(sessions.flatMap((session) => session.system_devices.map((device) => device.id)));
  const radio = [...radioKeys].map((identityKey): BlePresenceAnalytics => {
    const observed = sessions.filter((session) =>
      session.points.some((point) => blePointTrackingKey(point) === identityKey)
    );
    const points = observed.flatMap((session) =>
      session.points.filter((point) => blePointTrackingKey(point) === identityKey)
    );
    const latest = points.at(-1)!;
    const labelPoint = [...points].reverse().find((point) => point.local_name) ?? latest;
    return {
      key: identityKey,
      label: labelPoint.local_name || labelPoint.protocol || shortBleIdentity(identityKey),
      source: 'radio',
      detail: `${latest.identity_confidence.replaceAll('_', ' ')} · ${latest.rssi_dbm} dBm latest`,
      connected: false,
      paired: false,
      presence: analyzeRadioPresence(observed.map((session) => session.observed_at_ms), sessionTimes, nowMs)!
    };
  });
  const system = [...systemIds].map((id): BlePresenceAnalytics => {
    const observed = sessions.filter((session) =>
      session.system_devices.some((device) => device.id === id)
    );
    const latest = observed.at(-1)!.system_devices.find((device) => device.id === id)!;
    return {
      key: `system:${id}`,
      label: latest.name || latest.category || 'Known system Bluetooth device',
      source: 'system',
      detail: [latest.category, latest.transport, latest.connected ? 'connected' : latest.paired ? 'paired' : null]
        .filter(Boolean)
        .join(' · '),
      connected: latest.connected === true,
      paired: latest.paired === true,
      presence: analyzeRadioPresence(observed.map((session) => session.observed_at_ms), sessionTimes, nowMs)!
    };
  });
  return [...system, ...radio].sort((left, right) =>
    Number(right.connected) - Number(left.connected)
    || presenceRank(left.presence.presenceClass) - presenceRank(right.presence.presenceClass)
    || right.presence.lastSeenMs - left.presence.lastSeenMs
  );
}

function presenceRank(value: RadioPresencePattern['presenceClass']): number {
  return ['new', 'stable', 'weekday', 'recurring', 'intermittent', 'dormant'].indexOf(value);
}

export function shortBleIdentity(value: string): string {
  return value.length <= 20 ? value : `${value.slice(0, 10)}…${value.slice(-7)}`;
}

function average(values: number[]): number {
  return values.reduce((sum, value) => sum + value, 0) / Math.max(1, values.length);
}

function standardDeviation(values: number[], mean: number): number {
  const variance = values.reduce((sum, value) => sum + (value - mean) ** 2, 0) / Math.max(1, values.length);
  return Math.sqrt(variance);
}
