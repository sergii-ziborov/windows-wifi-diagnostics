import type {
  DesktopBleHistoryArchive,
  DesktopBleHistoryPoint,
  DesktopBleHistorySession
} from '../../platform/bleHistory';

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
}

export interface BleHistoryAnalytics {
  sessions: DesktopBleHistorySession[];
  sessionCount: number;
  observationCount: number;
  uniqueIdentityCount: number;
  findingCount: number;
  highFindingCount: number;
  identities: BleIdentityAnalytics[];
  firstSessionMs: number | null;
  lastSessionMs: number | null;
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
  const cutoff = window === 'all' ? Number.NEGATIVE_INFINITY : nowMs - WINDOW_MS[window];
  const sessions = [...(archive?.sessions ?? [])]
    .filter((session) => session.observed_at_ms >= cutoff && session.observed_at_ms <= nowMs)
    .sort((left, right) => left.observed_at_ms - right.observed_at_ms);
  const identityKeys = new Set(sessions.flatMap((session) => session.points.map((point) => point.identity_key)));
  const identities = [...identityKeys]
    .map((identityKey) => analyzeIdentity(identityKey, sessions))
    .sort((left, right) =>
      right.highFindingCount - left.highFindingCount
      || right.sessionsSeen - left.sessionsSeen
      || right.observationCount - left.observationCount
    );
  const findings = sessions.flatMap((session) => session.findings);

  return {
    sessions,
    sessionCount: sessions.length,
    observationCount: sessions.reduce((sum, session) => sum + session.points.length, 0),
    uniqueIdentityCount: identities.length,
    findingCount: findings.length,
    highFindingCount: findings.filter((finding) => finding.severity === 'high').length,
    identities,
    firstSessionMs: sessions.at(0)?.observed_at_ms ?? null,
    lastSessionMs: sessions.at(-1)?.observed_at_ms ?? null
  };
}

function analyzeIdentity(identityKey: string, sessions: DesktopBleHistorySession[]): BleIdentityAnalytics {
  const firstSessionIndex = sessions.findIndex((session) =>
    session.points.some((point) => point.identity_key === identityKey)
  );
  const eligibleSessions = firstSessionIndex < 0 ? [] : sessions.slice(firstSessionIndex);
  const sessionsWithIdentity = eligibleSessions.filter((session) =>
    session.points.some((point) => point.identity_key === identityKey)
  );
  const points = sessionsWithIdentity.flatMap((session) =>
    session.points.filter((point) => point.identity_key === identityKey)
  );
  const latest = points.at(-1)!;
  const rssiValues = points.map((point) => point.rssi_dbm);
  const mean = average(rssiValues);
  const findings = sessions
    .flatMap((session) => session.findings)
    .filter((finding) => finding.identity_key === identityKey);
  const labelPoint = [...points].reverse().find((point) => point.local_name) ?? latest;

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
    highFindingCount: findings.filter((finding) => finding.severity === 'high').length
  };
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
