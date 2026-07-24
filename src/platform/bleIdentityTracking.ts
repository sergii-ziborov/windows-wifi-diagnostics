export type BleTrackingConfidence =
  | 'stable_identity'
  | 'same_ephemeral_address'
  | 'probabilistic_rotation'
  | 'single_observation';

export interface BleTrackablePoint {
  identity_key: string;
  identity_confidence: string;
  local_name: string | null;
  address_type: string;
  rssi_dbm: number;
  payload_hash: string;
  tx_power_dbm?: number | null;
  connectable?: boolean | null;
  service_uuids?: string[];
  company_ids?: number[];
  service_data_uuids?: string[];
  tracking_key?: string;
  tracking_confidence?: BleTrackingConfidence;
}

export interface BleTrackableSession {
  observed_at_ms: number;
  zone: string | null;
  points: BleTrackablePoint[];
}

interface TrackState {
  key: string;
  identityKey: string;
  family: string;
  lastSeenMs: number;
  lastRssiDbm: number;
  lastPayloadHash: string;
  zone: string | null;
}

const INFORMATIVE_MAX_GAP_MS = 30 * 60 * 1_000;
const ANONYMOUS_MAX_GAP_MS = 2 * 60 * 1_000;

export function applyBleIdentityTracking(sessions: BleTrackableSession[]): void {
  const tracks = new Map<string, TrackState>();
  for (const session of sessions) {
    const usedTracks = new Set<string>();
    for (const point of session.points) {
      if (point.identity_confidence !== 'ephemeral_address') {
        point.tracking_key = point.identity_key;
        point.tracking_confidence = 'stable_identity';
        rememberTrack(tracks, session, point, point.identity_key);
        usedTracks.add(point.identity_key);
        continue;
      }

      const family = trackingFamily(point);
      const informative = hasInformativeEvidence(point);
      const match = bestTrackMatch(tracks, usedTracks, session, point, family, informative);
      const trackingKey = match?.key ?? point.identity_key;
      point.tracking_key = trackingKey;
      point.tracking_confidence = match
        ? match.identityKey === point.identity_key
          ? 'same_ephemeral_address'
          : 'probabilistic_rotation'
        : 'single_observation';
      rememberTrack(tracks, session, point, trackingKey, family);
      usedTracks.add(trackingKey);
    }
  }
}

export function blePointTrackingKey(point: Pick<BleTrackablePoint, 'identity_key' | 'tracking_key'>): string {
  return point.tracking_key || point.identity_key;
}

function bestTrackMatch(
  tracks: Map<string, TrackState>,
  usedTracks: Set<string>,
  session: BleTrackableSession,
  point: BleTrackablePoint,
  family: string,
  informative: boolean
): TrackState | null {
  const maxGapMs = informative ? INFORMATIVE_MAX_GAP_MS : ANONYMOUS_MAX_GAP_MS;
  const maxRssiDelta = informative ? 18 : 4;
  let best: { track: TrackState; score: number } | null = null;
  for (const track of tracks.values()) {
    if (usedTracks.has(track.key) || track.family !== family) continue;
    if (session.zone && track.zone && session.zone !== track.zone) continue;
    const gapMs = session.observed_at_ms - track.lastSeenMs;
    const rssiDelta = Math.abs(point.rssi_dbm - track.lastRssiDbm);
    if (gapMs < 0 || gapMs > maxGapMs || rssiDelta > maxRssiDelta) continue;
    const payloadBonus = point.payload_hash && point.payload_hash === track.lastPayloadHash ? 120 : 0;
    const score = rssiDelta * 10 + gapMs / 1_000 - payloadBonus;
    if (!best || score < best.score) best = { track, score };
  }
  return best?.track ?? null;
}

function rememberTrack(
  tracks: Map<string, TrackState>,
  session: BleTrackableSession,
  point: BleTrackablePoint,
  key: string,
  family = trackingFamily(point)
): void {
  tracks.set(key, {
    key,
    identityKey: point.identity_key,
    family,
    lastSeenMs: session.observed_at_ms,
    lastRssiDbm: point.rssi_dbm,
    lastPayloadHash: point.payload_hash,
    zone: session.zone
  });
}

function trackingFamily(point: BleTrackablePoint): string {
  return [
    normalizedText(point.local_name),
    point.address_type,
    point.connectable === true ? 'connectable' : point.connectable === false ? 'not-connectable' : 'connectable-unknown',
    point.tx_power_dbm ?? 'tx-unknown',
    normalizedList(point.service_uuids),
    normalizedNumbers(point.company_ids),
    normalizedList(point.service_data_uuids)
  ].join('|');
}

function hasInformativeEvidence(point: BleTrackablePoint): boolean {
  return Boolean(
    normalizedText(point.local_name)
    || point.tx_power_dbm !== null && point.tx_power_dbm !== undefined
    || point.service_uuids?.length
    || point.company_ids?.length
    || point.service_data_uuids?.length
  );
}

function normalizedText(value: string | null): string {
  return value?.trim().toLowerCase().replace(/\s+/g, ' ') ?? '';
}

function normalizedList(values: string[] | undefined): string {
  return [...new Set(values ?? [])].map((value) => value.toLowerCase()).sort().join(',');
}

function normalizedNumbers(values: number[] | undefined): string {
  return [...new Set(values ?? [])].sort((left, right) => left - right).join(',');
}
