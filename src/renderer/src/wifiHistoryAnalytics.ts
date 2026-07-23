import type { WindowsWifiNetwork } from '../../collector/types';
import { analyzeRadioPresence, type RadioPresencePattern } from './radioHistoryPatterns';

export type WifiHistoryWindow = '1h' | '24h' | '7d' | 'all';

export interface WifiHistoryItem {
  key: string;
  network: WindowsWifiNetwork;
  missedScans: number;
}

export interface WifiHistorySnapshotView {
  id: string;
  tsUtc: string;
  items: WifiHistoryItem[];
  ssidCount: number;
  bssidCount: number;
  liveCount: number;
  strongestSignal: number | null;
}

export interface WifiHistoryChange {
  tsMs: number;
  appeared: number;
  disappeared: number;
  signalDelta: number | null;
}

export interface WifiPresenceAnalytics {
  key: string;
  label: string;
  detail: string;
  vendor: string | null;
  presence: RadioPresencePattern;
}

export interface WifiHistoryAnalytics {
  snapshots: Array<WifiHistorySnapshotView & { tsMs: number }>;
  snapshotCount: number;
  latestApCount: number;
  apDelta: number;
  latestLiveCount: number;
  liveRatio: number;
  strongestSignal: number | null;
  signalDelta: number | null;
  changes: WifiHistoryChange[];
  bands: Array<[string, number]>;
  security: Array<[string, number]>;
  vendors: Array<[string, number]>;
  channels: Array<[string, number]>;
  presenceRecords: WifiPresenceAnalytics[];
  newPresenceCount: number;
  stablePresenceCount: number;
  dormantPresenceCount: number;
}

const WINDOW_MS: Record<Exclude<WifiHistoryWindow, 'all'>, number> = {
  '1h': 60 * 60_000,
  '24h': 24 * 60 * 60_000,
  '7d': 7 * 24 * 60 * 60_000
};

export function analyzeWifiHistory(
  history: readonly WifiHistorySnapshotView[],
  window: WifiHistoryWindow,
  nowMs = Date.now()
): WifiHistoryAnalytics {
  const cutoff = window === 'all' ? Number.NEGATIVE_INFINITY : nowMs - WINDOW_MS[window];
  const allSnapshots = history
    .map((item) => ({ ...item, tsMs: Date.parse(item.tsUtc) }))
    .filter((item) => Number.isFinite(item.tsMs) && item.tsMs <= nowMs)
    .sort((left, right) => left.tsMs - right.tsMs);
  const snapshots = allSnapshots.filter((item) => item.tsMs >= cutoff);
  const first = snapshots[0] ?? null;
  const latest = snapshots.at(-1) ?? null;
  const latestItems = latest?.items ?? [];
  const latestLive = latestItems.filter((item) => item.missedScans === 0);
  const changes = snapshots.slice(1).map((current, index) => compareSnapshots(snapshots[index], current));
  const presenceRecords = analyzeWifiPresence(allSnapshots, nowMs);

  return {
    snapshots,
    snapshotCount: snapshots.length,
    latestApCount: latest?.bssidCount ?? 0,
    apDelta: latest && first ? latest.bssidCount - first.bssidCount : 0,
    latestLiveCount: latest?.liveCount ?? 0,
    liveRatio: latest?.bssidCount ? Math.round((latest.liveCount / latest.bssidCount) * 100) : 0,
    strongestSignal: latest?.strongestSignal ?? null,
    signalDelta: latest?.strongestSignal !== null && latest?.strongestSignal !== undefined && first?.strongestSignal !== null && first?.strongestSignal !== undefined
      ? latest.strongestSignal - first.strongestSignal
      : null,
    changes,
    bands: countValues(latestLive.map((item) => item.network.band || 'Unknown band')),
    security: countValues(latestLive.map((item) => (
      item.network.security_assessment?.posture
      ?? item.network.authentication
      ?? 'Unknown'
    ))),
    vendors: countValues(latestLive.map((item) => item.network.mac_enrichment?.vendor || 'Unresolved')),
    channels: countValues(latestLive.map((item) => (
      item.network.channel === null ? 'Unknown' : `${item.network.band || 'Band'} · ch ${item.network.channel}`
    ))),
    presenceRecords,
    newPresenceCount: presenceRecords.filter((item) => item.presence.presenceClass === 'new').length,
    stablePresenceCount: presenceRecords.filter((item) => item.presence.presenceClass === 'stable').length,
    dormantPresenceCount: presenceRecords.filter((item) => item.presence.presenceClass === 'dormant').length
  };
}

function analyzeWifiPresence(
  snapshots: Array<WifiHistorySnapshotView & { tsMs: number }>,
  nowMs: number
): WifiPresenceAnalytics[] {
  const sessionTimes = snapshots.map((snapshot) => snapshot.tsMs);
  const keys = new Set(snapshots.flatMap((snapshot) =>
    snapshot.items.filter((item) => item.missedScans === 0).map((item) => item.key)
  ));
  return [...keys].map((key): WifiPresenceAnalytics => {
    const observed = snapshots.filter((snapshot) =>
      snapshot.items.some((item) => item.key === key && item.missedScans === 0)
    );
    const latest = observed.at(-1)!.items.find((item) => item.key === key)!;
    const network = latest.network;
    const detail = [
      network.mac_enrichment?.vendor,
      network.band,
      network.channel === null ? null : `ch ${network.channel}`,
      network.authentication
    ].filter(Boolean).join(' · ');
    return {
      key,
      label: network.ssid || network.bssid || key,
      detail,
      vendor: network.mac_enrichment?.vendor ?? null,
      presence: analyzeRadioPresence(observed.map((snapshot) => snapshot.tsMs), sessionTimes, nowMs)!
    };
  }).sort((left, right) =>
    presenceRank(left.presence.presenceClass) - presenceRank(right.presence.presenceClass)
    || right.presence.lastSeenMs - left.presence.lastSeenMs
  );
}

function presenceRank(value: RadioPresencePattern['presenceClass']): number {
  return ['new', 'stable', 'weekday', 'recurring', 'intermittent', 'dormant'].indexOf(value);
}

function compareSnapshots(
  previous: WifiHistorySnapshotView & { tsMs: number },
  current: WifiHistorySnapshotView & { tsMs: number }
): WifiHistoryChange {
  const previousKeys = liveKeys(previous);
  const currentKeys = liveKeys(current);
  const appeared = [...currentKeys].filter((key) => !previousKeys.has(key)).length;
  const disappeared = [...previousKeys].filter((key) => !currentKeys.has(key)).length;
  const signalDelta = current.strongestSignal !== null && previous.strongestSignal !== null
    ? current.strongestSignal - previous.strongestSignal
    : null;
  return { tsMs: current.tsMs, appeared, disappeared, signalDelta };
}

function liveKeys(snapshot: WifiHistorySnapshotView): Set<string> {
  return new Set(snapshot.items.filter((item) => item.missedScans === 0).map((item) => item.key));
}

function countValues(values: string[]): Array<[string, number]> {
  const counts = new Map<string, number>();
  values.forEach((value) => counts.set(value, (counts.get(value) ?? 0) + 1));
  return [...counts.entries()].sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]));
}
