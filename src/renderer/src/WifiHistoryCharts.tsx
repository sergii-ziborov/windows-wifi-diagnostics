import {
  EvidenceMatrix,
  EvidencePulseStrip,
  EvidenceTimeline,
  type MatrixRow
} from './RadioAnalyticsCharts';
import type { WifiHistoryAnalytics } from './wifiHistoryAnalytics';

export function WifiCountChart({ analytics }: { analytics: WifiHistoryAnalytics }) {
  return (
    <EvidenceTimeline
      points={analytics.snapshots.map((snapshot) => ({
        key: snapshot.id,
        timestampMs: snapshot.tsMs,
        values: [snapshot.bssidCount, snapshot.liveCount]
      }))}
      series={[
        { label: 'All retained APs', color: '#fcee0a' },
        { label: 'Live APs', color: '#79d75d' }
      ]}
      minimum={0}
      maximum={Math.max(1, ...analytics.snapshots.flatMap((snapshot) => [snapshot.bssidCount, snapshot.liveCount]))}
      ariaLabel="Observed Wi-Fi access point counts over retained snapshots"
    />
  );
}

export function WifiSignalChart({ analytics }: { analytics: WifiHistoryAnalytics }) {
  return (
    <EvidenceTimeline
      points={analytics.snapshots.map((snapshot) => ({
        key: snapshot.id,
        timestampMs: snapshot.tsMs,
        values: [snapshot.strongestSignal]
      }))}
      series={[{ label: 'Strongest signal', color: '#58b9ff' }]}
      minimum={0}
      maximum={100}
      suffix="%"
      ariaLabel="Strongest observed Wi-Fi signal over retained snapshots"
    />
  );
}

export function WifiChurnChart({ analytics }: { analytics: WifiHistoryAnalytics }) {
  return (
    <EvidencePulseStrip
      buckets={analytics.changes.map((change) => ({
        key: String(change.tsMs),
        label: new Date(change.tsMs).toISOString(),
        timestampMs: change.tsMs,
        primary: change.appeared,
        secondary: change.disappeared,
        tone: change.appeared + change.disappeared >= 6 ? 'high' : change.appeared + change.disappeared >= 3 ? 'warning' : 'normal'
      }))}
      primaryLabel="Appeared"
      secondaryLabel="Not observed"
    />
  );
}

export function WifiBandHistoryChart({ analytics }: { analytics: WifiHistoryAnalytics }) {
  const bands = ['2.4 GHz', '5 GHz', '6 GHz', 'Unknown'];
  const rows: MatrixRow[] = bands.map((band) => ({
    key: band,
    label: band,
    meta: 'live AP count',
    values: analytics.snapshots.map((snapshot) => snapshot.items.filter((item) =>
      item.missedScans === 0 && normalizedBand(item.network.band) === band
    ).length)
  }));
  return <EvidenceMatrix columns={columns(analytics)} rows={rows} />;
}

export function WifiNetworkSignalChart({ analytics }: { analytics: WifiHistoryAnalytics }) {
  const counts = new Map<string, { count: number; label: string; band: string }>();
  analytics.snapshots.forEach((snapshot) => snapshot.items.forEach((item) => {
    if (item.missedScans !== 0) return;
    const current = counts.get(item.key);
    counts.set(item.key, {
      count: (current?.count ?? 0) + 1,
      label: item.network.ssid || item.network.bssid || item.key,
      band: normalizedBand(item.network.band)
    });
  }));
  const rows: MatrixRow[] = [...counts.entries()]
    .sort((left, right) => right[1].count - left[1].count)
    .slice(0, 10)
    .map(([key, metadata]) => ({
      key,
      label: metadata.label,
      meta: `${metadata.band} · ${metadata.count}/${analytics.snapshotCount} scans`,
      values: analytics.snapshots.map((snapshot) => {
        const item = snapshot.items.find((candidate) => candidate.key === key && candidate.missedScans === 0);
        return item?.network.signal_percent ?? null;
      })
    }));
  return <EvidenceMatrix columns={columns(analytics)} rows={rows} suffix="%" />;
}

function columns(analytics: WifiHistoryAnalytics) {
  return analytics.snapshots.map((snapshot) => ({
    key: snapshot.id,
    label: new Date(snapshot.tsMs).toLocaleTimeString(),
    timestampMs: snapshot.tsMs
  }));
}

function normalizedBand(value: string | null): string {
  const band = value?.toLowerCase() ?? '';
  if (band.includes('2.4')) return '2.4 GHz';
  if (band.includes('6')) return '6 GHz';
  if (band.includes('5')) return '5 GHz';
  return 'Unknown';
}
