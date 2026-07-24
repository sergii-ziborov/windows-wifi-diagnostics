import type { DesktopBleHistorySession } from '../../platform/bleHistory';
import { blePointTrackingKey } from '../../platform/bleIdentityTracking';
import {
  EvidenceMatrix,
  EvidencePulseStrip,
  EvidenceTimeline,
  type MatrixRow
} from './RadioAnalyticsCharts';
import type { BleHistoryAnalytics } from './bleAnalytics';

const COLORS = ['#fcee0a', '#58b9ff', '#79d75d', '#d58cff', '#ff8b5c'];

export function BleActivityTimelineChart({ sessions }: { sessions: DesktopBleHistorySession[] }) {
  return (
    <EvidenceTimeline
      points={sessions.map((session) => ({
        key: session.scan_id,
        timestampMs: session.observed_at_ms,
        values: [
          new Set(session.points.map(blePointTrackingKey)).size,
          session.advertisement_count,
          session.system_device_count
        ]
      }))}
      series={[
        { label: 'Radio identities', color: '#fcee0a' },
        { label: 'Advertisements', color: '#58b9ff' },
        { label: 'System devices', color: '#79d75d' }
      ]}
      minimum={0}
      maximum={Math.max(1, ...sessions.flatMap((session) => [
        new Set(session.points.map(blePointTrackingKey)).size,
        session.advertisement_count,
        session.system_device_count
      ]))}
      ariaLabel="Bluetooth radio and system activity per retained scan"
    />
  );
}

export function BleRssiHistoryChart({ analytics }: { analytics: BleHistoryAnalytics }) {
  const identities = analytics.identities.slice(0, 5);
  return (
    <EvidenceTimeline
      points={analytics.sessions.map((session) => ({
        key: session.scan_id,
        timestampMs: session.observed_at_ms,
        values: identities.map((identity) =>
          session.points.find((point) => blePointTrackingKey(point) === identity.identityKey)?.rssi_dbm ?? null
        )
      }))}
      series={identities.map((identity, index) => ({ label: identity.label, color: COLORS[index] }))}
      minimum={-110}
      maximum={-20}
      suffix=" dBm"
      ariaLabel="Observed RSSI history for recurring Bluetooth identities"
    />
  );
}

export function BleChurnChart({ analytics }: { analytics: BleHistoryAnalytics }) {
  return (
    <EvidencePulseStrip
      buckets={analytics.changes.map((change) => ({
        key: String(change.tsMs),
        label: new Date(change.tsMs).toISOString(),
        timestampMs: change.tsMs,
        primary: change.appeared,
        secondary: change.notObserved,
        tone: change.appeared + change.notObserved >= 8
          ? 'high'
          : change.appeared + change.notObserved >= 4 ? 'warning' : 'normal'
      }))}
      primaryLabel="Appeared"
      secondaryLabel="Not observed"
    />
  );
}

export function BleFindingHistoryChart({ sessions }: { sessions: DesktopBleHistorySession[] }) {
  return (
    <EvidencePulseStrip
      buckets={sessions.map((session) => {
        const warnings = session.findings.filter((finding) => finding.severity === 'warning').length;
        const high = session.findings.filter((finding) => finding.severity === 'high').length;
        return {
          key: session.scan_id,
          label: new Date(session.observed_at_ms).toISOString(),
          timestampMs: session.observed_at_ms,
          primary: warnings,
          secondary: high,
          tone: high ? 'high' as const : warnings ? 'warning' as const : 'normal' as const
        };
      })}
      primaryLabel="Warnings"
      secondaryLabel="High"
    />
  );
}

export function BleSystemHistoryChart({ sessions }: { sessions: DesktopBleHistorySession[] }) {
  return (
    <EvidenceTimeline
      points={sessions.map((session) => ({
        key: session.scan_id,
        timestampMs: session.observed_at_ms,
        values: [
          session.system_devices?.length ?? 0,
          session.system_devices?.filter((device) => device.connected === true).length ?? 0,
          session.system_devices?.filter((device) => device.paired === true).length ?? 0
        ]
      }))}
      series={[
        { label: 'System devices', color: '#58b9ff' },
        { label: 'Connected', color: '#79d75d' },
        { label: 'Paired', color: '#fcee0a' }
      ]}
      minimum={0}
      maximum={Math.max(1, ...sessions.map((session) => session.system_devices?.length ?? 0))}
      ariaLabel="Paired and connected system Bluetooth devices per retained scan"
    />
  );
}

export function BleRecurrenceMatrixChart({
  sessions,
  analytics
}: {
  sessions: DesktopBleHistorySession[];
  analytics: BleHistoryAnalytics;
}) {
  const visibleSessions = sessions.slice(-24);
  const rows: MatrixRow[] = analytics.identities.slice(0, 12).map((identity) => ({
    key: identity.identityKey,
    label: identity.label,
    meta: `${identity.scanCoveragePercent}% scan coverage`,
    values: visibleSessions.map((session) =>
      session.points.find((point) => blePointTrackingKey(point) === identity.identityKey)?.rssi_dbm ?? null
    )
  }));
  return (
    <EvidenceMatrix
      columns={visibleSessions.map((session) => ({
        key: session.scan_id,
        label: new Date(session.observed_at_ms).toLocaleTimeString(),
        timestampMs: session.observed_at_ms
      }))}
      rows={rows}
      suffix=" dBm"
    />
  );
}
