import { useMemo, useState } from 'react';
import type { DesktopBleHistoryArchive, DesktopBleHistorySession } from '../../platform/bleHistory';
import { analyzeBleHistory, shortBleIdentity, type BleAnalyticsWindow } from './bleAnalytics';
import { BluetoothMetric } from './BluetoothMetric';

const WINDOWS: Array<{ value: BleAnalyticsWindow; label: string }> = [
  { value: '1h', label: '1 hour' },
  { value: '24h', label: '24 hours' },
  { value: '7d', label: '7 days' },
  { value: 'all', label: 'All retained' }
];

export function BluetoothAnalytics({ history }: { history: DesktopBleHistoryArchive | null }) {
  const [window, setWindow] = useState<BleAnalyticsWindow>('24h');
  const analytics = useMemo(
    () => analyzeBleHistory(history, window),
    [history, window]
  );

  return (
    <section className="ble-analytics-layout">
      <div className="ble-analytics-toolbar">
        <div>
          <p className="bluetooth-eyebrow">Observed scan sessions only</p>
          <h2>Bluetooth history analytics</h2>
        </div>
        <div className="ble-window-switch" aria-label="Bluetooth analytics time window">
          {WINDOWS.map((option) => (
            <button
              type="button"
              key={option.value}
              className={window === option.value ? 'active' : ''}
              onClick={() => setWindow(option.value)}
            >
              {option.label}
            </button>
          ))}
        </div>
      </div>

      {history?.storage_warning ? <p className="error banner">{history.storage_warning}</p> : null}

      <section className="bluetooth-kpis" aria-label="Bluetooth history summary">
        <BluetoothMetric label="Scan sessions" value={analytics.sessionCount} />
        <BluetoothMetric label="Observations" value={analytics.observationCount} />
        <BluetoothMetric label="Unique identities" value={analytics.uniqueIdentityCount} />
        <BluetoothMetric
          label="Findings"
          value={analytics.findingCount}
          tone={analytics.highFindingCount > 0 ? 'danger' : 'neutral'}
        />
      </section>

      {analytics.sessions.length ? (
        <>
          <article className="panel ble-session-chart-panel">
            <div className="panel-heading">
              <h2>Identities per scan</h2>
              <span className="muted">Real timestamps; no smoothing or inferred samples</span>
            </div>
            <BleSessionChart sessions={analytics.sessions} />
          </article>

          <article className="panel">
            <div className="panel-heading">
              <h2>Recurrence matrix</h2>
              <span className="muted">Last {Math.min(16, analytics.sessions.length)} scans</span>
            </div>
            <BleRecurrenceMatrix sessions={analytics.sessions} identityKeys={analytics.identities.map((item) => item.identityKey)} />
          </article>

          <article className="panel">
            <div className="panel-heading">
              <h2>Identity evidence</h2>
              <span className="muted">Coverage means observed scans, not continuous physical presence</span>
            </div>
            <div className="ble-analytics-table-wrap">
              <table className="ble-analytics-table">
                <thead>
                  <tr>
                    <th>Identity</th>
                    <th>Scan coverage</th>
                    <th>First / last scan</th>
                    <th>RSSI evidence</th>
                    <th>Findings</th>
                  </tr>
                </thead>
                <tbody>
                  {analytics.identities.slice(0, 24).map((identity) => (
                    <tr key={identity.identityKey}>
                      <td>
                        <strong>{identity.label}</strong>
                        <small title={identity.identityKey}>{shortBleIdentity(identity.identityKey)}</small>
                        <small>{formatIdentityConfidence(identity.confidence)}</small>
                      </td>
                      <td>
                        <strong>{identity.scanCoveragePercent}%</strong>
                        <small>{identity.sessionsSeen} of {identity.eligibleSessions} scans since first seen</small>
                      </td>
                      <td>
                        <strong>{formatDateTime(identity.firstSeenMs)}</strong>
                        <small>{formatDateTime(identity.lastSeenMs)}</small>
                      </td>
                      <td>
                        <strong>{Math.round(identity.rssiMeanDbm)} dBm mean</strong>
                        <small>
                          {identity.rssiMinDbm}…{identity.rssiMaxDbm} dBm · σ {identity.rssiStandardDeviationDb.toFixed(1)} dB
                        </small>
                      </td>
                      <td className={identity.highFindingCount ? 'ble-finding-cell danger' : 'ble-finding-cell'}>
                        <strong>{identity.findingCount}</strong>
                        <small>{identity.highFindingCount ? `${identity.highFindingCount} high` : 'No high findings'}</small>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </article>
        </>
      ) : (
        <article className="panel ble-analytics-empty">
          <h2>No scan sessions in this window</h2>
          <p className="muted">Run Bluetooth scans or choose a wider retained-history window.</p>
        </article>
      )}

      <p className="bluetooth-privacy-note">
        Blank cells mean “not observed during that scan”, not “device absent”. RadioChron does not fill gaps,
        infer distance from RSSI, or convert recurrence into a malicious-device verdict. Retention is local,
        capped at 30 days / 512 scans, and cleared by Reset local history.
      </p>
    </section>
  );
}

function BleSessionChart({ sessions }: { sessions: DesktopBleHistorySession[] }) {
  const width = 960;
  const height = 220;
  const left = 48;
  const right = 16;
  const top = 20;
  const bottom = 36;
  const plotWidth = width - left - right;
  const plotHeight = height - top - bottom;
  const firstMs = sessions[0].observed_at_ms;
  const lastMs = sessions.at(-1)!.observed_at_ms;
  const spanMs = Math.max(1, lastMs - firstMs);
  const counts = sessions.map((session) => new Set(session.points.map((point) => point.identity_key)).size);
  const maximum = Math.max(1, ...counts);
  const barWidth = Math.max(4, Math.min(24, plotWidth / Math.max(1, sessions.length) * 0.55));

  return (
    <div className="ble-session-chart-wrap">
      <svg className="ble-session-chart" viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Unique Bluetooth identities observed per scan session">
        {[0, 0.5, 1].map((ratio) => {
          const y = top + plotHeight * ratio;
          const value = Math.round(maximum * (1 - ratio));
          return (
            <g key={ratio}>
              <line x1={left} x2={width - right} y1={y} y2={y} className="ble-chart-grid" />
              <text x={left - 10} y={y + 4} className="ble-chart-axis" textAnchor="end">{value}</text>
            </g>
          );
        })}
        {sessions.map((session, index) => {
          const x = left + ((session.observed_at_ms - firstMs) / spanMs) * plotWidth;
          const count = counts[index];
          const barHeight = count / maximum * plotHeight;
          const severity = highestSeverity(session);
          return (
            <rect
              key={session.scan_id}
              x={Math.min(width - right - barWidth, Math.max(left, x - barWidth / 2))}
              y={top + plotHeight - barHeight}
              width={barWidth}
              height={Math.max(2, barHeight)}
              rx="3"
              className={`ble-chart-bar ble-chart-bar-${severity}`}
            >
              <title>
                {formatDateTime(session.observed_at_ms)} · {count} identities · {session.points.length} observations
              </title>
            </rect>
          );
        })}
        <text x={left} y={height - 10} className="ble-chart-axis">{formatDateTime(firstMs)}</text>
        <text x={width - right} y={height - 10} className="ble-chart-axis" textAnchor="end">{formatDateTime(lastMs)}</text>
      </svg>
    </div>
  );
}

function BleRecurrenceMatrix({
  sessions,
  identityKeys
}: {
  sessions: DesktopBleHistorySession[];
  identityKeys: string[];
}) {
  const visibleSessions = sessions.slice(-16);
  const visibleKeys = identityKeys.slice(0, 10);
  return (
    <div className="ble-matrix-wrap">
      <table className="ble-matrix">
        <thead>
          <tr>
            <th>Identity</th>
            {visibleSessions.map((session) => (
              <th key={session.scan_id} title={formatDateTime(session.observed_at_ms)}>
                {formatTime(session.observed_at_ms)}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {visibleKeys.map((identityKey) => {
            const labelPoint = [...visibleSessions]
              .reverse()
              .flatMap((session) => session.points)
              .find((point) => point.identity_key === identityKey);
            return (
              <tr key={identityKey}>
                <th title={identityKey}>{labelPoint?.local_name || labelPoint?.protocol || shortBleIdentity(identityKey)}</th>
                {visibleSessions.map((session) => {
                  const point = session.points.find((item) => item.identity_key === identityKey);
                  return (
                    <td key={session.scan_id}>
                      <span
                        className={point ? `ble-matrix-cell ${rssiTone(point.rssi_dbm)}` : 'ble-matrix-cell empty'}
                        title={point
                          ? `${formatDateTime(session.observed_at_ms)} · ${point.rssi_dbm} dBm`
                          : `${formatDateTime(session.observed_at_ms)} · not observed in this scan`}
                      >
                        {point ? point.rssi_dbm : '–'}
                      </span>
                    </td>
                  );
                })}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function highestSeverity(session: DesktopBleHistorySession): 'neutral' | 'warning' | 'high' {
  if (session.findings.some((finding) => finding.severity === 'high')) return 'high';
  if (session.findings.some((finding) => finding.severity === 'warning')) return 'warning';
  return 'neutral';
}

function rssiTone(rssiDbm: number): 'strong' | 'medium' | 'weak' {
  if (rssiDbm >= -60) return 'strong';
  if (rssiDbm >= -75) return 'medium';
  return 'weak';
}

function formatIdentityConfidence(value: string): string {
  return value.replaceAll('_', ' ');
}

function formatDateTime(value: number): string {
  return new Date(value).toLocaleString([], {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });
}

function formatTime(value: number): string {
  return new Date(value).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}
