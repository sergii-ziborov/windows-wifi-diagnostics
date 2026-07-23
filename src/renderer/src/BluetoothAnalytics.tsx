import { useMemo, useState } from 'react';
import type { DesktopBleHistoryArchive } from '../../platform/bleHistory';
import { analyzeBleHistory, shortBleIdentity, type BleAnalyticsWindow } from './bleAnalytics';
import {
  BleActivityTimelineChart,
  BleChurnChart,
  BleFindingHistoryChart,
  BleRecurrenceMatrixChart,
  BleRssiHistoryChart,
  BleSystemHistoryChart
} from './BluetoothHistoryCharts';
import { BluetoothMetric } from './BluetoothMetric';
import { RadioPresenceTable } from './RadioPresenceTable';
import { buildBluetoothHistoryReportHtml } from './radioReportPdf';

const WINDOWS: Array<{ value: BleAnalyticsWindow; label: string }> = [
  { value: '1h', label: '1 hour' },
  { value: '24h', label: '24 hours' },
  { value: '7d', label: '7 days' },
  { value: 'all', label: 'All retained' }
];

export function BluetoothAnalytics({ history }: { history: DesktopBleHistoryArchive | null }) {
  const [window, setWindow] = useState<BleAnalyticsWindow>('24h');
  const [exportStatus, setExportStatus] = useState<string | null>(null);
  const analytics = useMemo(() => analyzeBleHistory(history, window), [history, window]);

  async function exportPdf(): Promise<void> {
    if (!globalThis.window.monitor?.exportReportPdf) {
      setExportStatus('PDF export is unavailable in this build.');
      return;
    }
    setExportStatus('Preparing PDF…');
    const label = WINDOWS.find((option) => option.value === window)?.label ?? window;
    const result = await globalThis.window.monitor.exportReportPdf({
      filename: 'radiochron-bluetooth-history.pdf',
      html: buildBluetoothHistoryReportHtml(analytics, label)
    });
    setExportStatus(result.saved ? `Saved: ${result.path}` : result.error ?? 'PDF export cancelled.');
  }

  return (
    <section className="ble-analytics-layout">
      <div className="ble-analytics-toolbar">
        <div>
          <p className="bluetooth-eyebrow">Observed scan sessions only</p>
          <h2>Bluetooth analytics</h2>
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
          <button type="button" className="report-export-button" onClick={() => void exportPdf()}>
            Export PDF
          </button>
        </div>
      </div>
      {exportStatus ? <p className="report-export-status">{exportStatus}</p> : null}

      {history?.storage_warning ? <p className="error banner">{history.storage_warning}</p> : null}

      <section className="bluetooth-kpis" aria-label="Bluetooth history summary">
        <BluetoothMetric label="Scan sessions" value={analytics.sessionCount} />
        <BluetoothMetric label="Observations" value={analytics.observationCount} />
        <BluetoothMetric label="RF / system devices" value={`${analytics.uniqueIdentityCount} / ${analytics.uniqueSystemDeviceCount}`} />
        <BluetoothMetric
          label="Findings"
          value={analytics.findingCount}
          tone={analytics.highFindingCount > 0 ? 'danger' : 'neutral'}
        />
        <BluetoothMetric label="New ≤24h" value={analytics.newPresenceCount} />
        <BluetoothMetric label="Sample-stable" value={analytics.stablePresenceCount} />
        <BluetoothMetric label="Dormant >7d" value={analytics.dormantPresenceCount} />
      </section>

      {analytics.sessions.length ? (
        <>
          <article className="panel">
            <ChartTitle
              title="Radio and system activity"
              detail="Select or drag across exact retained scan timestamps"
            />
            <BleActivityTimelineChart sessions={analytics.sessions} />
          </article>

          <section className="wifi-report-chart-grid">
            <article className="panel">
              <ChartTitle title="RSSI by identity" detail="Gaps remain gaps; no inferred samples" />
              <BleRssiHistoryChart analytics={analytics} />
            </article>
            <article className="panel">
              <ChartTitle title="Identity pulse watch" detail="Appeared vs not observed transitions" />
              <BleChurnChart analytics={analytics} />
            </article>
            <article className="panel">
              <ChartTitle title="System inventory" detail={`${analytics.connectedSystemDeviceCount} connected in latest scan`} />
              <BleSystemHistoryChart sessions={analytics.sessions} />
            </article>
            <article className="panel">
              <ChartTitle title="Detector pulse watch" detail="Warnings and high evidence by scan" />
              <BleFindingHistoryChart sessions={analytics.sessions} />
            </article>
          </section>

          <article className="panel">
            <ChartTitle
              title="Recurrence and RSSI matrix"
              detail={`Interactive evidence across the last ${Math.min(24, analytics.sessions.length)} scans`}
            />
            <BleRecurrenceMatrixChart sessions={analytics.sessions} analytics={analytics} />
          </article>

          <RadioPresenceTable
            title="Bluetooth presence patterns"
            detail="1/7/30-day sampled stability, weekday recurrence, new and dormant identities"
            rows={analytics.presenceRecords}
          />

          <article className="panel">
            <ChartTitle title="Identity evidence" detail="Coverage means observed scans, not continuous presence" />
            <div className="ble-analytics-table-wrap">
              <table className="ble-analytics-table">
                <thead>
                  <tr>
                    <th>Identity</th><th>Scan coverage</th><th>First / last scan</th><th>RSSI evidence</th><th>Findings</th>
                  </tr>
                </thead>
                <tbody>
                  {analytics.identities.slice(0, 24).map((identity) => (
                    <tr key={identity.identityKey}>
                      <td>
                        <strong>{identity.label}</strong>
                        <small title={identity.identityKey}>{shortBleIdentity(identity.identityKey)}</small>
                        <small>{identity.confidence.replaceAll('_', ' ')}</small>
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

function ChartTitle({ title, detail }: { title: string; detail: string }) {
  return <div className="panel-heading"><h2>{title}</h2><span className="muted">{detail}</span></div>;
}

function formatDateTime(value: number): string {
  return new Date(value).toLocaleString([], {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });
}
