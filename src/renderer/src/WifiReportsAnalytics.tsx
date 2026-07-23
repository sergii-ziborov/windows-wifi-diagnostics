import { useMemo, useState } from 'react';
import { BluetoothMetric } from './BluetoothMetric';
import { RadioPresenceTable } from './RadioPresenceTable';
import { buildWifiHistoryReportHtml } from './radioReportPdf';
import {
  WifiBandHistoryChart,
  WifiChurnChart,
  WifiCountChart,
  WifiNetworkSignalChart,
  WifiSignalChart
} from './WifiHistoryCharts';
import {
  analyzeWifiHistory,
  type WifiHistorySnapshotView,
  type WifiHistoryWindow
} from './wifiHistoryAnalytics';

const WINDOWS: Array<{ value: WifiHistoryWindow; label: string }> = [
  { value: '1h', label: '1 hour' },
  { value: '24h', label: '24 hours' },
  { value: '7d', label: '7 days' },
  { value: 'all', label: 'All retained' }
];

export function WifiReportsAnalytics({
  history,
  nowMs
}: {
  history: readonly WifiHistorySnapshotView[];
  nowMs: number;
}) {
  const [window, setWindow] = useState<WifiHistoryWindow>('24h');
  const [exportStatus, setExportStatus] = useState<string | null>(null);
  const analytics = useMemo(() => analyzeWifiHistory(history, window, nowMs), [history, nowMs, window]);

  async function exportPdf(): Promise<void> {
    if (!globalThis.window.monitor?.exportReportPdf) {
      setExportStatus('PDF export is unavailable in this build.');
      return;
    }
    setExportStatus('Preparing PDF…');
    const label = WINDOWS.find((option) => option.value === window)?.label ?? window;
    const result = await globalThis.window.monitor.exportReportPdf({
      filename: 'radiochron-wifi-history.pdf',
      html: buildWifiHistoryReportHtml(analytics, label)
    });
    setExportStatus(result.saved ? `Saved: ${result.path}` : result.error ?? 'PDF export cancelled.');
  }

  return (
    <section className="wifi-report-analytics">
      <article className="panel wifi-report-heading">
        <div>
          <p className="bluetooth-eyebrow">Observed snapshots only</p>
          <h2>Wi-Fi history analytics</h2>
          <p className="muted">Counts and changes use the exact locally retained scan timestamps. Missing scans are not backfilled.</p>
        </div>
        <div className="ble-window-switch" aria-label="Wi-Fi analytics time window">
          {WINDOWS.map((option) => (
            <button type="button" className={window === option.value ? 'active' : ''} key={option.value} onClick={() => setWindow(option.value)}>
              {option.label}
            </button>
          ))}
          <button type="button" className="report-export-button" onClick={() => void exportPdf()}>
            Export PDF
          </button>
        </div>
      </article>
      {exportStatus ? <p className="report-export-status">{exportStatus}</p> : null}
      <section className="bluetooth-kpis">
        <BluetoothMetric label="Snapshots" value={analytics.snapshotCount} />
        <BluetoothMetric label="Latest APs" value={analytics.latestApCount} />
        <BluetoothMetric label="Live now" value={`${analytics.latestLiveCount} · ${analytics.liveRatio}%`} />
        <BluetoothMetric label="Strongest" value={analytics.strongestSignal === null ? '—' : `${analytics.strongestSignal}%`} />
        <BluetoothMetric label="New ≤24h" value={analytics.newPresenceCount} />
        <BluetoothMetric label="Sample-stable" value={analytics.stablePresenceCount} />
        <BluetoothMetric label="Dormant >7d" value={analytics.dormantPresenceCount} />
      </section>
      <section className="wifi-report-chart-grid">
        <article className="panel"><ReportTitle title="AP visibility timeline" detail={deltaLabel(analytics.apDelta, 'AP')} /><WifiCountChart analytics={analytics} /></article>
        <article className="panel"><ReportTitle title="Strongest signal timeline" detail={signalDeltaLabel(analytics.signalDelta)} /><WifiSignalChart analytics={analytics} /></article>
        <article className="panel"><ReportTitle title="Change pulse watch" detail={`${analytics.changes.length} real transitions`} /><WifiChurnChart analytics={analytics} /></article>
        <article className="panel"><ReportTitle title="Band evidence matrix" detail="Live observations per retained scan" /><WifiBandHistoryChart analytics={analytics} /></article>
        <article className="panel"><ReportTitle title="AP signal matrix" detail="Ten most frequently observed BSSIDs" /><WifiNetworkSignalChart analytics={analytics} /></article>
      </section>
      <section className="wifi-report-breakdown-grid">
        <Breakdown title="Security posture" entries={analytics.security} />
        <Breakdown title="Bands" entries={analytics.bands} />
        <Breakdown title="Manufacturers" entries={analytics.vendors} />
        <Breakdown title="Channels" entries={analytics.channels} />
      </section>
      <RadioPresenceTable
        title="Wi-Fi presence patterns"
        detail="1/7/30-day sampled stability, weekday recurrence, new and dormant APs"
        rows={analytics.presenceRecords}
      />
      <article className="panel">
        <ReportTitle title="Change evidence" detail={`${analytics.changes.length} observed snapshot transitions`} />
        {analytics.changes.length ? (
          <div className="wifi-change-table-wrap"><table className="wifi-change-table">
            <thead><tr><th>Observed at</th><th>Appeared</th><th>Not observed</th><th>Strongest Δ</th></tr></thead>
            <tbody>{analytics.changes.slice(-12).reverse().map((change) => (
              <tr key={change.tsMs}><td>{new Date(change.tsMs).toLocaleString()}</td><td>+{change.appeared}</td><td>-{change.disappeared}</td><td>{change.signalDelta === null ? '—' : `${change.signalDelta > 0 ? '+' : ''}${change.signalDelta} pp`}</td></tr>
            ))}</tbody>
          </table></div>
        ) : <p className="muted">At least two retained snapshots are required to calculate change evidence.</p>}
        <p className="bluetooth-privacy-note">“Not observed” means missing from that scan, not proof that an AP was switched off or left the area.</p>
      </article>
    </section>
  );
}

function Breakdown({ title, entries }: { title: string; entries: Array<[string, number]> }) {
  const maximum = Math.max(1, ...entries.map((entry) => entry[1]));
  return (
    <article className="panel">
      <h3>{title}</h3>
      {entries.length ? <div className="ble-breakdown">{entries.slice(0, 6).map(([label, count]) => (
        <div className="ble-breakdown-row" key={label}><span>{label}</span><i><b style={{ width: `${Math.round((count / maximum) * 100)}%` }} /></i><strong>{count}</strong></div>
      ))}</div> : <p className="muted">No evidence in this window.</p>}
    </article>
  );
}

function ReportTitle({ title, detail }: { title: string; detail: string }) {
  return <div className="panel-heading"><h2>{title}</h2><span className="muted">{detail}</span></div>;
}

function deltaLabel(delta: number, label: string): string {
  return `${delta > 0 ? '+' : ''}${delta} ${label}${Math.abs(delta) === 1 ? '' : 's'} across window`;
}

function signalDeltaLabel(delta: number | null): string {
  return delta === null ? 'Insufficient signal history' : `${delta > 0 ? '+' : ''}${delta} percentage points`;
}
