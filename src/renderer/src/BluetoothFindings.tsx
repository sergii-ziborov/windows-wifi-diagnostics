import type { RadioChronBleFinding } from 'radiochron';
import type { DesktopBleHistoryArchive, DesktopBleHistoryFinding } from '../../platform/bleHistory';
import { BluetoothMetric } from './BluetoothMetric';
import { shortBleIdentity } from './bleAnalytics';

type FindingView = Pick<RadioChronBleFinding, 'kind' | 'severity' | 'identity_key' | 'summary'> & {
  evidence?: string[];
  limitations?: string[];
  observedAtMs?: number;
};

export function BluetoothFindings({
  findings,
  history
}: {
  findings: RadioChronBleFinding[];
  history: DesktopBleHistoryArchive | null;
}) {
  const retained = (history?.sessions ?? []).flatMap((session) =>
    session.findings.map((finding) => retainedFinding(finding, session.observed_at_ms))
  );
  const all = uniqueFindings([
    ...findings.map((finding) => ({ ...finding, observedAtMs: finding.observed_at_ms })),
    ...retained
  ]).sort((left, right) => (right.observedAtMs ?? 0) - (left.observedAtMs ?? 0));
  const high = all.filter((item) => item.severity === 'high').length;
  const warning = all.filter((item) => item.severity === 'warning').length;

  return (
    <section className="ble-view-layout">
      <section className="bluetooth-kpis">
        <BluetoothMetric label="Evidence findings" value={all.length} tone={high ? 'danger' : 'neutral'} />
        <BluetoothMetric label="High" value={high} tone={high ? 'danger' : 'neutral'} />
        <BluetoothMetric label="Warning" value={warning} />
        <BluetoothMetric label="Detector types" value={new Set(all.map((item) => item.kind)).size} />
      </section>
      <article className="panel">
        <div className="panel-heading">
          <div><p className="bluetooth-eyebrow">Retained detector evidence</p><h2>Bluetooth findings</h2></div>
          <span className="muted">Evidence, never an automatic threat verdict</span>
        </div>
        {all.length ? <div className="bluetooth-finding-list">{all.map((finding, index) => (
          <article className={`bluetooth-finding bluetooth-finding-${finding.severity}`} key={`${finding.kind}:${finding.identity_key}:${finding.observedAtMs}:${index}`}>
            <div><strong>{finding.kind.replaceAll('_', ' ')}</strong><span>{finding.severity}</span></div>
            <p>{finding.summary}</p>
            {finding.identity_key ? <small>Identity {shortBleIdentity(finding.identity_key)}</small> : null}
            {finding.observedAtMs ? <small>{new Date(finding.observedAtMs).toLocaleString()}</small> : null}
            {finding.evidence?.map((item) => <small key={item}>{item}</small>)}
            {finding.limitations?.map((item) => <small className="bluetooth-limitation" key={item}>Limitation: {item}</small>)}
          </article>
        ))}</div> : (
          <div className="ble-findings-empty">
            <h2>No detector evidence yet</h2>
            <p className="muted">Persistence, co-travel, disappearance, clone and beacon-flood detectors need repeated scans.</p>
          </div>
        )}
      </article>
    </section>
  );
}

function retainedFinding(finding: DesktopBleHistoryFinding, observedAtMs: number): FindingView {
  return { ...finding, observedAtMs };
}

function uniqueFindings(findings: FindingView[]): FindingView[] {
  const seen = new Set<string>();
  return findings.filter((finding) => {
    const key = `${finding.kind}:${finding.severity}:${finding.identity_key}:${finding.summary}:${finding.observedAtMs}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
