import type { RadioChronBleFinding } from 'radiochron';
import { analyzeBleDevice } from './bleIntelligence';
import type { BleWorkspaceDevice } from './bleWorkspaceModel';
import { BluetoothMetric } from './BluetoothMetric';

export function BluetoothOverview({
  devices,
  findings,
  scanCount,
  onSelect
}: {
  devices: BleWorkspaceDevice[];
  findings: RadioChronBleFinding[];
  scanCount: number;
  onSelect: (device: BleWorkspaceDevice) => void;
}) {
  const rows = devices.map((device) => ({ device, intelligence: analyzeBleDevice(device) }));
  const vendorCount = new Set(rows.map((row) => row.intelligence.vendor).filter(Boolean)).size;
  const connectedCount = devices.filter((device) => device.connected === true).length;
  const categories = countBy(rows.map((row) => row.intelligence.category));
  const vendors = countBy(rows.map((row) => row.intelligence.vendor ?? 'Unresolved'));

  return (
    <section className="ble-view-layout">
      <section className="bluetooth-kpis" aria-label="Bluetooth overview">
        <BluetoothMetric label="Identities" value={devices.length} />
        <BluetoothMetric label="Known vendors" value={vendorCount} />
        <BluetoothMetric label="Connected" value={connectedCount} />
        <BluetoothMetric label="Findings" value={findings.length} tone={findings.some((item) => item.severity === 'high') ? 'danger' : 'neutral'} />
      </section>

      <section className="ble-overview-grid">
        <article className="panel">
          <div className="panel-heading">
            <h2>Device composition</h2>
            <span className="muted">SIG services + advertisement evidence</span>
          </div>
          <BleBreakdown entries={categories} empty="Scan to classify nearby device roles." />
        </article>
        <article className="panel">
          <div className="panel-heading">
            <h2>Manufacturer evidence</h2>
            <span className="muted">Company ID and name hints</span>
          </div>
          <BleBreakdown entries={vendors} empty="No manufacturer data resolved yet." />
        </article>
        <article className="panel ble-overview-nearby">
          <div className="panel-heading">
            <h2>Strongest nearby identities</h2>
            <span className="muted">{scanCount} retained scan session{scanCount === 1 ? '' : 's'}</span>
          </div>
          {rows.length ? rows.slice(0, 8).map(({ device, intelligence }) => (
            <button className="ble-nearby-row" type="button" key={device.key} onClick={() => onSelect(device)}>
              <span>
                <strong>{intelligence.displayName}</strong>
                <small>{intelligence.vendor ?? intelligence.category} · {intelligence.privacyLabel}</small>
              </span>
              <b>{device.connected === true ? 'Connected' : device.rssiDbm === null ? 'System' : `${device.rssiDbm} dBm`}</b>
            </button>
          )) : <p className="muted">Run a BLE scan to populate the workspace.</p>}
        </article>
      </section>

      <article className="panel ble-detector-coverage">
        <div>
          <p className="bluetooth-eyebrow">Detector coverage</p>
          <h2>What RadioChron can explain</h2>
        </div>
        <Coverage label="Identity recurrence" detail="Protocol identity, static and private address confidence" />
        <Coverage label="Behavior changes" detail="Persistence, disappearance, clone and flood evidence" />
        <Coverage label="Device intelligence" detail="Company IDs, assigned services and advertisement signatures" />
        <Coverage label="System devices" detail="Paired and connected names, transport and OS device type" />
        <Coverage label="Signal history" detail="Observed RSSI by scan and sensor zone; never converted to fake distance" />
      </article>
    </section>
  );
}

function BleBreakdown({ entries, empty }: { entries: Array<[string, number]>; empty: string }) {
  const maximum = Math.max(1, ...entries.map((entry) => entry[1]));
  if (!entries.length) return <p className="muted">{empty}</p>;
  return (
    <div className="ble-breakdown">
      {entries.slice(0, 7).map(([label, count]) => (
        <div className="ble-breakdown-row" key={label}>
          <span>{label}</span>
          <i><b style={{ width: `${Math.round((count / maximum) * 100)}%` }} /></i>
          <strong>{count}</strong>
        </div>
      ))}
    </div>
  );
}

function Coverage({ label, detail }: { label: string; detail: string }) {
  return <div className="ble-coverage-item"><strong>{label}</strong><span>{detail}</span></div>;
}

function countBy(values: string[]): Array<[string, number]> {
  const counts = new Map<string, number>();
  values.forEach((value) => counts.set(value, (counts.get(value) ?? 0) + 1));
  return [...counts.entries()].sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]));
}
