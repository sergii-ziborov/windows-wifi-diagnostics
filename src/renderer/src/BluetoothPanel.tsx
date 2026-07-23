import { useCallback, useEffect, useState } from 'react';
import type { RadioChronBleFinding } from 'radiochron';
import type { DesktopBleScanResult } from '../../platform/radiochronBle';

interface BluetoothPanelProps {
  demoMode: boolean;
}

export function BluetoothPanel({ demoMode }: BluetoothPanelProps) {
  const [durationMs, setDurationMs] = useState(4_000);
  const [zone, setZone] = useState('Desktop sensor');
  const [result, setResult] = useState<DesktopBleScanResult | null>(null);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const scan = useCallback(async () => {
    if (!window.monitor?.scanBluetooth) {
      setError('This build does not expose the RadioChron BLE bridge.');
      return;
    }
    setScanning(true);
    setError(null);
    try {
      setResult(await window.monitor.scanBluetooth({ durationMs, zone: zone.trim() || null }));
    } catch (nextError: unknown) {
      setError(nextError instanceof Error ? nextError.message : String(nextError));
    } finally {
      setScanning(false);
    }
  }, [durationMs, zone]);

  useEffect(() => {
    if (demoMode && !result && !scanning) void scan();
  }, [demoMode, result, scan, scanning]);

  async function resetHistory(): Promise<void> {
    if (!window.monitor?.resetBluetoothTracker) return;
    setError(null);
    try {
      await window.monitor.resetBluetoothTracker();
      setResult(null);
    } catch (nextError: unknown) {
      setError(nextError instanceof Error ? nextError.message : String(nextError));
    }
  }

  return (
    <section className="bluetooth-layout">
      <article className="panel bluetooth-hero">
        <div>
          <p className="bluetooth-eyebrow">{demoMode ? 'Synthetic BLE lab' : 'Local Bluetooth sensor'}</p>
          <h2>Bluetooth history and change detection</h2>
          <p className="muted">
            Scan BLE advertisements through the native RadioChron bridge. History stays in this process and
            records identity evidence, presence, signal range and explicit detector limitations.
          </p>
        </div>
        <div className="bluetooth-actions">
          <label>
            <span>Sensor zone</span>
            <input value={zone} maxLength={120} onChange={(event) => setZone(event.target.value)} />
          </label>
          <label>
            <span>Scan window</span>
            <select value={durationMs} onChange={(event) => setDurationMs(Number(event.target.value))}>
              <option value={2_000}>2 seconds</option>
              <option value={4_000}>4 seconds</option>
              <option value={8_000}>8 seconds</option>
            </select>
          </label>
          <button type="button" className="primary-button" onClick={() => void scan()} disabled={scanning}>
            {scanning ? 'Scanning BLE' : 'Scan Bluetooth'}
          </button>
          <button type="button" className="secondary-button" onClick={() => void resetHistory()} disabled={scanning}>
            Reset local history
          </button>
        </div>
      </article>

      {error ? <p className="error banner">{error}</p> : null}

      <section className="bluetooth-kpis" aria-label="Bluetooth scan summary">
        <BluetoothMetric label="Adapters" value={result?.scan.adapter_count ?? 0} />
        <BluetoothMetric label="Advertisements" value={result?.scan.advertisements.length ?? 0} />
        <BluetoothMetric label="Tracked identities" value={result?.histories.length ?? 0} />
        <BluetoothMetric
          label="Findings"
          value={result?.findings.length ?? 0}
          tone={result?.findings.some((finding) => finding.severity === 'high') ? 'danger' : 'neutral'}
        />
      </section>

      <section className="bluetooth-columns">
        <article className="panel">
          <div className="panel-heading">
            <h2>Nearby advertisements</h2>
            <span className="muted">
              {result ? `${result.scan.elapsed_ms} ms scan` : 'Run a scan to collect local evidence'}
            </span>
          </div>
          {result?.scan.advertisements.length ? (
            <div className="bluetooth-device-list">
              {result.scan.advertisements.map((advertisement, index) => (
                <div className="bluetooth-device" key={`${advertisement.address}:${index}`}>
                  <div>
                    <strong>{advertisement.local_name || 'Unnamed BLE device'}</strong>
                    <span>{advertisement.address}</span>
                  </div>
                  <div className="bluetooth-device-meta">
                    <span>{advertisement.address_type.replaceAll('_', ' ')}</span>
                    <strong>{advertisement.rssi_dbm} dBm</strong>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="muted">No advertisements collected yet.</p>
          )}
          {result?.scan.errors.map((scanError) => (
            <p className="error" key={scanError}>{scanError}</p>
          ))}
        </article>

        <article className="panel">
          <div className="panel-heading">
            <h2>Detector findings</h2>
            <span className="muted">Evidence, not a threat verdict</span>
          </div>
          {result?.findings.length ? (
            <div className="bluetooth-finding-list">
              {result.findings.map((finding, index) => (
                <BluetoothFinding finding={finding} key={`${finding.kind}:${finding.identity_key}:${index}`} />
              ))}
            </div>
          ) : (
            <p className="muted">No persistence, disappearance, clone or flood evidence in the current history.</p>
          )}
        </article>
      </section>

      <article className="panel">
        <div className="panel-heading">
          <h2>Identity history</h2>
          <span className="muted">Private addresses can rotate; protocol identities are stronger.</span>
        </div>
        {result?.histories.length ? (
          <div className="bluetooth-history-grid">
            {result.histories.map((history) => (
              <div className="bluetooth-history" key={history.identity.key}>
                <strong>{history.identity.protocol || history.identity.confidence.replaceAll('_', ' ')}</strong>
                <span title={history.identity.key}>{shortIdentity(history.identity.key)}</span>
                <dl>
                  <dt>Seen</dt><dd>{history.observation_count} times</dd>
                  <dt>Sensors</dt><dd>{history.sensor_count}</dd>
                  <dt>RSSI range</dt><dd>{history.rssi_min_dbm} to {history.rssi_max_dbm} dBm</dd>
                  <dt>Mean RSSI</dt><dd>{Math.round(history.rssi_mean_dbm)} dBm</dd>
                </dl>
              </div>
            ))}
          </div>
        ) : (
          <p className="muted">History is empty.</p>
        )}
        <p className="bluetooth-privacy-note">
          RadioChron does not infer physical distance from RSSI and does not label a device malicious from presence
          alone. Raw scans remain local; reset clears the in-process tracker.
        </p>
      </article>
    </section>
  );
}

function BluetoothFinding({ finding }: { finding: RadioChronBleFinding }) {
  return (
    <div className={`bluetooth-finding bluetooth-finding-${finding.severity}`}>
      <div>
        <strong>{finding.kind.replaceAll('_', ' ')}</strong>
        <span>{finding.severity}</span>
      </div>
      <p>{finding.summary}</p>
      {finding.evidence.map((item) => <small key={item}>{item}</small>)}
      {finding.limitations.map((item) => <small className="bluetooth-limitation" key={item}>{item}</small>)}
    </div>
  );
}

function BluetoothMetric({
  label,
  value,
  tone = 'neutral'
}: {
  label: string;
  value: number;
  tone?: 'neutral' | 'danger';
}) {
  return (
    <article className={`panel bluetooth-metric bluetooth-metric-${tone}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </article>
  );
}

function shortIdentity(identity: string): string {
  return identity.length <= 34 ? identity : `${identity.slice(0, 18)}…${identity.slice(-10)}`;
}
