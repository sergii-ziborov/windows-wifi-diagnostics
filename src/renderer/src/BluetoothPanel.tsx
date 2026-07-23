import { useCallback, useEffect, useState } from 'react';
import type { RadioChronBleFinding } from 'radiochron';
import type { DesktopBleHistoryArchive, DesktopBleViewResult } from '../../platform/bleHistory';
import { BluetoothAnalytics } from './BluetoothAnalytics';
import { BluetoothMetric } from './BluetoothMetric';
import { shortBleIdentity } from './bleAnalytics';

interface BluetoothPanelProps {
  demoMode: boolean;
}

export function BluetoothPanel({ demoMode }: BluetoothPanelProps) {
  const [durationMs, setDurationMs] = useState(4_000);
  const [zone, setZone] = useState('Desktop sensor');
  const [result, setResult] = useState<DesktopBleViewResult | null>(null);
  const [history, setHistory] = useState<DesktopBleHistoryArchive | null>(null);
  const [activeView, setActiveView] = useState<'scanner' | 'analytics'>('scanner');
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
      const nextResult = await window.monitor.scanBluetooth({ durationMs, zone: zone.trim() || null });
      setResult(nextResult);
      setHistory(nextResult.analytics_history);
    } catch (nextError: unknown) {
      setError(nextError instanceof Error ? nextError.message : String(nextError));
    } finally {
      setScanning(false);
    }
  }, [durationMs, zone]);

  useEffect(() => {
    let cancelled = false;
    if (!window.monitor?.getBluetoothHistory) return;
    void window.monitor.getBluetoothHistory()
      .then((storedHistory) => {
        if (!cancelled) setHistory(storedHistory);
      })
      .catch((nextError: unknown) => {
        if (!cancelled) setError(nextError instanceof Error ? nextError.message : String(nextError));
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (demoMode && !result && !scanning) void scan();
  }, [demoMode, result, scan, scanning]);

  async function resetHistory(): Promise<void> {
    if (!window.monitor?.resetBluetoothTracker) return;
    setError(null);
    try {
      await window.monitor.resetBluetoothTracker();
      setResult(null);
      setHistory(null);
    } catch (nextError: unknown) {
      setError(nextError instanceof Error ? nextError.message : String(nextError));
    }
  }

  return (
    <section className="bluetooth-layout">
      <article className="panel bluetooth-hero">
        <div>
          <p className="bluetooth-eyebrow">{demoMode ? 'Synthetic BLE lab' : 'Local Bluetooth sensor'}</p>
          <h2>Bluetooth scanner and retained history</h2>
          <p className="muted">
            Scan BLE advertisements through the native RadioChron bridge. Privacy-minimized identities and scan
            sessions stay local so recurrence can be analyzed without inventing samples between scans.
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

      <nav className="bluetooth-view-switch" aria-label="Bluetooth views">
        <button
          type="button"
          data-bluetooth-view="scanner"
          className={activeView === 'scanner' ? 'active' : ''}
          onClick={() => setActiveView('scanner')}
        >
          Scanner
        </button>
        <button
          type="button"
          data-bluetooth-view="analytics"
          className={activeView === 'analytics' ? 'active' : ''}
          onClick={() => setActiveView('analytics')}
        >
          History analytics
        </button>
      </nav>

      {error ? <p className="error banner">{error}</p> : null}

      {activeView === 'analytics' ? (
        <BluetoothAnalytics history={history ?? result?.analytics_history ?? null} />
      ) : (
        <>
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
              <h2>Core identity history</h2>
              <span className="muted">Private addresses can rotate; protocol identities are stronger.</span>
            </div>
            {result?.histories.length ? (
              <div className="bluetooth-history-grid">
                {result.histories.map((item) => (
                  <div className="bluetooth-history" key={item.identity.key}>
                    <strong>{item.identity.protocol || item.identity.confidence.replaceAll('_', ' ')}</strong>
                    <span title={item.identity.key}>{shortBleIdentity(item.identity.key)}</span>
                    <dl>
                      <dt>Seen</dt><dd>{item.observation_count} times</dd>
                      <dt>Sensors</dt><dd>{item.sensor_count}</dd>
                      <dt>RSSI range</dt><dd>{item.rssi_min_dbm} to {item.rssi_max_dbm} dBm</dd>
                      <dt>Mean RSSI</dt><dd>{Math.round(item.rssi_mean_dbm)} dBm</dd>
                    </dl>
                  </div>
                ))}
              </div>
            ) : (
              <p className="muted">Run a scan to populate the process-local detector history.</p>
            )}
            <p className="bluetooth-privacy-note">
              RadioChron does not infer physical distance from RSSI and does not label a device malicious from
              presence alone. Reset clears both the core tracker and the retained Electron scan archive.
            </p>
          </article>
        </>
      )}
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
