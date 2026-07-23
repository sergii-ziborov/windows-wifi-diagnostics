import { useCallback, useEffect, useMemo, useState } from 'react';
import type { DesktopBleHistoryArchive, DesktopBleViewResult } from '../../platform/bleHistory';
import { BluetoothAnalytics } from './BluetoothAnalytics';
import { BluetoothControls } from './BluetoothControls';
import { BluetoothDeviceModal } from './BluetoothDeviceModal';
import { BluetoothDevices } from './BluetoothDevices';
import { BluetoothFindings } from './BluetoothFindings';
import { BluetoothMap } from './BluetoothMap';
import { BluetoothOverview } from './BluetoothOverview';
import { buildBleWorkspaceDevices, type BleWorkspaceDevice } from './bleWorkspaceModel';
import type { BluetoothView } from './bluetoothWorkspace';

interface BluetoothPanelProps {
  demoMode: boolean;
  activeView: BluetoothView;
}

export function BluetoothPanel({ demoMode, activeView }: BluetoothPanelProps) {
  const [durationMs, setDurationMs] = useState(4_000);
  const [zone, setZone] = useState('Desktop sensor');
  const [result, setResult] = useState<DesktopBleViewResult | null>(null);
  const [history, setHistory] = useState<DesktopBleHistoryArchive | null>(null);
  const [selectedDevice, setSelectedDevice] = useState<BleWorkspaceDevice | null>(null);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const devices = useMemo(
    () => buildBleWorkspaceDevices(result, history ?? result?.analytics_history ?? null),
    [history, result]
  );

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
      setSelectedDevice(null);
    } catch (nextError: unknown) {
      setError(nextError instanceof Error ? nextError.message : String(nextError));
    }
  }

  return (
    <section className="bluetooth-layout">
      <BluetoothControls
        zone={zone}
        durationMs={durationMs}
        scanning={scanning}
        adapterCount={result?.scan.adapter_count ?? 0}
        systemDeviceCount={result?.scan.system_devices?.length ?? 0}
        elapsedMs={result?.scan.elapsed_ms ?? null}
        lastScanMs={result?.scanned_at_ms ?? history?.sessions.at(-1)?.observed_at_ms ?? null}
        onZoneChange={setZone}
        onDurationChange={setDurationMs}
        onScan={() => void scan()}
        onReset={() => void resetHistory()}
      />

      {demoMode ? <p className="ble-demo-banner">Synthetic BLE lab data · names, addresses and history are mocked.</p> : null}
      {error ? <p className="error banner">{error}</p> : null}
      {history?.storage_warning ? <p className="error banner">{history.storage_warning}</p> : null}

      {activeView === 'overview' ? (
        <BluetoothOverview
          devices={devices}
          findings={result?.findings ?? []}
          scanCount={(history ?? result?.analytics_history)?.sessions.length ?? 0}
          onSelect={setSelectedDevice}
        />
      ) : null}
      {activeView === 'map' ? (
        <BluetoothMap
          devices={devices}
          zone={zone}
          adapterCount={result?.scan.adapter_count ?? 0}
          lastScanMs={result?.scanned_at_ms ?? history?.sessions.at(-1)?.observed_at_ms ?? null}
          onSelect={setSelectedDevice}
        />
      ) : null}
      {activeView === 'devices' ? <BluetoothDevices devices={devices} onSelect={setSelectedDevice} /> : null}
      {activeView === 'history' ? <BluetoothAnalytics history={history ?? result?.analytics_history ?? null} /> : null}
      {activeView === 'findings' ? (
        <BluetoothFindings findings={result?.findings ?? []} history={history ?? result?.analytics_history ?? null} />
      ) : null}

      {selectedDevice ? <BluetoothDeviceModal device={selectedDevice} onClose={() => setSelectedDevice(null)} /> : null}
    </section>
  );
}
