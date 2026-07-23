import type { DesktopBleDiscoveryMode } from '../../platform/radiochronBle';

interface BluetoothControlsProps {
  zone: string;
  durationMs: number;
  scanning: boolean;
  adapterCount: number;
  systemDeviceCount: number;
  discoveryMode: DesktopBleDiscoveryMode | null;
  elapsedMs: number | null;
  lastScanMs: number | null;
  onZoneChange: (value: string) => void;
  onDurationChange: (value: number) => void;
  onScan: () => void;
  onReset: () => void;
}

export function BluetoothControls({
  zone,
  durationMs,
  scanning,
  adapterCount,
  systemDeviceCount,
  discoveryMode,
  elapsedMs,
  lastScanMs,
  onZoneChange,
  onDurationChange,
  onScan,
  onReset
}: BluetoothControlsProps) {
  return (
    <section className="ble-command-strip" aria-label="Bluetooth scanner controls">
      <div className="ble-command-status">
        <span className={scanning ? 'ble-live-dot active' : 'ble-live-dot'} />
        <div>
          <strong>
            {scanning
              ? 'Scanning radio + system Bluetooth'
              : `${adapterCount} radio adapter${adapterCount === 1 ? '' : 's'} · ${systemDeviceCount} system device${systemDeviceCount === 1 ? '' : 's'}`}
          </strong>
          <small>
            {lastScanMs
              ? `Last evidence ${formatTime(lastScanMs)}${elapsedMs ? ` · ${elapsedMs} ms` : ''}${discoveryMode ? ` · ${discoveryLabel(discoveryMode)}` : ''}`
              : 'No radio or system inventory collected in this session'}
          </small>
        </div>
      </div>
      <div className="bluetooth-actions">
        <label>
          <span>Sensor zone</span>
          <input value={zone} maxLength={120} onChange={(event) => onZoneChange(event.target.value)} />
        </label>
        <label>
          <span>Scan window</span>
          <select value={durationMs} onChange={(event) => onDurationChange(Number(event.target.value))}>
            <option value={2_000}>2 seconds</option>
            <option value={4_000}>4 seconds</option>
            <option value={8_000}>8 seconds</option>
          </select>
        </label>
        <button type="button" className="primary-button" onClick={onScan} disabled={scanning}>
          {scanning ? 'Scanning BLE' : 'Scan Bluetooth'}
        </button>
        <button type="button" className="secondary-button" onClick={onReset} disabled={scanning}>
          Reset history
        </button>
      </div>
    </section>
  );
}

function discoveryLabel(mode: DesktopBleDiscoveryMode): string {
  if (mode === 'active') return 'active discovery';
  if (mode === 'passive') return 'passive discovery';
  return 'OS-managed discovery';
}

function formatTime(value: number): string {
  return new Date(value).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}
