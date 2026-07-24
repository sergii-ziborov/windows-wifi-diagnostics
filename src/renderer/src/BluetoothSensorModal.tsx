import { useEffect } from 'react';
import { analyzeBleDevice } from './bleIntelligence';
import type { BleWorkspaceDevice } from './bleWorkspaceModel';
import { useBodyScrollLock } from './bodyScrollLock';
import type { DesktopBleDiscoveryMode } from '../../platform/radiochronBle';

export function BluetoothSensorModal({
  zone,
  adapterCount,
  discoveryMode,
  lastScanMs,
  devices,
  onClose
}: {
  zone: string;
  adapterCount: number;
  discoveryMode: DesktopBleDiscoveryMode | null;
  lastScanMs: number | null;
  devices: BleWorkspaceDevice[];
  onClose: () => void;
}) {
  useBodyScrollLock(true);
  useEffect(() => {
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', closeOnEscape);
    return () => window.removeEventListener('keydown', closeOnEscape);
  }, [onClose]);
  const connected = devices.filter((device) => device.connected === true);
  const paired = devices.filter((device) => device.paired === true && device.connected !== true);
  const observed = devices.filter((device) => device.radioObserved);

  return (
    <div className="ble-modal-backdrop" role="presentation" onMouseDown={(event) => {
      if (event.currentTarget === event.target) onClose();
    }}>
      <article className="ble-device-modal ble-sensor-modal" role="dialog" aria-modal="true" aria-label="Local Bluetooth sensor details">
        <header>
          <div>
            <p className="bluetooth-eyebrow">Local radio node</p>
            <h2>You · {zone || 'Desktop sensor'}</h2>
            <span>Operating-system inventory and bounded radio discovery</span>
          </div>
          <button type="button" className="secondary-button" onClick={onClose}>Close</button>
        </header>
        <section className="ble-detail-grid">
          <Fact label="Radio adapters" value={`${adapterCount}`} />
          <Fact label="Discovery" value={discoveryLabel(discoveryMode)} />
          <Fact label="Connected links" value={`${connected.length}`} />
          <Fact label="Paired links" value={`${paired.length}`} />
          <Fact label="Radio observations" value={`${observed.length}`} />
          <Fact label="Last scan" value={lastScanMs === null ? 'No scan yet' : new Date(lastScanMs).toLocaleString()} />
          <Fact label="Storage" value="Local 30-day / 512-scan cap" />
        </section>
        <RelationGroup title="Connected now" devices={connected} empty="No connected Bluetooth device reported by the OS." />
        <RelationGroup title="Paired / known" devices={paired} empty="No paired-only device in the current OS inventory." />
        <RelationGroup title="Radio observed" devices={observed} empty="No current BLE advertisements." />
        <p className="bluetooth-privacy-note">
          Solid lines are OS-reported local connections. Dashed lines are paired inventory. Radio-observed devices
          are listed without a line because an advertisement does not prove a connection or ownership.
          The operating system does not expose third-party device-to-device links.
        </p>
      </article>
    </div>
  );
}

function discoveryLabel(mode: DesktopBleDiscoveryMode | null): string {
  if (mode === 'active') return 'Active · scan window only';
  if (mode === 'passive') return 'Passive';
  if (mode === 'platform_managed') return 'OS managed';
  return 'Not reported';
}

function RelationGroup({
  title,
  devices,
  empty
}: {
  title: string;
  devices: BleWorkspaceDevice[];
  empty: string;
}) {
  return (
    <section className="ble-detail-section">
      <h3>{title}</h3>
      {devices.length ? devices.slice(0, 24).map((device) => {
        const intelligence = analyzeBleDevice(device);
        return (
          <div className="ble-detail-row" key={device.key}>
            <strong>{intelligence.displayName}</strong>
            <span>{intelligence.category}</span>
            <code>{device.rssiDbm === null ? 'NO RSSI' : `${device.rssiDbm} dBm`}</code>
          </div>
        );
      }) : <p className="muted">{empty}</p>}
    </section>
  );
}

function Fact({ label, value }: { label: string; value: string }) {
  return <div className="ble-detail-fact"><span>{label}</span><strong>{value}</strong></div>;
}
