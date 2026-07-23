import { useEffect } from 'react';
import { analyzeBleDevice, bleCompanyName } from './bleIntelligence';
import type { BleWorkspaceDevice } from './bleWorkspaceModel';
import { shortBleIdentity } from './bleAnalytics';

export function BluetoothDeviceModal({
  device,
  onClose
}: {
  device: BleWorkspaceDevice;
  onClose: () => void;
}) {
  const intelligence = analyzeBleDevice(device);
  useEffect(() => {
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', closeOnEscape);
    return () => window.removeEventListener('keydown', closeOnEscape);
  }, [onClose]);

  return (
    <div className="ble-modal-backdrop" role="presentation" onMouseDown={(event) => {
      if (event.currentTarget === event.target) onClose();
    }}>
      <article className="ble-device-modal" role="dialog" aria-modal="true" aria-label={`${intelligence.displayName} Bluetooth details`}>
        <header>
          <div>
            <p className="bluetooth-eyebrow">{intelligence.category}</p>
            <h2>{intelligence.displayName}</h2>
            <span>{intelligence.vendor ?? 'Manufacturer unresolved'} · {intelligence.confidence} confidence</span>
          </div>
          <button type="button" className="secondary-button" onClick={onClose}>Close</button>
        </header>
        <section className="ble-detail-grid">
          <Fact label="Current address" value={device.currentAddress ?? 'Not retained'} mono />
          <Fact label="Address behavior" value={intelligence.privacyLabel} />
          <Fact label="Identity key" value={shortBleIdentity(device.identityKey)} mono title={device.identityKey} />
          <Fact label="Identity confidence" value={device.identityConfidence.replaceAll('_', ' ')} />
          <Fact label="Signal" value={device.rssiDbm === null ? 'Not advertising in this scan' : `${device.rssiDbm} dBm`} />
          <Fact label="Tx power" value={device.txPowerDbm === null ? 'Not advertised' : `${device.txPowerDbm} dBm`} />
          <Fact label="Connectable" value={device.connectable === null ? 'Unknown' : device.connectable ? 'Yes' : 'No'} />
          <Fact label="System state" value={device.connected === true ? 'Connected' : device.paired === true ? 'Paired' : device.systemId ? 'Known to operating system' : 'Radio only'} />
          <Fact label="System appearance" value={device.systemAppearance === null ? 'Not reported' : `${device.systemAppearance} (${intelligence.category})`} />
          <Fact label="Transport" value={device.transport ?? 'Unknown'} />
          <Fact label="Evidence merge" value={device.mergeConfidence?.replaceAll('_', ' ') ?? 'Radio evidence only'} />
          <Fact label="Observed" value={`${device.observationCount} scan observation${device.observationCount === 1 ? '' : 's'}`} />
        </section>
        <DetailSection title="Assigned services">
          {intelligence.services.length ? intelligence.services.map((service) => (
            <div className="ble-detail-row" key={service.uuid}><strong>{service.name}</strong><span>{service.category}</span><code>{service.uuid}</code></div>
          )) : <p className="muted">No standard service UUID was advertised.</p>}
        </DetailSection>
        <DetailSection title="Manufacturer data">
          {device.manufacturerData.length ? device.manufacturerData.map((item, index) => (
            <div className="ble-detail-row" key={`${item.company_id}:${index}`}>
              <strong>{bleCompanyName(item.company_id) ?? `Unassigned manufacturer 0x${item.company_id.toString(16).padStart(4, '0').toUpperCase()}`}</strong>
              <span>Company ID 0x{item.company_id.toString(16).padStart(4, '0').toUpperCase()}</span>
              <code>{bytesToHex(item.data)}</code>
            </div>
          )) : <p className="muted">No manufacturer-specific data was present.</p>}
        </DetailSection>
        <DetailSection title="Interpretation evidence">
          {intelligence.evidence.length ? <ul>{intelligence.evidence.map((item) => <li key={item}>{item}</li>)}</ul> : <p className="muted">Only generic advertisement evidence is available.</p>}
          {device.zones.length ? <p className="muted">Observed sensor zones: {device.zones.join(', ')}</p> : null}
        </DetailSection>
        <p className="bluetooth-privacy-note">
          Vendor and type are evidence-based classifications, not device ownership or threat verdicts.
          RSSI is not converted into physical distance.
        </p>
      </article>
    </div>
  );
}

function Fact({ label, value, mono = false, title }: { label: string; value: string; mono?: boolean; title?: string }) {
  return <div className="ble-detail-fact"><span>{label}</span><strong className={mono ? 'mono' : ''} title={title}>{value}</strong></div>;
}

function DetailSection({ title, children }: { title: string; children: React.ReactNode }) {
  return <section className="ble-detail-section"><h3>{title}</h3>{children}</section>;
}

function bytesToHex(bytes: number[]): string {
  if (!bytes.length) return 'empty payload';
  return bytes.slice(0, 32).map((byte) => byte.toString(16).padStart(2, '0')).join(' ') + (bytes.length > 32 ? ' …' : '');
}
