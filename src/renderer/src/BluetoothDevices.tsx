import { useMemo, useState } from 'react';
import { analyzeBleDevice } from './bleIntelligence';
import type { BleWorkspaceDevice } from './bleWorkspaceModel';

export function BluetoothDevices({
  devices,
  onSelect
}: {
  devices: BleWorkspaceDevice[];
  onSelect: (device: BleWorkspaceDevice) => void;
}) {
  const [query, setQuery] = useState('');
  const [category, setCategory] = useState('all');
  const rows = useMemo(
    () => devices.map((device) => ({ device, intelligence: analyzeBleDevice(device) })),
    [devices]
  );
  const categories = [...new Set(rows.map((row) => row.intelligence.category))].sort();
  const filtered = rows.filter(({ device, intelligence }) => {
    const matchesCategory = category === 'all' || intelligence.category === category;
    const haystack = [
      intelligence.displayName,
      intelligence.vendor,
      intelligence.category,
      device.currentAddress,
      device.identityKey,
      ...intelligence.protocols,
      ...intelligence.services.map((service) => service.name)
    ].filter(Boolean).join(' ').toLowerCase();
    return matchesCategory && haystack.includes(query.trim().toLowerCase());
  });

  return (
    <section className="panel ble-devices-panel">
      <div className="ble-devices-heading">
        <div>
          <p className="bluetooth-eyebrow">System inventory + radio evidence</p>
          <h2>Bluetooth device inventory</h2>
        </div>
        <div className="ble-device-filters">
          <input
            aria-label="Search Bluetooth devices"
            value={query}
            placeholder="Search name, vendor, service…"
            onChange={(event) => setQuery(event.target.value)}
          />
          <select aria-label="Filter device category" value={category} onChange={(event) => setCategory(event.target.value)}>
            <option value="all">All categories</option>
            {categories.map((item) => <option value={item} key={item}>{item}</option>)}
          </select>
        </div>
      </div>
      <div className="ble-device-table-wrap">
        <table className="ble-device-table">
          <thead>
            <tr><th>Device</th><th>Vendor / type</th><th>Protocols and services</th><th>Identity</th><th>Status / signal</th></tr>
          </thead>
          <tbody>
            {filtered.map(({ device, intelligence }) => (
              <tr key={device.key} onClick={() => onSelect(device)}>
                <td><button type="button" onClick={() => onSelect(device)}>{intelligence.displayName}</button><small>{device.currentAddress ?? 'Address not retained'}</small></td>
                <td><strong>{intelligence.vendor ?? 'Unresolved manufacturer'}</strong><small>{intelligence.category} · {intelligence.confidence} confidence</small></td>
                <td><strong>{intelligence.protocols.join(', ') || intelligence.services[0]?.name || 'No assigned service'}</strong><small>{intelligence.services.length} service UUID{intelligence.services.length === 1 ? '' : 's'}</small></td>
                <td><strong>{intelligence.privacyLabel}</strong><small>{device.identityConfidence.replaceAll('_', ' ')}</small></td>
                <td>
                  <strong>{device.connected === true ? 'Connected' : device.rssiDbm === null ? device.paired === true ? 'Paired' : 'System device' : `${device.rssiDbm} dBm`}</strong>
                  <small>{device.rssiDbm === null ? `${device.transport ?? 'unknown'} · no current advertising RSSI` : device.retainedOnly ? 'latest retained radio evidence' : 'advertising now'}</small>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!filtered.length ? <p className="ble-table-empty">No devices match this view.</p> : null}
      </div>
    </section>
  );
}
