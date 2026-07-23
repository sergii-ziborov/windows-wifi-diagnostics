import beaconVisualUrl from './assets/device-visuals/bluetooth-beacon.svg';
import mouseVisualUrl from './assets/device-visuals/bluetooth-mouse.svg';
import phoneVisualUrl from './assets/device-visuals/bluetooth-phone.svg';
import sensorVisualUrl from './assets/device-visuals/bluetooth-sensor.svg';
import wearableVisualUrl from './assets/device-visuals/bluetooth-wearable.svg';
import speakerVisualUrl from './assets/device-visuals/speaker.svg';
import unknownVisualUrl from './assets/device-visuals/unknown-device.svg';
import { analyzeBleDevice, type BleDeviceIntelligence } from './bleIntelligence';
import type { BleWorkspaceDevice } from './bleWorkspaceModel';

export function BleMapRadioNode({
  device,
  intelligence,
  position,
  highlighted,
  onHighlight,
  onOpen
}: {
  device: BleWorkspaceDevice;
  intelligence: BleDeviceIntelligence;
  position: { x: number; y: number };
  highlighted: boolean;
  onHighlight: () => void;
  onOpen: () => void;
}) {
  const tier = signalTier(device.rssiDbm as number);
  const visual = bluetoothVisual(intelligence.category);
  return (
    <button
      type="button"
      className={`map-node radio-map-node ble-radio-node ble-radio-node-${tier} ${highlighted ? 'map-node-selected' : ''} ${device.retainedOnly ? 'map-node-stale' : ''}`}
      style={{ left: `${position.x}%`, top: `${position.y}%` }}
      title={`${intelligence.displayName} · ${device.rssiDbm} dBm · ${intelligence.category}`}
      aria-label={`${intelligence.displayName}. ${device.rssiDbm} dBm. Click to show relationships; double-click for evidence.`}
      onClick={(event) => {
        event.stopPropagation();
        onHighlight();
      }}
      onDoubleClick={(event) => {
        event.stopPropagation();
        onOpen();
      }}
    >
      <span className="map-node-orb">
        <span className="map-node-avatar"><img src={visual} alt="" /></span>
        <SignalBars tier={tier} />
      </span>
      <span className="map-node-label">
        <strong>{intelligence.displayName}</strong>
        <small>{device.rssiDbm} dBm{device.retainedOnly ? ' · history' : ''}</small>
      </span>
    </button>
  );
}

export function BleMapSystemNode({
  device,
  position,
  highlighted,
  onHighlight,
  onOpen
}: {
  device: BleWorkspaceDevice;
  position: { x: number; y: number };
  highlighted: boolean;
  onHighlight: () => void;
  onOpen: () => void;
}) {
  const intelligence = analyzeBleDevice(device);
  const visual = bluetoothVisual(intelligence.category);
  const state = device.connected ? 'Connected' : device.paired ? 'Paired' : 'Known to OS';
  return (
    <button
      type="button"
      className={`ble-system-canvas-node ${device.connected ? 'connected' : device.paired ? 'paired' : ''} ${highlighted ? 'selected' : ''}`}
      style={{ left: `${position.x}%`, top: `${position.y}%` }}
      onClick={(event) => {
        event.stopPropagation();
        onHighlight();
      }}
      onDoubleClick={(event) => {
        event.stopPropagation();
        onOpen();
      }}
      title={`${intelligence.displayName} · ${state} · no current RSSI`}
    >
      <span className="map-memory-avatar"><img src={visual} alt="" /></span>
      <span><strong>{intelligence.displayName}</strong><small>{state} · no RSSI</small></span>
    </button>
  );
}

export function BleMapSideRow({
  device,
  onSelect
}: {
  device: BleWorkspaceDevice;
  onSelect: (device: BleWorkspaceDevice) => void;
}) {
  const intelligence = analyzeBleDevice(device);
  const visual = bluetoothVisual(intelligence.category);
  return (
    <button type="button" className="ble-map-list-row" onClick={() => onSelect(device)}>
      <span className="map-memory-avatar"><img src={visual} alt="" /></span>
      <span>
        <strong>{intelligence.displayName}</strong>
        <small>{intelligence.category}{device.connected ? ' · connected' : device.paired ? ' · paired' : ''}</small>
      </span>
      <b>{device.rssiDbm === null ? 'SYSTEM' : `${device.rssiDbm}`}</b>
    </button>
  );
}

function SignalBars({ tier }: { tier: 'strong' | 'medium' | 'weak' }) {
  const enabled = tier === 'strong' ? 3 : tier === 'medium' ? 2 : 1;
  return (
    <span className={`signal-bars signal-bars-${tier}`} aria-hidden="true">
      {[1, 2, 3].map((bar) => <i className={bar <= enabled ? 'signal-bar signal-bar-on' : 'signal-bar'} key={bar} />)}
    </span>
  );
}

function bluetoothVisual(category: string): string {
  const normalized = category.toLowerCase();
  if (normalized.includes('input') || normalized.includes('mouse') || normalized.includes('keyboard')) return mouseVisualUrl;
  if (normalized.includes('audio')) return speakerVisualUrl;
  if (normalized.includes('beacon') || normalized.includes('tracker')) return beaconVisualUrl;
  if (normalized.includes('health') || normalized.includes('medical') || normalized.includes('fitness')) return wearableVisualUrl;
  if (normalized.includes('phone')) return phoneVisualUrl;
  if (normalized.includes('sensor') || normalized.includes('navigation')) return sensorVisualUrl;
  return unknownVisualUrl;
}

function signalTier(rssi: number): 'strong' | 'medium' | 'weak' {
  if (rssi >= -60) return 'strong';
  if (rssi >= -80) return 'medium';
  return 'weak';
}
