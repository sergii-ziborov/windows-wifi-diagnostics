import { analyzeBleDevice } from './bleIntelligence';
import type { RadioMapConnectionLink } from './RadioMapConnections';
import type { BleWorkspaceDevice } from './bleWorkspaceModel';

export function buildBleMapRelations(
  devices: readonly BleWorkspaceDevice[],
  positions: ReadonlyMap<string, { x: number; y: number }>
): RadioMapConnectionLink[] {
  return devices.flatMap((device) => {
    if (device.connected !== true && device.paired !== true) return [];
    const end = positions.get(device.key);
    if (!end) return [];

    const connected = device.connected === true;
    return [{
      id: `ble-link:${device.key}`,
      sourceKey: null,
      targetKey: device.key,
      kind: connected ? 'connected' : 'paired',
      start: { x: 50, y: 50 },
      end,
      sourceRadiusPx: 26,
      targetRadiusPx: device.rssiDbm === null ? 34 : 27,
      signal: signalStrength(device.rssiDbm),
      label: connected ? 'Connected now' : 'Paired / known',
      detail: `${analyzeBleDevice(device).displayName} · ${
        device.rssiDbm === null ? 'no RSSI' : `${device.rssiDbm} dBm`
      }`
    }];
  });
}

function signalStrength(rssiDbm: number | null): number | null {
  return rssiDbm === null ? null : Math.max(0, Math.min(100, (rssiDbm + 100) * 2));
}
