import type { BleWorkspaceDevice } from './bleWorkspaceModel';

export type BleMapHistoryFilter =
  | 'all'
  | 'current'
  | 'connected'
  | 'system'
  | 'radio'
  | 'new'
  | '1h'
  | '24h'
  | '7d'
  | '30d'
  | 'history';

export const BLE_MAP_HISTORY_FILTERS: Array<{ value: BleMapHistoryFilter; label: string }> = [
  { value: 'all', label: 'All evidence' },
  { value: 'current', label: 'Current scan' },
  { value: 'connected', label: 'Connected' },
  { value: 'system', label: 'System inventory' },
  { value: 'radio', label: 'Radio observed' },
  { value: 'new', label: 'New ≤24h' },
  { value: '1h', label: 'Seen ≤1h' },
  { value: '24h', label: 'Seen ≤24h' },
  { value: '7d', label: 'Seen ≤7d' },
  { value: '30d', label: 'Seen ≤30d' },
  { value: 'history', label: 'Retained only' }
];

export function filterBleMapDevices(
  devices: readonly BleWorkspaceDevice[],
  filter: BleMapHistoryFilter,
  query: string,
  nowMs = Date.now()
): BleWorkspaceDevice[] {
  const normalizedQuery = query.trim().toLowerCase();
  return devices.filter((device) => {
    if (normalizedQuery && !searchText(device).includes(normalizedQuery)) return false;
    const ageMs = device.lastSeenMs === null ? Number.POSITIVE_INFINITY : Math.max(0, nowMs - device.lastSeenMs);
    switch (filter) {
      case 'current':
        return !device.retainedOnly;
      case 'connected':
        return device.connected === true;
      case 'system':
        return Boolean(device.systemId);
      case 'radio':
        return device.radioObserved || device.rssiDbm !== null;
      case 'new':
        return device.firstSeenMs !== null && nowMs - device.firstSeenMs <= 24 * 60 * 60 * 1_000;
      case '1h':
        return ageMs <= 60 * 60 * 1_000;
      case '24h':
        return ageMs <= 24 * 60 * 60 * 1_000;
      case '7d':
        return ageMs <= 7 * 24 * 60 * 60 * 1_000;
      case '30d':
        return ageMs <= 30 * 24 * 60 * 60 * 1_000;
      case 'history':
        return device.retainedOnly;
      case 'all':
        return true;
    }
  });
}

function searchText(device: BleWorkspaceDevice): string {
  return [
    device.localName,
    device.systemCategory,
    device.transport,
    device.protocol,
    device.protocolIdentity,
    device.serviceUuids.join(' '),
    device.currentAddress
  ].filter(Boolean).join(' ').toLowerCase();
}
