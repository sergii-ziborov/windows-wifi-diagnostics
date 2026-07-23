export type BluetoothView = 'overview' | 'map' | 'devices' | 'history' | 'findings';

export const BLUETOOTH_TABS: ReadonlyArray<{ key: BluetoothView; label: string }> = [
  { key: 'overview', label: 'Overview' },
  { key: 'map', label: 'Map' },
  { key: 'devices', label: 'Devices' },
  { key: 'history', label: 'Analytics' },
  { key: 'findings', label: 'Findings' }
];
