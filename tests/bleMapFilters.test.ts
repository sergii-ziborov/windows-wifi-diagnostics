import { describe, expect, it } from 'vitest';
import { filterBleMapDevices } from '../src/renderer/src/bleMapFilters';
import type { BleWorkspaceDevice } from '../src/renderer/src/bleWorkspaceModel';

describe('BLE map filters', () => {
  it('separates connected system devices from retained radio history', () => {
    const now = Date.UTC(2026, 6, 23, 12);
    const devices = [
      device({ key: 'mouse', systemId: 'mouse', connected: true, localName: 'MX Master', rssiDbm: null }),
      device({ key: 'old', retainedOnly: true, radioObserved: false, lastSeenMs: now - 8 * 24 * 60 * 60 * 1_000 })
    ];

    expect(filterBleMapDevices(devices, 'connected', '', now).map((item) => item.key)).toEqual(['mouse']);
    expect(filterBleMapDevices(devices, 'history', '', now).map((item) => item.key)).toEqual(['old']);
    expect(filterBleMapDevices(devices, '7d', '', now)).toEqual([]);
  });

  it('searches friendly names and categories', () => {
    const devices = [device({ localName: 'Studio Keyboard', systemCategory: 'Keyboard' })];
    expect(filterBleMapDevices(devices, 'all', 'keyboard')).toHaveLength(1);
    expect(filterBleMapDevices(devices, 'all', 'headphones')).toHaveLength(0);
  });
});

function device(overrides: Partial<BleWorkspaceDevice>): BleWorkspaceDevice {
  return {
    key: 'device',
    identityKey: 'device',
    identityConfidence: 'static_address',
    protocol: null,
    currentAddress: null,
    addressType: 'unknown',
    localName: null,
    rssiDbm: -60,
    txPowerDbm: null,
    connectable: null,
    serviceUuids: [],
    manufacturerData: [],
    serviceData: [],
    protocolIdentity: null,
    firstSeenMs: null,
    lastSeenMs: null,
    observationCount: 1,
    zones: [],
    retainedOnly: false,
    radioObserved: true,
    systemId: null,
    transport: 'ble',
    paired: null,
    connected: null,
    systemCategory: null,
    systemAppearance: null,
    inventorySource: null,
    mergeConfidence: null,
    ...overrides,
    trackingConfidence: overrides.trackingConfidence ?? 'stable_identity'
  };
}
