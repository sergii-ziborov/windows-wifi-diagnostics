import { describe, expect, it } from 'vitest';
import { buildBleMapRelations } from '../src/renderer/src/bleMapRelations';
import type { BleWorkspaceDevice } from '../src/renderer/src/bleWorkspaceModel';

describe('BLE map relationships', () => {
  it('draws only OS-reported connected and paired relationships', () => {
    const devices = [
      device({ key: 'mouse', connected: true, paired: true, localName: 'MX Master 2S' }),
      device({ key: 'keyboard', paired: true, localName: 'Keyboard' }),
      device({ key: 'advertisement', radioObserved: true }),
      device({ key: 'retained', radioObserved: false, retainedOnly: true }),
      device({ key: 'inventory', radioObserved: false, systemId: 'inventory' })
    ];
    const positions = new Map(devices.map((item, index) => [
      item.key,
      { x: 10 + index, y: 20 + index }
    ]));

    const links = buildBleMapRelations(devices, positions);

    expect(links.map(({ targetKey, kind }) => ({ targetKey, kind }))).toEqual([
      { targetKey: 'mouse', kind: 'connected' },
      { targetKey: 'keyboard', kind: 'paired' }
    ]);
  });

  it('does not invent a relationship when a known device has no map position', () => {
    expect(buildBleMapRelations(
      [device({ key: 'mouse', connected: true })],
      new Map()
    )).toEqual([]);
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
