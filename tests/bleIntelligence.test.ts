import { describe, expect, it } from 'vitest';
import {
  analyzeBleDevice,
  bleAppearanceName,
  bleAssignedNumbersMetadata,
  bleCompanyName
} from '../src/renderer/src/bleIntelligence';
import type { BleWorkspaceDevice } from '../src/renderer/src/bleWorkspaceModel';

describe('BLE device intelligence', () => {
  it('resolves an assigned company and iBeacon signature from advertisement evidence', () => {
    const intelligence = analyzeBleDevice(device({
      localName: 'Lobby beacon',
      manufacturerData: [{ company_id: 0x004c, data: [0x02, 0x15, 0x01] }]
    }));

    expect(intelligence.vendor).toBe('Apple, Inc.');
    expect(intelligence.vendorSource).toBe('company_id');
    expect(intelligence.protocols).toContain('iBeacon');
    expect(intelligence.category).toBe('Beacon / tracker');
    expect(intelligence.confidence).toBe('high');
  });

  it('classifies assigned services without inventing a manufacturer', () => {
    const intelligence = analyzeBleDevice(device({
      serviceUuids: ['0000180d-0000-1000-8000-00805f9b34fb']
    }));

    expect(intelligence.vendor).toBeNull();
    expect(intelligence.services[0]).toMatchObject({ name: 'Heart Rate', category: 'Health / fitness' });
    expect(intelligence.category).toBe('Health / fitness');
    expect(intelligence.confidence).toBe('medium');
  });

  it('uses the generated full Company ID lookup beyond the common vendor set', () => {
    expect(bleCompanyName(0x10cc)).toBe('Linde GmbH');
    expect(bleAppearanceName(962)).toBe('Mouse');
    expect(bleAssignedNumbersMetadata().counts).toEqual({
      companies: 3998,
      services: 126,
      appearances: 302
    });
  });

  it('prefers system friendly names and device type over advertisement guesses', () => {
    const intelligence = analyzeBleDevice(device({
      localName: 'MX Master 2S',
      systemId: 'windows:mouse',
      systemCategory: 'Mouse',
      inventorySource: 'windows-device-enumeration',
      connected: true,
      radioObserved: false,
      rssiDbm: null
    }));

    expect(intelligence.displayName).toBe('MX Master 2S');
    expect(intelligence.category).toBe('Mouse');
    expect(intelligence.confidence).toBe('high');
    expect(intelligence.evidence.join(' ')).toMatch(/Windows/i);
  });

  it('never renders missing radio identity as undefined', () => {
    const anonymous = analyzeBleDevice(device({
      addressType: 'resolvable_private',
      localName: 'undefined'
    }));
    const assignedVendor = analyzeBleDevice(device({
      manufacturerData: [{ company_id: 0x004c, data: [0x10, 0x02] }]
    }));

    expect(anonymous.displayName).toBe('Anonymous private BLE advertiser');
    expect(anonymous.category).toBe('Identity not advertised');
    expect(assignedVendor.displayName).toBe('Apple, Inc. Bluetooth device');
    expect(assignedVendor.protocols).toContain('Apple Continuity');
  });
});

function device(overrides: Partial<BleWorkspaceDevice>): BleWorkspaceDevice {
  return {
    key: 'test-device',
    identityKey: 'ble-id-v1:test',
    identityConfidence: 'static_address',
    protocol: null,
    currentAddress: 'AA:BB:CC:DD:EE:FF',
    addressType: 'random_static',
    localName: null,
    rssiDbm: -60,
    txPowerDbm: null,
    connectable: false,
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
