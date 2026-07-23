import { describe, expect, it } from 'vitest';
import type { DesktopBleViewResult } from '../src/platform/bleHistory';
import { buildBleWorkspaceDevices } from '../src/renderer/src/bleWorkspaceModel';

describe('Bluetooth workspace model', () => {
  it('includes a connected system mouse even when it is not advertising', () => {
    const devices = buildBleWorkspaceDevices(result([], [{
      id: 'windows:mouse',
      name: 'MX Master 2S',
      address: 'e9:90:d7:23:ca:69',
      transport: 'ble',
      paired: true,
      connected: true,
      category: 'Mouse',
      class_of_device: null,
      appearance: 962,
      source: 'windows-device-enumeration'
    }]), null);

    expect(devices).toHaveLength(1);
    expect(devices[0]).toMatchObject({
      localName: 'MX Master 2S',
      connected: true,
      paired: true,
      systemCategory: 'Mouse',
      systemAppearance: 962,
      rssiDbm: null,
      radioObserved: false,
      mergeConfidence: 'system_only'
    });
  });

  it('joins system naming and radio evidence only on an exact address', () => {
    const advertisement = {
      address: 'AA:BB:CC:DD:EE:FF',
      address_type: 'public' as const,
      local_name: null,
      rssi_dbm: -55,
      service_uuids: [],
      manufacturer_data: [],
      service_data: []
    };
    const devices = buildBleWorkspaceDevices(result([advertisement], [{
      id: 'windows:keyboard',
      name: 'Studio Keyboard',
      address: 'aa-bb-cc-dd-ee-ff',
      transport: 'dual',
      paired: true,
      connected: false,
      category: 'Keyboard',
      class_of_device: 0,
      appearance: null,
      source: 'windows-device-enumeration'
    }]), null);

    expect(devices).toHaveLength(1);
    expect(devices[0]).toMatchObject({
      localName: 'Studio Keyboard',
      rssiDbm: -55,
      radioObserved: true,
      systemCategory: 'Keyboard',
      mergeConfidence: 'exact_address'
    });
  });
});

function result(
  advertisements: DesktopBleViewResult['scan']['advertisements'],
  systemDevices: NonNullable<DesktopBleViewResult['scan']['system_devices']>
): DesktopBleViewResult {
  return {
    scanned_at_ms: 1000,
    scan: {
      adapter_count: 1,
      elapsed_ms: 500,
      advertisements,
      system_devices: systemDevices,
      errors: []
    },
    observations: [],
    histories: [],
    findings: [],
    analytics_history: {
      schema_version: 3,
      generated_at_ms: 1000,
      storage_warning: null,
      retention: { max_age_days: 30, max_sessions: 512 },
      sessions: []
    }
  };
}
