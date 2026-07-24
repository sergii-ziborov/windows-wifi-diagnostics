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

  it('uses the latest history tracking key for a rotated current address', () => {
    const advertisement = {
      address: '41:00:00:00:00:02',
      address_type: 'resolvable_private' as const,
      local_name: null,
      rssi_dbm: -43,
      service_uuids: [],
      manufacturer_data: [{ company_id: 0x004c, data: [1, 2, 3] }],
      service_data: []
    };
    const view = result([advertisement], []);
    const identity = {
      key: 'ble-id-v1:rotated-address',
      confidence: 'ephemeral_address' as const,
      protocol: null
    };
    view.scanned_at_ms = 2_000;
    view.observations = [{
      identity,
      payload_hash: 'ble-payload-v1:apple',
      history: {
        identity,
        first_seen_ms: 2_000,
        last_seen_ms: 2_000,
        observation_count: 1,
        sensor_count: 1,
        movement_session_count: 0,
        rssi_min_dbm: -43,
        rssi_max_dbm: -43,
        rssi_mean_dbm: -43,
        last_payload_hash: 'ble-payload-v1:apple'
      },
      findings: []
    }];
    view.analytics_history.sessions = [{
      scan_id: 'current',
      observed_at_ms: 2_000,
      zone: 'Desk',
      elapsed_ms: 500,
      adapter_count: 1,
      advertisement_count: 1,
      system_device_count: 0,
      error_count: 0,
      points: [{
        identity_key: identity.key,
        tracking_key: 'ble-id-v1:first-address',
        tracking_confidence: 'probabilistic_rotation',
        identity_confidence: 'ephemeral_address',
        protocol: null,
        local_name: null,
        address_type: 'resolvable_private',
        rssi_dbm: -43,
        payload_hash: 'ble-payload-v1:apple'
      }],
      system_devices: [],
      findings: []
    }];

    const devices = buildBleWorkspaceDevices(view, view.analytics_history);

    expect(devices).toHaveLength(1);
    expect(devices[0]).toMatchObject({
      key: 'ble-id-v1:first-address',
      identityKey: 'ble-id-v1:rotated-address',
      trackingConfidence: 'probabilistic_rotation',
      retainedOnly: false
    });
  });

  it('keeps one-off private addresses in analytics history without presenting them as retained devices', () => {
    const archive = result([], []).analytics_history;
    const point = (identityKey: string, trackingKey: string, confidence: 'ephemeral_address' | 'static_address') => ({
      identity_key: identityKey,
      tracking_key: trackingKey,
      tracking_confidence: confidence === 'static_address' ? 'stable_identity' as const : 'single_observation' as const,
      identity_confidence: confidence,
      protocol: null,
      local_name: null,
      address_type: confidence === 'static_address' ? 'public' as const : 'resolvable_private' as const,
      rssi_dbm: -55,
      payload_hash: 'payload'
    });
    archive.sessions = [
      {
        scan_id: 'one',
        observed_at_ms: 1_000,
        zone: 'Desk',
        elapsed_ms: 500,
        adapter_count: 1,
        advertisement_count: 3,
        system_device_count: 0,
        error_count: 0,
        points: [
          point('single-private', 'single-private', 'ephemeral_address'),
          point('recurring-private-one', 'recurring-private', 'ephemeral_address'),
          point('stable', 'stable', 'static_address')
        ],
        system_devices: [],
        findings: []
      },
      {
        scan_id: 'two',
        observed_at_ms: 2_000,
        zone: 'Desk',
        elapsed_ms: 500,
        adapter_count: 1,
        advertisement_count: 1,
        system_device_count: 0,
        error_count: 0,
        points: [point('recurring-private-two', 'recurring-private', 'ephemeral_address')],
        system_devices: [],
        findings: []
      }
    ];

    const devices = buildBleWorkspaceDevices(null, archive);

    expect(devices.map((device) => device.key).sort()).toEqual(['recurring-private', 'stable']);
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
      schema_version: 4,
      generated_at_ms: 1000,
      storage_warning: null,
      retention: { max_age_days: 30, max_sessions: 512 },
      sessions: []
    }
  };
}
