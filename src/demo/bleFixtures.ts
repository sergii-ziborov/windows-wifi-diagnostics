import type { DesktopBleScanResult } from '../platform/radiochronBle';

export function demoBleScanResult(): DesktopBleScanResult {
  const scannedAtMs = Date.now();
  return {
    scanned_at_ms: scannedAtMs,
    scan: {
      adapter_count: 1,
      elapsed_ms: 1_500,
      advertisements: [
        {
          address: '02:00:00:BE:AC:01',
          address_type: 'random_static',
          local_name: 'Mock Env Beacon',
          rssi_dbm: -48,
          tx_power_dbm: -8,
          connectable: false,
          service_uuids: ['0000feaa-0000-1000-8000-00805f9b34fb'],
          manufacturer_data: [],
          service_data: [],
          protocol_identity: 'demo:environment-beacon'
        },
        {
          address: '02:00:00:BE:AC:02',
          address_type: 'resolvable_private',
          local_name: 'Mock Tag',
          rssi_dbm: -67,
          tx_power_dbm: null,
          connectable: true,
          service_uuids: [],
          manufacturer_data: [],
          service_data: [],
          protocol_identity: null
        },
        {
          address: '02:00:00:BE:AC:03',
          address_type: 'random_static',
          local_name: 'Mock Asset Beacon',
          rssi_dbm: -74,
          tx_power_dbm: -12,
          connectable: false,
          service_uuids: [],
          manufacturer_data: [],
          service_data: [],
          protocol_identity: 'demo:asset-beacon'
        }
      ],
      errors: []
    },
    observations: [],
    histories: [
      {
        identity: {
          key: 'protocol:demo-environment-beacon',
          confidence: 'caller_provided',
          protocol: 'caller'
        },
        first_seen_ms: 12_000,
        last_seen_ms: 132_000,
        observation_count: 18,
        sensor_count: 1,
        movement_session_count: 0,
        rssi_min_dbm: -55,
        rssi_max_dbm: -45,
        rssi_mean_dbm: -49,
        last_payload_hash: 'demo-payload-a'
      },
      {
        identity: {
          key: 'ephemeral:demo-private-tag',
          confidence: 'ephemeral_address',
          protocol: null
        },
        first_seen_ms: 72_000,
        last_seen_ms: 132_000,
        observation_count: 9,
        sensor_count: 1,
        movement_session_count: 0,
        rssi_min_dbm: -72,
        rssi_max_dbm: -64,
        rssi_mean_dbm: -67,
        last_payload_hash: 'demo-payload-b'
      },
      {
        identity: {
          key: 'protocol:demo-asset-beacon',
          confidence: 'caller_provided',
          protocol: 'caller'
        },
        first_seen_ms: 24_000,
        last_seen_ms: 132_000,
        observation_count: 14,
        sensor_count: 1,
        movement_session_count: 0,
        rssi_min_dbm: -80,
        rssi_max_dbm: -70,
        rssi_mean_dbm: -74,
        last_payload_hash: 'demo-payload-c'
      }
    ],
    findings: [
      {
        kind: 'persistent_unknown',
        severity: 'warning',
        identity_key: 'ephemeral:demo-private-tag',
        observed_at_ms: 132_000,
        summary: 'An unknown BLE identity persisted near this sensor.',
        evidence: ['Seen 9 times across 60 seconds.', 'Observed by 1 stationary sensor.'],
        limitations: [
          'A persistent beacon is not proof of tracking or malicious intent.',
          'Private BLE addresses can rotate and split one physical device into multiple histories.'
        ]
      }
    ]
  };
}
