import type {
  DesktopBleHistoryArchive,
  DesktopBleHistoryPoint,
  DesktopBleViewResult
} from '../platform/bleHistory';

export function demoBleScanResult(): DesktopBleViewResult {
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
    ],
    analytics_history: demoBleHistory(scannedAtMs)
  };
}

export function demoBleHistory(scannedAtMs = Date.now()): DesktopBleHistoryArchive {
  const sessions = Array.from({ length: 12 }, (_, index) => {
    const observedAtMs = scannedAtMs - (11 - index) * 5 * 60 * 1_000;
    const points: DesktopBleHistoryPoint[] = [
      demoPoint('protocol:demo-environment-beacon', 'Mock Env Beacon', 'caller_provided', 'caller', -48 + (index % 4) - 2)
    ];
    if ([3, 4, 6, 7, 8, 10, 11].includes(index)) {
      points.push(demoPoint('ephemeral:demo-private-tag', 'Mock Tag', 'ephemeral_address', null, -70 + (index % 5)));
    }
    if (index % 2 === 0 || index >= 9) {
      points.push(demoPoint('protocol:demo-asset-beacon', 'Mock Asset Beacon', 'caller_provided', 'caller', -78 + (index % 6)));
    }
    const persistentFinding = index >= 8 && points.some((point) => point.identity_key === 'ephemeral:demo-private-tag');
    return {
      scan_id: `mock-scan-${String(index + 1).padStart(2, '0')}`,
      observed_at_ms: observedAtMs,
      zone: index < 7 ? 'Mock Lab' : 'Mock Desk',
      elapsed_ms: 1_500,
      adapter_count: 1,
      advertisement_count: points.length,
      error_count: 0,
      points,
      findings: persistentFinding
        ? [{
            kind: 'persistent_unknown' as const,
            severity: 'warning' as const,
            identity_key: 'ephemeral:demo-private-tag',
            summary: 'Mock unknown identity recurred across sampled scans.'
          }]
        : []
    };
  });

  return {
    schema_version: 1,
    generated_at_ms: scannedAtMs,
    storage_warning: null,
    retention: {
      max_age_days: 30,
      max_sessions: 512
    },
    sessions
  };
}

function demoPoint(
  identityKey: string,
  localName: string,
  identityConfidence: DesktopBleHistoryPoint['identity_confidence'],
  protocol: string | null,
  rssiDbm: number
): DesktopBleHistoryPoint {
  return {
    identity_key: identityKey,
    identity_confidence: identityConfidence,
    protocol,
    local_name: localName,
    address_type: identityConfidence === 'ephemeral_address' ? 'resolvable_private' : 'random_static',
    rssi_dbm: rssiDbm,
    payload_hash: `mock-payload:${identityKey}`
  };
}
