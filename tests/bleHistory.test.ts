import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import type { DesktopBleScanResult } from '../src/platform/radiochronBle';
import {
  appendBleHistory,
  clearBleHistory,
  readBleHistory
} from '../src/platform/bleHistory';

const tempDirs: string[] = [];

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((directory) => rm(directory, { force: true, recursive: true })));
});

describe('desktop BLE history', () => {
  it('persists privacy-minimized scan sessions without raw radio addresses', async () => {
    const filePath = await tempHistoryFile();
    const result = sampleResult(Date.UTC(2026, 6, 23, 12), 'AA:BB:CC:DD:EE:FF');

    const archive = await appendBleHistory(filePath, result, 'Desk');
    const stored = await readFile(filePath, 'utf8');

    expect(archive.sessions).toHaveLength(1);
    expect(archive.sessions[0].points[0]).toMatchObject({
      identity_key: 'ble-id-v1:privacy-safe',
      local_name: 'Test Beacon',
      rssi_dbm: -61,
      service_uuids: ['0000181a-0000-1000-8000-00805f9b34fb'],
      company_ids: [0x0059],
      service_data_uuids: []
    });
    expect(stored).not.toContain('AA:BB:CC:DD:EE:FF');
    expect(stored).not.toContain('"manufacturer_data":');
    expect(stored).not.toContain('"service_data":');
    expect(stored).toContain('ble-id-v1:privacy-safe');
    expect(archive.sessions[0].system_devices[0]).toMatchObject({
      id: 'windows:test-mouse',
      name: 'Test Mouse',
      connected: true,
      category: 'Mouse',
      appearance: 962
    });
    expect(stored).not.toContain('11:22:33:44:55:66');
  });

  it('retains only sessions inside the 30 day window', async () => {
    const filePath = await tempHistoryFile();
    const nowMs = Date.UTC(2026, 6, 23, 12);
    await appendBleHistory(filePath, sampleResult(nowMs - 31 * 24 * 60 * 60 * 1_000, 'old'), 'Desk');

    const archive = await appendBleHistory(filePath, sampleResult(nowMs, 'current'), 'Desk');

    expect(archive.sessions).toHaveLength(1);
    expect(archive.sessions[0].observed_at_ms).toBe(nowMs);
  });

  it('fails closed on invalid persisted schemas and clears the archive', async () => {
    const filePath = await tempHistoryFile();
    await writeFile(filePath, '{"schema_version":99,"sessions":[]}', 'utf8');

    const invalid = await readBleHistory(filePath, Date.now());
    expect(invalid.sessions).toEqual([]);
    expect(invalid.storage_warning).toMatch(/unsupported|invalid/i);

    await clearBleHistory(filePath);
    const cleared = await readBleHistory(filePath, Date.now());
    expect(cleared.sessions).toEqual([]);
    expect(cleared.storage_warning).toBeNull();
  });

  it('migrates version 1 radio-only history without discarding it', async () => {
    const filePath = await tempHistoryFile();
    const legacySession = {
      scan_id: 'legacy',
      observed_at_ms: Date.now(),
      zone: 'Desk',
      elapsed_ms: 500,
      adapter_count: 1,
      advertisement_count: 0,
      error_count: 0,
      points: [],
      findings: []
    };
    await writeFile(filePath, JSON.stringify({ schema_version: 1, sessions: [legacySession] }), 'utf8');

    const archive = await readBleHistory(filePath, Date.now());

    expect(archive.schema_version).toBe(3);
    expect(archive.sessions).toHaveLength(1);
    expect(archive.sessions[0].system_devices).toEqual([]);
  });
});

async function tempHistoryFile(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), 'radiochron-ble-history-'));
  tempDirs.push(directory);
  return join(directory, 'ble-history.json');
}

function sampleResult(scannedAtMs: number, address: string): DesktopBleScanResult {
  const identity = {
    key: 'ble-id-v1:privacy-safe',
    confidence: 'static_address' as const,
    protocol: null
  };
  return {
    scanned_at_ms: scannedAtMs,
    scan: {
      adapter_count: 1,
      elapsed_ms: 500,
      advertisements: [{
        address,
        address_type: 'random_static',
        local_name: 'Test Beacon',
        rssi_dbm: -61,
        service_uuids: ['0000181a-0000-1000-8000-00805f9b34fb'],
        manufacturer_data: [{ company_id: 0x0059, data: [1, 2, 3] }]
      }],
      system_devices: [{
        id: 'windows:test-mouse',
        name: 'Test Mouse',
        address: '11:22:33:44:55:66',
        transport: 'ble',
        paired: true,
        connected: true,
        category: 'Mouse',
        class_of_device: null,
        appearance: 962,
        source: 'windows-device-enumeration'
      }],
      errors: []
    },
    observations: [{
      identity,
      payload_hash: 'ble-payload-v1:test',
      history: {
        identity,
        first_seen_ms: 1,
        last_seen_ms: 1,
        observation_count: 1,
        sensor_count: 1,
        movement_session_count: 0,
        rssi_min_dbm: -61,
        rssi_max_dbm: -61,
        rssi_mean_dbm: -61,
        last_payload_hash: 'ble-payload-v1:test'
      },
      findings: []
    }],
    histories: [],
    findings: []
  };
}
