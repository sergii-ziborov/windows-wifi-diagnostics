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
      rssi_dbm: -61
    });
    expect(stored).not.toContain('AA:BB:CC:DD:EE:FF');
    expect(stored).toContain('ble-id-v1:privacy-safe');
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
        rssi_dbm: -61
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
