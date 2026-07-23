import { describe, expect, it, vi } from 'vitest';
import { demoBleScanResult } from '../src/demo/bleFixtures';
import { scanRadioChronBle } from '../src/platform/radiochronBle';

describe('RadioChron BLE desktop adapter', () => {
  it('records native advertisements with a stationary desktop sensor context', async () => {
    const observe = vi.fn(async (observation) => ({
      identity: { key: observation.advertisement.address, confidence: 'static_address', protocol: null },
      payload_hash: 'hash',
      history: {
        identity: { key: observation.advertisement.address, confidence: 'static_address', protocol: null },
        first_seen_ms: observation.monotonic_ms,
        last_seen_ms: observation.monotonic_ms,
        observation_count: 1,
        sensor_count: 1,
        movement_session_count: 0,
        rssi_min_dbm: -42,
        rssi_max_dbm: -42,
        rssi_mean_dbm: -42,
        last_payload_hash: 'hash'
      },
      findings: []
    }));
    const client = {
      ble: {
        scan: vi.fn(async () => ({
          adapter_count: 1,
          elapsed_ms: 500,
          advertisements: [{
            address: '02:00:00:00:00:01',
            address_type: 'random_static' as const,
            rssi_dbm: -42
          }],
          errors: []
        })),
        observe,
        histories: vi.fn(async () => []),
        evaluate: vi.fn(async () => []),
        identify: vi.fn(),
        resetTracker: vi.fn()
      }
    };

    const result = await scanRadioChronBle({ durationMs: 500, zone: 'Lab' }, client as never);

    expect(result.scan.advertisements).toHaveLength(1);
    expect(observe).toHaveBeenCalledWith(expect.objectContaining({
      context: expect.objectContaining({
        zone: 'Lab',
        movement_session: null,
        sensor_is_moving: false
      })
    }));
  });

  it('keeps screenshot data synthetic and visibly marked', () => {
    const demo = demoBleScanResult();
    expect(demo.scan.advertisements).toHaveLength(3);
    expect(demo.scan.advertisements.every((item) => item.local_name?.startsWith('Mock'))).toBe(true);
    expect(demo.scan.advertisements.every((item) => item.address.startsWith('02:00:00:'))).toBe(true);
  });
});
