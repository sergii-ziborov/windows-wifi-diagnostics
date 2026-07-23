import { describe, expect, it } from 'vitest';
import { layoutBleMap } from '../src/renderer/src/bleMapLayout';

describe('Bluetooth map layout', () => {
  it('separates colliding signal labels', () => {
    const signals = Array.from({ length: 12 }, (_, index) => ({
      key: `same-band-${index}`,
      rssiDbm: -42
    }));
    const positions = [...layoutBleMap(signals, 'wide', 1).values()];

    for (let left = 0; left < positions.length; left += 1) {
      for (let right = left + 1; right < positions.length; right += 1) {
        const dx = Math.abs(positions[left].x - positions[right].x);
        const dy = Math.abs(positions[left].y - positions[right].y);
        expect(dx >= 5.5 || dy >= 8, `nodes ${left} and ${right} still overlap`).toBe(true);
      }
    }
  });

  it('moves a signal farther from the sensor with spread and zoom', () => {
    const signal = [{ key: 'device', rssiDbm: -65 }];
    const normal = layoutBleMap(signal, 'normal', 1).get('device')!;
    const far = layoutBleMap(signal, 'far+', 1.4).get('device')!;
    const distance = (point: { x: number; y: number }) => Math.hypot(point.x - 50, point.y - 50);

    expect(distance(far)).toBeGreaterThan(distance(normal));
  });
});
