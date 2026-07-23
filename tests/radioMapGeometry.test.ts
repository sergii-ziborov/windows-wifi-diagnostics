import { describe, expect, it } from 'vitest';
import {
  adjustRadioMapPanForZoom,
  clampRadioMapPan,
  clampRadioMapZoom,
  radioMapRingStyle,
  radioMetricPointToViewport
} from '../src/renderer/src/radioMapGeometry';

describe('shared radio map geometry', () => {
  it('uses the same bounded zoom range for Wi-Fi and Bluetooth', () => {
    expect(clampRadioMapZoom(0.1)).toBe(0.35);
    expect(clampRadioMapZoom(1.237)).toBe(1.24);
    expect(clampRadioMapZoom(8)).toBe(4);
  });

  it('keeps the cursor anchor stable when zoom changes', () => {
    const rect = { left: 100, top: 50, width: 800, height: 600 };
    expect(adjustRadioMapPanForZoom(
      { x: 0, y: 0 },
      1,
      2,
      rect,
      { clientX: 300, clientY: 200 }
    )).toEqual({ x: 200, y: 150 });
  });

  it('maps metric circles into a rectangular viewport without distortion', () => {
    expect(radioMetricPointToViewport({ x: 75, y: 50 }, { width: 1000, height: 500 }))
      .toEqual({ x: 62.5, y: 50 });
    expect(radioMapRingStyle(82, 1, { width: 1000, height: 500 }))
      .toEqual({ width: '410px', height: '410px' });
  });

  it('prevents unbounded panning', () => {
    expect(clampRadioMapPan(9999, 2)).toBe(661);
    expect(clampRadioMapPan(-9999, 2)).toBe(-661);
  });
});
