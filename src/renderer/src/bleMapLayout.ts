export type BleMapSpread = 'tight' | 'compact' | 'normal' | 'wide' | 'wide+' | 'far' | 'far+';

export interface BleMapSignal {
  key: string;
  rssiDbm: number;
}

export interface BleMapPosition {
  x: number;
  y: number;
}

const SPREAD_SCALE: Record<BleMapSpread, number> = {
  tight: 0.62,
  compact: 0.78,
  normal: 1,
  wide: 1.22,
  'wide+': 1.42,
  far: 1.66,
  'far+': 1.9
};

export function layoutBleMap(
  signals: readonly BleMapSignal[],
  spread: BleMapSpread,
  zoom: number,
  viewportSize: MapViewportSize = { width: 0, height: 0 }
): Map<string, BleMapPosition> {
  const scale = SPREAD_SCALE[spread] * clamp(zoom, 0.35, 4);
  const positions = signals.map((signal) => initialPosition(signal, scale));
  for (let iteration = 0; iteration < 42; iteration += 1) {
    separateNodes(positions, viewportSize);
    positions.forEach(keepOutsideSensor);
    positions.forEach((position) => keepInBounds(position, zoom));
  }
  return new Map(positions.map((item) => [item.key, { x: item.x, y: item.y }]));
}

function initialPosition(signal: BleMapSignal, scale: number) {
  const normalized = clamp((-signal.rssiDbm - 30) / 75, 0.12, 1);
  const radius = (8 + normalized * 34) * scale;
  const angle = (hashString(signal.key) % 360) * (Math.PI / 180);
  return {
    key: signal.key,
    x: 50 + Math.cos(angle) * radius,
    y: 50 + Math.sin(angle) * radius
  };
}

function separateNodes(
  nodes: Array<{ key: string; x: number; y: number }>,
  viewportSize: MapViewportSize
): void {
  const metricPixels = Math.max(1, Math.min(viewportSize.width || 620, viewportSize.height || 560));
  const minimumX = Math.max(7, (94 / metricPixels) * 100);
  const minimumY = Math.max(10, (82 / metricPixels) * 100);
  for (let leftIndex = 0; leftIndex < nodes.length; leftIndex += 1) {
    for (let rightIndex = leftIndex + 1; rightIndex < nodes.length; rightIndex += 1) {
      const left = nodes[leftIndex];
      const right = nodes[rightIndex];
      const dx = right.x - left.x;
      const dy = right.y - left.y;
      if (Math.abs(dx) >= minimumX || Math.abs(dy) >= minimumY) continue;
      const fallbackAngle = (hashString(`${left.key}:${right.key}`) % 360) * (Math.PI / 180);
      const distance = Math.hypot(dx, dy);
      const unitX = distance > 0.01 ? dx / distance : Math.cos(fallbackAngle);
      const unitY = distance > 0.01 ? dy / distance : Math.sin(fallbackAngle);
      const push = Math.max(
        (minimumX - Math.abs(dx)) / 2,
        (minimumY - Math.abs(dy)) / 2,
        0.35
      );
      left.x -= unitX * push;
      left.y -= unitY * push;
      right.x += unitX * push;
      right.y += unitY * push;
    }
  }
}

function keepOutsideSensor(node: { x: number; y: number }): void {
  const dx = node.x - 50;
  const dy = node.y - 50;
  if (Math.abs(dx) >= 7 || Math.abs(dy) >= 13) return;
  const angle = Math.atan2(dy || 0.1, dx || 0.1);
  node.x = 50 + Math.cos(angle) * 8;
  node.y = 50 + Math.sin(angle) * 14;
}

function keepInBounds(node: { x: number; y: number }, zoom: number): void {
  const overflow = 18 + Math.max(0, zoom - 1) * 28;
  node.x = clamp(node.x, -overflow, 100 + overflow);
  node.y = clamp(node.y, -overflow, 100 + overflow);
}

function clamp(value: number, minimum: number, maximum: number): number {
  return Math.max(minimum, Math.min(maximum, value));
}

function hashString(value: string): number {
  let hash = 2166136261;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
}
import type { MapViewportSize } from './RadioMapViewport';
