import type { CSSProperties } from 'react';

export interface RadioMapPosition {
  x: number;
  y: number;
}

export type MapPan = RadioMapPosition;

export interface MapViewportSize {
  width: number;
  height: number;
}

export function clampRadioMapZoom(value: number): number {
  return Math.min(4, Math.max(0.35, Math.round(value * 100) / 100));
}

export function adjustRadioMapPanForZoom(
  pan: MapPan,
  fromZoom: number,
  toZoom: number,
  stageRect: Pick<DOMRect, 'left' | 'top' | 'width' | 'height'> | null,
  anchor?: { clientX: number; clientY: number }
): MapPan {
  const ratio = toZoom / Math.max(0.01, fromZoom);
  const centerX = stageRect ? stageRect.width / 2 : 0;
  const centerY = stageRect ? stageRect.height / 2 : 0;
  const anchorX = stageRect && anchor ? anchor.clientX - stageRect.left : centerX;
  const anchorY = stageRect && anchor ? anchor.clientY - stageRect.top : centerY;
  return {
    x: clampRadioMapPan(pan.x * ratio + (anchorX - centerX) * (1 - ratio), toZoom),
    y: clampRadioMapPan(pan.y * ratio + (anchorY - centerY) * (1 - ratio), toZoom)
  };
}

export function clampRadioMapPan(value: number, zoom: number): number {
  const maximum = Math.round(560 * Math.max(0, zoom - 0.82));
  return Math.min(maximum, Math.max(-maximum, Math.round(value)));
}

export function radioMetricPointToViewport(
  position: RadioMapPosition,
  viewportSize: MapViewportSize
): RadioMapPosition {
  if (viewportSize.width <= 0 || viewportSize.height <= 0) return position;
  const metricScalePx = Math.min(viewportSize.width, viewportSize.height);
  return {
    x: Math.round((50 + ((position.x - 50) * metricScalePx) / viewportSize.width) * 10) / 10,
    y: Math.round((50 + ((position.y - 50) * metricScalePx) / viewportSize.height) * 10) / 10
  };
}

export function radioMapRingStyle(
  baseSizePercent: number,
  zoom: number,
  viewportSize: MapViewportSize
): CSSProperties {
  const size = Math.round(baseSizePercent * zoom * 10) / 10;
  if (viewportSize.width <= 0 || viewportSize.height <= 0) {
    return { width: `${size}%`, height: `${size}%` };
  }
  const sizePx = Math.round(Math.min(viewportSize.width, viewportSize.height) * (size / 100));
  return { width: `${sizePx}px`, height: `${sizePx}px` };
}
