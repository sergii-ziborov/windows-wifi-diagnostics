import {
  useEffect,
  useRef,
  useState,
  type CSSProperties
} from 'react';
import type { MapViewportSize } from './RadioMapViewport';

export interface RadioMapConnectionLink {
  id: string;
  sourceKey: string | null;
  targetKey: string;
  kind: string;
  start: { x: number; y: number };
  end: { x: number; y: number };
  sourceRadiusPx: number;
  targetRadiusPx: number;
  signal: number | null;
  label: string;
  detail: string;
}

export function RadioMapConnectionLayer({
  links,
  localNodeKey,
  selectedLinkId,
  highlightedItemKey,
  highlightedItemKeys,
  onSelect,
  onHighlight
}: {
  links: RadioMapConnectionLink[];
  localNodeKey: string;
  selectedLinkId: string | null;
  highlightedItemKey: string | null;
  highlightedItemKeys: Set<string>;
  onSelect: (linkId: string | null) => void;
  onHighlight: (itemKey: string | null) => void;
}) {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const [viewportSize, setViewportSize] = useState<MapViewportSize>({ width: 0, height: 0 });

  useEffect(() => {
    const svg = svgRef.current;
    if (!svg) return undefined;
    const updateSize = () => {
      const rect = svg.getBoundingClientRect();
      const next = { width: Math.round(rect.width), height: Math.round(rect.height) };
      setViewportSize((current) =>
        current.width === next.width && current.height === next.height ? current : next
      );
    };
    updateSize();
    if (typeof ResizeObserver === 'undefined') {
      window.addEventListener('resize', updateSize);
      return () => window.removeEventListener('resize', updateSize);
    }
    const observer = new ResizeObserver(updateSize);
    observer.observe(svg);
    return () => observer.disconnect();
  }, []);

  if (!links.length) return null;
  return (
    <svg ref={svgRef} className="map-connection-layer" viewBox="0 0 100 100" preserveAspectRatio="none" aria-label="Radio map relationships">
      {links.map((link) => {
        const path = connectionPath(link, viewportSize);
        const width = connectionWidth(link);
        const isSelected = link.id === selectedLinkId;
        const localHighlighted = highlightedItemKey === localNodeKey;
        const endpointHighlighted = highlightedItemKeys.has(link.targetKey)
          || (link.sourceKey !== null && highlightedItemKeys.has(link.sourceKey));
        const isHighlighted = localHighlighted ? link.sourceKey === null : endpointHighlighted;
        const hasHighlight = localHighlighted || highlightedItemKeys.size > 0;
        if (hasHighlight || selectedLinkId !== null) {
          if (!isSelected && !isHighlighted) return null;
        }
        const style = {
          '--map-link-edge-width': width.edge,
          '--map-link-core-width': width.core
        } as CSSProperties;
        return (
          <g
            key={link.id}
            className={`map-connection map-connection-${link.kind} ${isSelected ? 'map-connection-selected' : ''} ${isHighlighted ? 'map-connection-highlighted' : ''}`}
            style={style}
            role="button"
            tabIndex={0}
            aria-label={`${link.label}: ${link.detail}`}
            onClick={(event) => {
              event.stopPropagation();
              onHighlight(null);
              onSelect(isSelected ? null : link.id);
            }}
            onKeyDown={(event) => {
              if (event.key !== 'Enter' && event.key !== ' ') return;
              event.preventDefault();
              onHighlight(null);
              onSelect(isSelected ? null : link.id);
            }}
          >
            <path className="map-connection-hit" d={path} vectorEffect="non-scaling-stroke" />
            <path className="map-connection-edge" d={path} vectorEffect="non-scaling-stroke" />
            <path className="map-connection-core" d={path} vectorEffect="non-scaling-stroke" />
          </g>
        );
      })}
    </svg>
  );
}

function connectionPath(link: RadioMapConnectionLink, viewportSize: MapViewportSize): string {
  const start = offsetPoint(link.start, link.end, link.sourceRadiusPx, viewportSize);
  const end = offsetPoint(link.end, link.start, link.targetRadiusPx, viewportSize);
  return `M ${round(start.x)} ${round(start.y)} L ${round(end.x)} ${round(end.y)}`;
}

function offsetPoint(
  point: { x: number; y: number },
  toward: { x: number; y: number },
  radiusPx: number,
  viewportSize: MapViewportSize
): { x: number; y: number } {
  if (radiusPx <= 0 || viewportSize.width <= 0 || viewportSize.height <= 0) return point;
  const dxPx = ((toward.x - point.x) / 100) * viewportSize.width;
  const dyPx = ((toward.y - point.y) / 100) * viewportSize.height;
  const lengthPx = Math.hypot(dxPx, dyPx);
  if (lengthPx < 1) return point;
  const offsetPx = Math.min(radiusPx, lengthPx * 0.82);
  return {
    x: point.x + (dxPx / lengthPx) * (offsetPx / viewportSize.width) * 100,
    y: point.y + (dyPx / lengthPx) * (offsetPx / viewportSize.height) * 100
  };
}

function connectionWidth(link: RadioMapConnectionLink): { edge: string; core: string } {
  const signal = Math.max(15, Math.min(100, link.signal ?? 45));
  const base = ['connected', 'mesh_peer'].includes(link.kind) ? 1.9 : link.kind === 'memory' ? 1.1 : 1.45;
  const edge = base + signal / 145;
  return { edge: `${round(edge)}`, core: `${round(Math.max(0.8, edge * 0.42))}` };
}

function round(value: number): number {
  return Math.round(value * 10) / 10;
}
