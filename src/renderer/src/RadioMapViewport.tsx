import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
  type MouseEvent as ReactMouseEvent,
  type PointerEvent as ReactPointerEvent,
  type RefObject,
  type WheelEvent
} from 'react';
import { useBodyScrollLock } from './bodyScrollLock';
import {
  adjustRadioMapPanForZoom,
  clampRadioMapPan,
  clampRadioMapZoom,
  type MapPan,
  type MapViewportSize
} from './radioMapGeometry';
export type { MapPan, MapViewportSize } from './radioMapGeometry';

interface RadioMapViewportOptions {
  escapeBlocked?: boolean;
  blockedTargetSelector?: string;
}

export interface RadioMapViewportController {
  zoom: number;
  layoutZoom: number;
  pan: MapPan;
  isPanning: boolean;
  fullscreen: boolean;
  canPanMap: boolean;
  mapViewportSize: MapViewportSize;
  mapStageRef: RefObject<HTMLDivElement | null>;
  mapStageStyle: CSSProperties;
  canvasStyle: CSSProperties;
  zoomIn: () => void;
  zoomOut: () => void;
  resetZoom: () => void;
  toggleFullscreen: () => void;
  handleMapWheel: (event: WheelEvent<HTMLDivElement>) => void;
  handleMapPointerDown: (event: ReactPointerEvent<HTMLDivElement>) => void;
  handleMapClickCapture: (event: ReactMouseEvent<HTMLDivElement>) => void;
}

const DEFAULT_BLOCKED_TARGETS =
  '.map-toolbar, .map-location-toolbar, .map-connection-layer, .map-center, .map-node, .map-cluster, .radio-map-node, .ble-system-map-dock';

export function useRadioMapViewport(
  options: RadioMapViewportOptions = {}
): RadioMapViewportController {
  const blockedTargetSelector = options.blockedTargetSelector ?? DEFAULT_BLOCKED_TARGETS;
  const [zoom, setZoom] = useState(1);
  const [layoutZoom, setLayoutZoom] = useState(1);
  const [pan, setPan] = useState<MapPan>({ x: 0, y: 0 });
  const [isPanning, setIsPanning] = useState(false);
  const [fullscreen, setFullscreen] = useState(false);
  const [mapViewportSize, setMapViewportSize] = useState<MapViewportSize>({ width: 0, height: 0 });
  const mapStageRef = useRef<HTMLDivElement | null>(null);
  const dragStateRef = useRef<{
    pointerId: number;
    startX: number;
    startY: number;
    originX: number;
    originY: number;
  } | null>(null);
  const suppressNextMapClickRef = useRef(false);
  const canPanMap = zoom > 0.42;
  useBodyScrollLock(fullscreen);

  useEffect(() => {
    setLayoutZoom((previous) => {
      const ratio = zoom / previous;
      return ratio >= 1.5 || ratio <= 1 / 1.5 ? zoom : previous;
    });
  }, [zoom]);

  const applyZoomDelta = useCallback((delta: number, anchor?: { clientX: number; clientY: number }) => {
    setZoom((current) => {
      const next = clampRadioMapZoom(current + delta);
      if (next === current) return current;
      const stageRect = mapStageRef.current?.getBoundingClientRect() ?? null;
      setPan((currentPan) => adjustRadioMapPanForZoom(currentPan, current, next, stageRect, anchor));
      return next;
    });
  }, []);

  const zoomIn = useCallback(() => applyZoomDelta(0.18), [applyZoomDelta]);
  const zoomOut = useCallback(() => applyZoomDelta(-0.18), [applyZoomDelta]);
  const resetZoom = useCallback(() => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
  }, []);
  const toggleFullscreen = useCallback(() => setFullscreen((current) => !current), []);

  const handleMapWheel = useCallback((event: WheelEvent<HTMLDivElement>) => {
    if (!event.ctrlKey) return;
    event.preventDefault();
    applyZoomDelta(
      event.deltaY < 0 ? 0.12 : -0.12,
      { clientX: event.clientX, clientY: event.clientY }
    );
  }, [applyZoomDelta]);

  const handleMapPointerDown = useCallback((event: ReactPointerEvent<HTMLDivElement>) => {
    const target = event.target as HTMLElement;
    if (event.button !== 0 || !canPanMap || target.closest(blockedTargetSelector)) return;
    dragStateRef.current = {
      pointerId: event.pointerId,
      startX: event.clientX,
      startY: event.clientY,
      originX: pan.x,
      originY: pan.y
    };
    setIsPanning(true);
  }, [blockedTargetSelector, canPanMap, pan.x, pan.y]);

  const handleMapClickCapture = useCallback((event: ReactMouseEvent<HTMLDivElement>) => {
    if (!suppressNextMapClickRef.current) return;
    event.preventDefault();
    event.stopPropagation();
    suppressNextMapClickRef.current = false;
  }, []);

  useEffect(() => {
    if (canPanMap) return;
    setPan({ x: 0, y: 0 });
    setIsPanning(false);
    dragStateRef.current = null;
  }, [canPanMap]);

  useEffect(() => {
    const stage = mapStageRef.current;
    if (!stage) return undefined;
    const updateSize = () => {
      const rect = stage.getBoundingClientRect();
      const next = { width: Math.round(rect.width), height: Math.round(rect.height) };
      setMapViewportSize((current) =>
        current.width === next.width && current.height === next.height ? current : next
      );
    };
    updateSize();
    if (typeof ResizeObserver === 'undefined') {
      window.addEventListener('resize', updateSize);
      return () => window.removeEventListener('resize', updateSize);
    }
    const observer = new ResizeObserver(updateSize);
    observer.observe(stage);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    if (!fullscreen) return undefined;
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !options.escapeBlocked) setFullscreen(false);
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [fullscreen, options.escapeBlocked]);

  useEffect(() => {
    if (!fullscreen) return undefined;
    const handleWheel = (event: globalThis.WheelEvent) => {
      if (shouldPreventFullscreenScrollLeak(event.target, event.deltaY)) event.preventDefault();
    };
    const handleTouchMove = (event: TouchEvent) => {
      if (!(event.target instanceof Element) || !event.target.closest('.map-panel-fullscreen')) {
        event.preventDefault();
      }
    };
    window.addEventListener('wheel', handleWheel, { capture: true, passive: false });
    window.addEventListener('touchmove', handleTouchMove, { capture: true, passive: false });
    return () => {
      window.removeEventListener('wheel', handleWheel, { capture: true });
      window.removeEventListener('touchmove', handleTouchMove, { capture: true });
    };
  }, [fullscreen]);

  useEffect(() => {
    if (!isPanning) return undefined;
    const handleWindowPointerMove = (event: PointerEvent) => {
      const dragState = dragStateRef.current;
      if (!dragState || dragState.pointerId !== event.pointerId) return;
      event.preventDefault();
      const deltaX = event.clientX - dragState.startX;
      const deltaY = event.clientY - dragState.startY;
      if (Math.abs(deltaX) > 4 || Math.abs(deltaY) > 4) suppressNextMapClickRef.current = true;
      setPan({
        x: clampRadioMapPan(dragState.originX + deltaX, zoom),
        y: clampRadioMapPan(dragState.originY + deltaY, zoom)
      });
    };
    const stopWindowPan = (event: PointerEvent) => {
      const dragState = dragStateRef.current;
      if (!dragState || dragState.pointerId !== event.pointerId) return;
      dragStateRef.current = null;
      setIsPanning(false);
    };
    window.addEventListener('pointermove', handleWindowPointerMove);
    window.addEventListener('pointerup', stopWindowPan);
    window.addEventListener('pointercancel', stopWindowPan);
    return () => {
      window.removeEventListener('pointermove', handleWindowPointerMove);
      window.removeEventListener('pointerup', stopWindowPan);
      window.removeEventListener('pointercancel', stopWindowPan);
    };
  }, [isPanning, zoom]);

  const mapStageStyle = useMemo(() => ({
    '--map-grid-size': `${Math.max(14, Math.round(48 * zoom))}px`,
    '--map-grid-pan-x': `${Math.round(pan.x)}px`,
    '--map-grid-pan-y': `${Math.round(pan.y)}px`
  }) as CSSProperties, [pan.x, pan.y, zoom]);
  const canvasStyle = useMemo(
    () => ({ transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom / layoutZoom})` }),
    [layoutZoom, pan.x, pan.y, zoom]
  );

  return {
    zoom,
    layoutZoom,
    pan,
    isPanning,
    fullscreen,
    canPanMap,
    mapViewportSize,
    mapStageRef,
    mapStageStyle,
    canvasStyle,
    zoomIn,
    zoomOut,
    resetZoom,
    toggleFullscreen,
    handleMapWheel,
    handleMapPointerDown,
    handleMapClickCapture
  };
}
export function RadioMapViewportToolbar({
  viewport
}: {
  viewport: RadioMapViewportController;
}) {
  return (
    <div className="map-toolbar map-viewport-toolbar" aria-label="Map controls">
      <button type="button" onClick={viewport.zoomOut} aria-label="Zoom out">-</button>
      <span>{Math.round(viewport.zoom * 100)}%</span>
      <button type="button" onClick={viewport.zoomIn} aria-label="Zoom in">+</button>
      <button type="button" onClick={viewport.resetZoom}>Reset</button>
      <button type="button" onClick={viewport.toggleFullscreen}>
        {viewport.fullscreen ? 'Exit full' : 'Full map'}
      </button>
    </div>
  );
}

function shouldPreventFullscreenScrollLeak(target: EventTarget | null, deltaY: number): boolean {
  if (!(target instanceof Element)) return true;
  const panel = target.closest('.map-panel-fullscreen');
  if (!(panel instanceof HTMLElement)) return true;
  const scrollTarget = target.closest('.map-side-list, .map-panel-fullscreen');
  if (!(scrollTarget instanceof HTMLElement)) return true;
  if (scrollTarget.scrollHeight <= scrollTarget.clientHeight + 1) return true;
  if (deltaY < 0) return scrollTarget.scrollTop <= 0;
  if (deltaY > 0) {
    return scrollTarget.scrollTop + scrollTarget.clientHeight >= scrollTarget.scrollHeight - 1;
  }
  return false;
}
