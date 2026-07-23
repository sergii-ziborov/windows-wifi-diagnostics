import { useMemo, useState } from 'react';
import { analyzeBleDevice } from './bleIntelligence';
import {
  BLE_MAP_HISTORY_FILTERS,
  filterBleMapDevices,
  type BleMapHistoryFilter
} from './bleMapFilters';
import { layoutBleMap, type BleMapSpread } from './bleMapLayout';
import {
  BleMapRadioNode,
  BleMapSideRow,
  BleMapSystemNode
} from './BluetoothMapElements';
import { BluetoothSensorModal } from './BluetoothSensorModal';
import {
  RadioMapConnectionLayer,
  type RadioMapConnectionLink
} from './RadioMapConnections';
import { RadioMapViewportToolbar, useRadioMapViewport } from './RadioMapViewport';
import { radioMapRingStyle, radioMetricPointToViewport } from './radioMapGeometry';
import type { BleWorkspaceDevice } from './bleWorkspaceModel';

const LOCAL_NODE_KEY = 'ble:local';
const SPREADS: Array<{ value: BleMapSpread; label: string }> = [
  { value: 'tight', label: 'tight' },
  { value: 'compact', label: 'compact' },
  { value: 'normal', label: 'normal' },
  { value: 'wide', label: 'wide' },
  { value: 'wide+', label: 'wide+' },
  { value: 'far', label: 'far' },
  { value: 'far+', label: 'far+' }
];

interface BluetoothMapProps {
  devices: BleWorkspaceDevice[];
  zone: string;
  adapterCount: number;
  lastScanMs: number | null;
  onSelect: (device: BleWorkspaceDevice) => void;
}

export function BluetoothMap({
  devices,
  zone,
  adapterCount,
  lastScanMs,
  onSelect
}: BluetoothMapProps) {
  const [spread, setSpread] = useState<BleMapSpread>('wide');
  const [historyFilter, setHistoryFilter] = useState<BleMapHistoryFilter>('all');
  const [query, setQuery] = useState('');
  const [showAll, setShowAll] = useState(false);
  const [highlightedKey, setHighlightedKey] = useState<string | null>(null);
  const [selectedLinkId, setSelectedLinkId] = useState<string | null>(null);
  const [sensorOpen, setSensorOpen] = useState(false);
  const viewport = useRadioMapViewport({ escapeBlocked: sensorOpen });
  const filteredDevices = useMemo(
    () => filterBleMapDevices(devices, historyFilter, query),
    [devices, historyFilter, query]
  );
  const visibleDevices = showAll ? filteredDevices : filteredDevices.slice(0, 40);
  const radioDevices = visibleDevices.filter((device) => device.rssiDbm !== null);
  const systemOnlyDevices = visibleDevices.filter((device) => device.rssiDbm === null && device.systemId);
  const positions = useMemo(
    () => layoutBleMap(
      radioDevices.map((device) => ({ key: device.key, rssiDbm: device.rssiDbm as number })),
      spread,
      viewport.layoutZoom,
      viewport.mapViewportSize
    ),
    [radioDevices, spread, viewport.layoutZoom, viewport.mapViewportSize]
  );
  const radioNodes = radioDevices.map((device) => ({
    device,
    intelligence: analyzeBleDevice(device),
    position: radioMetricPointToViewport(
      positions.get(device.key) ?? { x: 50, y: 50 },
      viewport.mapViewportSize
    )
  }));
  const systemNodes = systemOnlyDevices.slice(0, 8).map((device, index) => ({
    device,
    position: systemNodePosition(index)
  }));
  const nodePositions = new Map<string, { x: number; y: number }>([
    ...radioNodes.map((node) => [node.device.key, node.position] as const),
    ...systemNodes.map((node) => [node.device.key, node.position] as const)
  ]);
  const links = visibleDevices.flatMap((device) => {
    const end = nodePositions.get(device.key);
    return end ? [buildRelation(device, end)] : [];
  });
  const selectedLink = links.find((link) => link.id === selectedLinkId) ?? null;
  const highlightedKeys = new Set(highlightedKey ? [highlightedKey] : []);

  function highlight(key: string | null): void {
    setHighlightedKey((current) => current === key ? null : key);
    setSelectedLinkId(null);
  }

  return (
    <>
      <article
      className={`panel map-panel ble-map-panel ${viewport.fullscreen ? 'map-panel-fullscreen' : ''}`}
      role={viewport.fullscreen ? 'dialog' : undefined}
      aria-modal={viewport.fullscreen || undefined}
    >
      <header className="panel-heading ble-map-heading">
        <div><p className="bluetooth-eyebrow">Relative RF view</p><h2>{zone || 'Desktop sensor'}</h2></div>
        <span className="muted">
          {radioNodes.length} radio · {systemOnlyDevices.length} system · {filteredDevices.length} filtered
        </span>
      </header>
      <div className="ble-map-filterbar" aria-label="Bluetooth map history filters">
        <input
          type="search"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Filter name, address, protocol…"
          aria-label="Filter Bluetooth devices"
        />
        <label><span>Seen</span><select value={historyFilter} onChange={(event) => setHistoryFilter(event.target.value as BleMapHistoryFilter)}>
          {BLE_MAP_HISTORY_FILTERS.map((option) => <option value={option.value} key={option.value}>{option.label}</option>)}
        </select></label>
        <label><span>Spread</span><select value={spread} onChange={(event) => setSpread(event.target.value as BleMapSpread)}>
          {SPREADS.map((option) => <option value={option.value} key={option.value}>{option.label}</option>)}
        </select></label>
        <button type="button" className={showAll ? 'active' : ''} onClick={() => setShowAll((current) => !current)}>
          {showAll ? 'Top 40' : `All ${filteredDevices.length}`}
        </button>
      </div>
      <div className="ap-map-layout">
        <div
          ref={viewport.mapStageRef}
          className={`ap-map-stage ${viewport.canPanMap ? 'ap-map-stage-pannable' : ''} ${viewport.isPanning ? 'ap-map-stage-panning' : ''}`}
          style={viewport.mapStageStyle}
          aria-label="Nearby Bluetooth signal map"
          onWheel={viewport.handleMapWheel}
          onPointerDown={viewport.handleMapPointerDown}
          onClickCapture={viewport.handleMapClickCapture}
        >
          <RadioMapViewportToolbar viewport={viewport} />
          <div className="ap-map-canvas" style={viewport.canvasStyle}>
            <div className="map-ring map-ring-near" style={radioMapRingStyle(26, viewport.layoutZoom, viewport.mapViewportSize)}><span>strong</span></div>
            <div className="map-ring map-ring-mid" style={radioMapRingStyle(54, viewport.layoutZoom, viewport.mapViewportSize)}><span>medium</span></div>
            <div className="map-ring map-ring-far" style={radioMapRingStyle(82, viewport.layoutZoom, viewport.mapViewportSize)}><span>weak</span></div>
            <div className="ble-system-zone"><span>OS inventory · no RF distance</span></div>
            <RadioMapConnectionLayer
              links={links}
              localNodeKey={LOCAL_NODE_KEY}
              selectedLinkId={selectedLinkId}
              highlightedItemKey={highlightedKey}
              highlightedItemKeys={highlightedKeys}
              onSelect={setSelectedLinkId}
              onHighlight={setHighlightedKey}
            />
            <button
              type="button"
              className={`map-center map-center-button ble-map-center ${highlightedKey === LOCAL_NODE_KEY ? 'map-center-selected' : ''}`}
              onClick={(event) => { event.stopPropagation(); highlight(LOCAL_NODE_KEY); }}
              onDoubleClick={(event) => { event.stopPropagation(); setSensorOpen(true); }}
              title="You · click for relationships · double-click for local sensor details"
            ><strong>You</strong><span>BLE sensor</span></button>
            {radioNodes.map(({ device, intelligence, position }) => (
              <BleMapRadioNode
                key={device.key}
                device={device}
                intelligence={intelligence}
                position={position}
                highlighted={highlightedKey === device.key}
                onHighlight={() => highlight(device.key)}
                onOpen={() => onSelect(device)}
              />
            ))}
            {systemNodes.map(({ device, position }) => (
              <BleMapSystemNode
                key={device.key}
                device={device}
                position={position}
                highlighted={highlightedKey === device.key}
                onHighlight={() => highlight(device.key)}
                onOpen={() => onSelect(device)}
              />
            ))}
          </div>
          {selectedLink ? <aside className="ble-relation-detail"><strong>{selectedLink.label}</strong><span>{selectedLink.detail}</span></aside> : null}
          {!visibleDevices.length ? <p className="ble-map-empty">No Bluetooth evidence matches this filter.</p> : null}
        </div>
        <aside className="map-side-list ble-map-sidebar">
          <div className="map-side-heading"><div><strong>Bluetooth evidence</strong><small>Double-click map nodes for details</small></div></div>
          <MapSideGroup title="System inventory" devices={systemOnlyDevices} onSelect={onSelect} />
          <MapSideGroup title="Radio signals" devices={radioDevices} onSelect={onSelect} />
        </aside>
      </div>
      <p className="bluetooth-privacy-note">
        Solid links are OS-reported connections; dashed links are paired inventory; dotted links are observations.
        Radius is signal strength, not physical distance. Drag, zoom and fullscreen use the same engine as Wi-Fi.
      </p>
      </article>
      {sensorOpen ? (
        <BluetoothSensorModal
          zone={zone}
          adapterCount={adapterCount}
          lastScanMs={lastScanMs}
          devices={devices}
          onClose={() => setSensorOpen(false)}
        />
      ) : null}
    </>
  );
}

function MapSideGroup({
  title,
  devices,
  onSelect
}: {
  title: string;
  devices: BleWorkspaceDevice[];
  onSelect: (device: BleWorkspaceDevice) => void;
}) {
  if (!devices.length) return null;
  return (
    <section className="ble-map-side-group" aria-label={title}>
      <h3>{title}</h3>
      {devices.map((device) => <BleMapSideRow device={device} key={device.key} onSelect={onSelect} />)}
    </section>
  );
}

function systemNodePosition(index: number): { x: number; y: number } {
  return { x: 14 + (index % 4) * 24, y: 86 + Math.floor(index / 4) * 8 };
}

function buildRelation(device: BleWorkspaceDevice, end: { x: number; y: number }): RadioMapConnectionLink {
  const kind = device.connected ? 'connected' : device.paired ? 'paired' : device.retainedOnly ? 'memory' : device.radioObserved ? 'observed' : 'system';
  const label = device.connected ? 'Connected now' : device.paired ? 'Paired / known' : device.radioObserved ? 'Advertisement observed' : device.retainedOnly ? 'Retained history' : 'OS inventory';
  return {
    id: `ble-link:${device.key}`,
    sourceKey: null,
    targetKey: device.key,
    kind,
    start: { x: 50, y: 50 },
    end,
    sourceRadiusPx: 26,
    targetRadiusPx: device.rssiDbm === null ? 34 : 27,
    signal: device.rssiDbm === null ? null : Math.max(0, Math.min(100, (device.rssiDbm + 100) * 2)),
    label,
    detail: `${analyzeBleDevice(device).displayName} · ${device.rssiDbm === null ? 'no RSSI' : `${device.rssiDbm} dBm`}`
  };
}
