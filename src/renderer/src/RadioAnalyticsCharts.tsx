import { useMemo, useState, type CSSProperties, type PointerEvent as ReactPointerEvent } from 'react';

export interface TimelinePoint {
  key: string;
  timestampMs: number;
  values: Array<number | null>;
}

export interface TimelineSeries {
  label: string;
  color: string;
}

export function EvidenceTimeline({
  points,
  series,
  minimum,
  maximum,
  suffix = '',
  ariaLabel
}: {
  points: TimelinePoint[];
  series: TimelineSeries[];
  minimum: number;
  maximum: number;
  suffix?: string;
  ariaLabel: string;
}) {
  const [selectedIndex, setSelectedIndex] = useState(Math.max(0, points.length - 1));
  const width = 1000;
  const height = 246;
  const plot = { left: 52, right: 18, top: 46, bottom: 30 };
  const plotWidth = width - plot.left - plot.right;
  const plotHeight = height - plot.top - plot.bottom;
  const range = Math.max(1, maximum - minimum);
  const selected = points[Math.min(selectedIndex, Math.max(0, points.length - 1))] ?? null;
  const x = (index: number) => plot.left + (index / Math.max(1, points.length - 1)) * plotWidth;
  const y = (value: number) => plot.top + (1 - (value - minimum) / range) * plotHeight;
  const paths = useMemo(
    () => series.map((_, seriesIndex) => lineSegments(points, seriesIndex, x, y)),
    [points, series]
  );

  if (!points.length) return <div className="radio-chart-empty">No retained evidence in this window.</div>;
  const selectFromPointer = (event: ReactPointerEvent<SVGSVGElement>) => {
    const rect = event.currentTarget.getBoundingClientRect();
    const ratio = Math.max(0, Math.min(1, (event.clientX - rect.left) / Math.max(1, rect.width)));
    setSelectedIndex(Math.round(ratio * Math.max(0, points.length - 1)));
  };
  return (
    <div className="radio-timeline">
      <div className="radio-chart-selection">
        <div><span>Selected evidence</span><strong>{formatDateTime(selected.timestampMs)}</strong></div>
        {series.map((item, index) => (
          <div key={item.label}>
            <span style={{ color: item.color }}>{item.label}</span>
            <strong>{formatValue(selected.values[index], suffix)}</strong>
          </div>
        ))}
      </div>
      <svg
        className="radio-timeline-chart"
        viewBox={`0 0 ${width} ${height}`}
        preserveAspectRatio="none"
        role="img"
        aria-label={ariaLabel}
        onPointerDown={selectFromPointer}
        onPointerMove={(event) => {
          if (event.buttons === 1) selectFromPointer(event);
        }}
      >
        {[0, 0.25, 0.5, 0.75, 1].map((ratio) => {
          const value = maximum - range * ratio;
          const lineY = plot.top + plotHeight * ratio;
          return <g key={ratio}>
            <line className="radio-chart-grid" x1={plot.left} x2={width - plot.right} y1={lineY} y2={lineY} />
            <text className="radio-chart-axis" x={4} y={lineY + 4}>{Math.round(value)}</text>
          </g>;
        })}
        {paths.map((segments, seriesIndex) => segments.map((path, segmentIndex) => (
          <path
            d={path}
            fill="none"
            key={`${series[seriesIndex].label}-${segmentIndex}`}
            stroke={series[seriesIndex].color}
            strokeWidth={seriesIndex === 0 ? 2.6 : 1.8}
          />
        )))}
        {points.map((point, pointIndex) => series.map((item, seriesIndex) => {
          const value = point.values[seriesIndex];
          return value === null ? null : (
            <circle
              cx={x(pointIndex)}
              cy={y(value)}
              fill={item.color}
              key={`${point.key}-${item.label}`}
              opacity={pointIndex === selectedIndex ? 1 : 0.46}
              r={pointIndex === selectedIndex ? 4.2 : 2.2}
            />
          );
        }))}
        <line
          className="radio-chart-cursor"
          x1={x(selectedIndex)}
          x2={x(selectedIndex)}
          y1={plot.top}
          y2={plot.top + plotHeight}
        />
        <text className="radio-chart-axis" x={plot.left} y={height - 7}>{formatShortTime(points[0].timestampMs)}</text>
        <text className="radio-chart-axis" textAnchor="end" x={width - plot.right} y={height - 7}>
          {formatShortTime(points.at(-1)!.timestampMs)}
        </text>
      </svg>
      <div className="radio-chart-legend">
        {series.map((item) => <span key={item.label}><i style={{ background: item.color }} />{item.label}</span>)}
      </div>
    </div>
  );
}

export interface PulseBucket {
  key: string;
  label: string;
  timestampMs: number;
  primary: number;
  secondary: number;
  tone?: 'normal' | 'warning' | 'high';
}

export function EvidencePulseStrip({
  buckets,
  primaryLabel,
  secondaryLabel
}: {
  buckets: PulseBucket[];
  primaryLabel: string;
  secondaryLabel: string;
}) {
  const [selectedKey, setSelectedKey] = useState<string | null>(buckets.at(-1)?.key ?? null);
  const maximum = Math.max(1, ...buckets.flatMap((bucket) => [bucket.primary, bucket.secondary]));
  const selected = buckets.find((bucket) => bucket.key === selectedKey) ?? buckets.at(-1) ?? null;
  if (!selected) return <div className="radio-chart-empty">At least two retained scans are required.</div>;
  return (
    <div className="radio-pulse-watch">
      <div className="radio-pulse-strip">
        {buckets.map((bucket, index) => {
          const style = {
            '--pulse-primary': `${Math.max(4, (bucket.primary / maximum) * 100)}%`,
            '--pulse-secondary': `${Math.max(3, (bucket.secondary / maximum) * 100)}%`
          } as CSSProperties;
          return (
            <button
              type="button"
              className={`radio-pulse-cell ${bucket.tone ?? 'normal'} ${selected.key === bucket.key ? 'selected' : ''}`}
              style={style}
              key={bucket.key}
              onClick={() => setSelectedKey(bucket.key)}
              title={`${formatDateTime(bucket.timestampMs)} · ${primaryLabel} ${bucket.primary} · ${secondaryLabel} ${bucket.secondary}`}
            >
              <i /><b />
              {index % 6 === 0 || index === buckets.length - 1 ? <span>{formatClock(bucket.timestampMs)}</span> : null}
            </button>
          );
        })}
      </div>
      <div className="radio-pulse-detail">
        <span>Selected transition</span>
        <strong>{formatDateTime(selected.timestampMs)}</strong>
        <dl>
          <div><dt>{primaryLabel}</dt><dd>{selected.primary}</dd></div>
          <div><dt>{secondaryLabel}</dt><dd>{selected.secondary}</dd></div>
        </dl>
      </div>
    </div>
  );
}

export interface MatrixRow {
  key: string;
  label: string;
  meta?: string;
  values: Array<number | null>;
}

export function EvidenceMatrix({
  columns,
  rows,
  suffix = ''
}: {
  columns: Array<{ key: string; label: string; timestampMs: number }>;
  rows: MatrixRow[];
  suffix?: string;
}) {
  const [selection, setSelection] = useState<{ row: number; column: number } | null>(null);
  const maximum = Math.max(1, ...rows.flatMap((row) => row.values.filter((value): value is number => value !== null)));
  const gridStyle = {
    gridTemplateColumns: `minmax(138px, 184px) repeat(${columns.length}, minmax(9px, 1fr))`
  };
  const selectedRow = selection ? rows[selection.row] : null;
  const selectedColumn = selection ? columns[selection.column] : null;
  const selectedValue = selection && selectedRow ? selectedRow.values[selection.column] : null;
  return (
    <div className="radio-matrix-wrap">
      <div className="radio-matrix">
        <div className="radio-matrix-row radio-matrix-axis" style={gridStyle}>
          <b>Evidence lane</b>
          {columns.map((column) => <i key={column.key} title={formatDateTime(column.timestampMs)} />)}
        </div>
        {rows.map((row, rowIndex) => (
          <div className="radio-matrix-row" style={gridStyle} key={row.key}>
            <button type="button" className="radio-matrix-label" onClick={() => setSelection({ row: rowIndex, column: columns.length - 1 })}>
              <strong>{row.label}</strong><span>{row.meta ?? 'observed evidence'}</span>
            </button>
            {columns.map((column, columnIndex) => {
              const value = row.values[columnIndex];
              const intensity = value === null ? 0 : Math.max(0.08, Math.abs(value) / maximum);
              return (
                <button
                  type="button"
                  className={`radio-matrix-cell ${value === null ? 'empty' : ''} ${selection?.row === rowIndex && selection.column === columnIndex ? 'selected' : ''}`}
                  style={{ '--matrix-alpha': intensity } as CSSProperties}
                  key={column.key}
                  onClick={() => setSelection({ row: rowIndex, column: columnIndex })}
                  title={`${row.label} · ${formatDateTime(column.timestampMs)} · ${formatValue(value, suffix)}`}
                />
              );
            })}
          </div>
        ))}
      </div>
      <div className="radio-matrix-selection">
        {selectedRow && selectedColumn
          ? <><span>{selectedRow.label}</span><strong>{formatValue(selectedValue, suffix)}</strong><small>{formatDateTime(selectedColumn.timestampMs)}</small></>
          : <><span>Evidence matrix</span><strong>Select a cell</strong><small>Each column is a real retained scan.</small></>}
      </div>
    </div>
  );
}

function lineSegments(
  points: TimelinePoint[],
  seriesIndex: number,
  x: (index: number) => number,
  y: (value: number) => number
): string[] {
  const segments: string[] = [];
  let current = '';
  points.forEach((point, index) => {
    const value = point.values[seriesIndex];
    if (value === null) {
      if (current) segments.push(current);
      current = '';
      return;
    }
    current += `${current ? ' L' : 'M'} ${x(index).toFixed(1)} ${y(value).toFixed(1)}`;
  });
  if (current) segments.push(current);
  return segments;
}

function formatValue(value: number | null, suffix: string): string {
  return value === null ? 'not observed' : `${Math.round(value * 10) / 10}${suffix}`;
}

function formatDateTime(value: number): string {
  return new Date(value).toLocaleString([], { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' });
}

function formatShortTime(value: number): string {
  return new Date(value).toLocaleString([], { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' });
}

function formatClock(value: number): string {
  return new Date(value).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}
