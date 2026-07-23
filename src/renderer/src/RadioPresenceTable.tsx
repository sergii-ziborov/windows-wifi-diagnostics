import { useMemo, useState } from 'react';
import type { RadioPresenceClass, RadioPresencePattern } from './radioHistoryPatterns';

export interface RadioPresenceRow {
  key: string;
  label: string;
  detail: string;
  presence: RadioPresencePattern;
}

const FILTERS: Array<{ value: 'all' | RadioPresenceClass; label: string }> = [
  { value: 'all', label: 'All' },
  { value: 'new', label: 'New' },
  { value: 'stable', label: 'Stable' },
  { value: 'weekday', label: 'Weekday' },
  { value: 'recurring', label: 'Recurring' },
  { value: 'intermittent', label: 'Intermittent' },
  { value: 'dormant', label: 'Dormant' }
];

export function RadioPresenceTable({
  title,
  detail,
  rows
}: {
  title: string;
  detail: string;
  rows: RadioPresenceRow[];
}) {
  const [filter, setFilter] = useState<'all' | RadioPresenceClass>('all');
  const [query, setQuery] = useState('');
  const filteredRows = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    return rows.filter((row) =>
      (filter === 'all' || row.presence.presenceClass === filter)
      && (!normalized || `${row.label} ${row.detail} ${row.presence.summary}`.toLowerCase().includes(normalized))
    );
  }, [filter, query, rows]);

  return (
    <article className="panel radio-presence-panel">
      <div className="radio-presence-heading">
        <div>
          <p className="bluetooth-eyebrow">Sampled presence, never inferred uptime</p>
          <h2>{title}</h2>
          <span>{detail}</span>
        </div>
        <label>
          <span>Filter devices</span>
          <input
            type="search"
            value={query}
            placeholder="Name, vendor, pattern"
            onChange={(event) => setQuery(event.target.value)}
          />
        </label>
      </div>
      <div className="radio-presence-filters" aria-label={`${title} filters`}>
        {FILTERS.map((item) => {
          const count = item.value === 'all'
            ? rows.length
            : rows.filter((row) => row.presence.presenceClass === item.value).length;
          return (
            <button
              type="button"
              className={filter === item.value ? 'active' : ''}
              onClick={() => setFilter(item.value)}
              key={item.value}
            >
              {item.label} <b>{count}</b>
            </button>
          );
        })}
      </div>
      <div className="radio-presence-table-wrap">
        <table className="radio-presence-table">
          <thead>
            <tr>
              <th>Device / AP</th>
              <th>Pattern</th>
              <th>1 day</th>
              <th>7 days</th>
              <th>30 days</th>
              <th>First / last observed</th>
            </tr>
          </thead>
          <tbody>
            {filteredRows.slice(0, 60).map((row) => (
              <tr key={row.key}>
                <td><strong>{row.label}</strong><small>{row.detail || 'No additional identity evidence'}</small></td>
                <td>
                  <span className={`radio-pattern-badge radio-pattern-${row.presence.presenceClass}`}>
                    {row.presence.presenceClass}
                  </span>
                  <small>{row.presence.summary}</small>
                </td>
                {row.presence.windows.map((window) => (
                  <td key={window.days}>
                    <strong className={`radio-window-${window.state}`}>
                      {window.state === 'insufficient' ? 'Need data' : `${window.coveragePercent}%`}
                    </strong>
                    <small>{window.seenSessions}/{window.eligibleSessions} scans · {window.distinctDays}d</small>
                  </td>
                ))}
                <td>
                  <strong>{formatDate(row.presence.firstSeenMs)}</strong>
                  <small>{formatDate(row.presence.lastSeenMs)}</small>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!filteredRows.length ? <p className="muted radio-presence-empty">No evidence matches these filters.</p> : null}
      </div>
    </article>
  );
}

function formatDate(value: number): string {
  return new Date(value).toLocaleString([], {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit'
  });
}
