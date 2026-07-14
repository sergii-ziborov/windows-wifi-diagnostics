import { mkdir } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import type {
  BaselineRunRecord,
  CollectResult,
  CollectorEvent,
  CollectorSourceStatus,
  EventContext
} from './types';

export const DEFAULT_RUN_DATABASE_FILE = join('data', 'monitor.sqlite');
const SQLITE_URI_PREFIX = 'sqlite:';

interface SqliteRunRow {
  run_id: string;
  host_id: string;
  started_at_utc: string;
  stopped_at_utc: string | null;
  cancelled: number;
  event_count: number;
  snapshot_count: number;
  network_scan_count: number;
  network_bssid_count: number;
  wlan_event_count: number;
  sources_json: string;
  updated_at_utc: string;
}

interface SqliteEventRow {
  payload_json: string;
}

interface CreateRunInput {
  context: EventContext;
  startedAt: Date;
  sources: CollectorSourceStatus[];
}

export class BaselineRunStore {
  readonly databaseFile: string;
  private readonly db: DatabaseSync;

  constructor(databaseFile: string) {
    this.databaseFile = databaseFile;
    this.db = new DatabaseSync(databaseFile);
    this.db.exec(`
      PRAGMA busy_timeout = 5000;
      PRAGMA journal_mode = WAL;
      PRAGMA synchronous = NORMAL;
      PRAGMA foreign_keys = ON;

      CREATE TABLE IF NOT EXISTS baseline_runs (
        run_id TEXT PRIMARY KEY,
        host_id TEXT NOT NULL,
        started_at_utc TEXT NOT NULL,
        stopped_at_utc TEXT,
        cancelled INTEGER NOT NULL DEFAULT 0,
        event_count INTEGER NOT NULL DEFAULT 0,
        snapshot_count INTEGER NOT NULL DEFAULT 0,
        network_scan_count INTEGER NOT NULL DEFAULT 0,
        network_bssid_count INTEGER NOT NULL DEFAULT 0,
        wlan_event_count INTEGER NOT NULL DEFAULT 0,
        sources_json TEXT NOT NULL DEFAULT '[]',
        status TEXT NOT NULL DEFAULT 'running',
        error TEXT,
        created_at_utc TEXT NOT NULL,
        updated_at_utc TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS collector_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id TEXT NOT NULL REFERENCES baseline_runs(run_id) ON DELETE CASCADE,
        ts_utc TEXT,
        event_type TEXT NOT NULL,
        source TEXT,
        payload_json TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_collector_events_run_id_id
        ON collector_events(run_id, id);

      CREATE INDEX IF NOT EXISTS idx_collector_events_type_time
        ON collector_events(event_type, ts_utc);

      CREATE INDEX IF NOT EXISTS idx_baseline_runs_started_at
        ON baseline_runs(started_at_utc);
    `);
  }

  createRun(input: CreateRunInput): void {
    const now = new Date().toISOString();
    this.db.prepare('DELETE FROM collector_events WHERE run_id = ?').run(input.context.runId);
    this.db.prepare(`
      INSERT INTO baseline_runs (
        run_id,
        host_id,
        started_at_utc,
        sources_json,
        status,
        created_at_utc,
        updated_at_utc
      )
      VALUES (?, ?, ?, ?, 'running', ?, ?)
      ON CONFLICT(run_id) DO UPDATE SET
        host_id = excluded.host_id,
        started_at_utc = excluded.started_at_utc,
        sources_json = excluded.sources_json,
        status = 'running',
        updated_at_utc = excluded.updated_at_utc
    `).run(
      input.context.runId,
      input.context.hostId,
      input.startedAt.toISOString(),
      JSON.stringify(input.sources),
      now,
      now
    );
  }

  appendEvent(event: CollectorEvent): void {
    this.db.prepare(`
      INSERT INTO collector_events (run_id, ts_utc, event_type, source, payload_json)
      VALUES (?, ?, ?, ?, ?)
    `).run(event.run_id, event.ts_utc, event.event_type, event.source, JSON.stringify(event));
  }

  finishRun(result: CollectResult): void {
    this.db.prepare(`
      UPDATE baseline_runs
      SET
        stopped_at_utc = ?,
        cancelled = ?,
        event_count = ?,
        snapshot_count = ?,
        network_scan_count = ?,
        network_bssid_count = ?,
        wlan_event_count = ?,
        sources_json = ?,
        status = 'complete',
        error = NULL,
        updated_at_utc = ?
      WHERE run_id = ?
    `).run(
      result.stopped_at_utc,
      result.cancelled ? 1 : 0,
      result.event_count,
      result.snapshot_count,
      result.network_scan_count,
      result.network_bssid_count,
      result.wlan_event_count,
      JSON.stringify(result.sources),
      new Date().toISOString(),
      result.run_id
    );
  }

  listRuns(last: number): BaselineRunRecord[] {
    const rows = this.db.prepare(`
      SELECT
        run_id,
        host_id,
        started_at_utc,
        stopped_at_utc,
        cancelled,
        event_count,
        snapshot_count,
        network_scan_count,
        network_bssid_count,
        wlan_event_count,
        sources_json,
        updated_at_utc
      FROM baseline_runs
      WHERE status = 'complete'
      ORDER BY datetime(started_at_utc) DESC, run_id DESC
      LIMIT ?
    `).all(Math.max(1, Math.trunc(last))) as unknown as SqliteRunRow[];

    return rows.map((row) => normalizeSqliteRun(row, this.databaseFile));
  }

  readEvents(runId: string): CollectorEvent[] {
    const rows = this.db.prepare(`
      SELECT payload_json
      FROM collector_events
      WHERE run_id = ?
      ORDER BY id ASC
    `).all(runId) as unknown as SqliteEventRow[];

    return rows
      .map((row) => parseCollectorEvent(row.payload_json))
      .filter((event): event is CollectorEvent => event !== null);
  }

  close(): void {
    this.db.close();
  }
}

export async function openBaselineRunStore(databaseFile?: string | null): Promise<BaselineRunStore> {
  const resolvedFile = resolve(databaseFile ?? DEFAULT_RUN_DATABASE_FILE);
  await mkdir(dirname(resolvedFile), { recursive: true });
  return new BaselineRunStore(resolvedFile);
}

export async function listSqliteBaselineRuns(options: {
  last: number;
  databaseFile?: string | null;
}): Promise<BaselineRunRecord[]> {
  const store = await openBaselineRunStore(options.databaseFile);
  try {
    return store.listRuns(options.last);
  } finally {
    store.close();
  }
}

export async function readSqliteRunEvents(runId: string, databaseFile?: string | null): Promise<CollectorEvent[]> {
  const store = await openBaselineRunStore(databaseFile);
  try {
    return store.readEvents(runId);
  } finally {
    store.close();
  }
}

export async function readSqliteRunEventsFromUri(uri: string): Promise<CollectorEvent[]> {
  const parsed = parseSqliteRunUri(uri);
  if (!parsed) {
    throw new Error(`Invalid SQLite run URI: ${uri}`);
  }

  return readSqliteRunEvents(parsed.runId, parsed.databaseFile);
}

export function sqliteRunEventsUri(databaseFile: string, runId: string): string {
  return `${SQLITE_URI_PREFIX}${databaseFile}#${runId}`;
}

export function sqliteRunSummaryUri(databaseFile: string, runId: string): string {
  return `${SQLITE_URI_PREFIX}${databaseFile}#${runId}/summary`;
}

export function isSqliteRunUri(value: string | null): boolean {
  return typeof value === 'string' && value.startsWith(SQLITE_URI_PREFIX);
}

function parseSqliteRunUri(uri: string): { databaseFile: string; runId: string } | null {
  if (!uri.startsWith(SQLITE_URI_PREFIX)) {
    return null;
  }

  const payload = uri.slice(SQLITE_URI_PREFIX.length);
  const hashIndex = payload.indexOf('#');
  if (hashIndex <= 0 || hashIndex === payload.length - 1) {
    return null;
  }

  const databaseFile = payload.slice(0, hashIndex);
  const runId = payload.slice(hashIndex + 1).split('/')[0];
  if (!databaseFile || !runId) {
    return null;
  }

  return { databaseFile, runId };
}

function normalizeSqliteRun(row: SqliteRunRow, databaseFile: string): BaselineRunRecord {
  return {
    run_id: row.run_id,
    out_dir: dirname(databaseFile),
    events_file: sqliteRunEventsUri(databaseFile, row.run_id),
    summary_file: sqliteRunSummaryUri(databaseFile, row.run_id),
    storage: 'sqlite',
    database_file: databaseFile,
    started_at_utc: row.started_at_utc,
    stopped_at_utc: row.stopped_at_utc,
    duration_seconds: durationSeconds(row.started_at_utc, row.stopped_at_utc),
    cancelled: Boolean(row.cancelled),
    event_count: numberOrNull(row.event_count),
    snapshot_count: numberOrNull(row.snapshot_count),
    network_scan_count: numberOrNull(row.network_scan_count),
    network_bssid_count: numberOrNull(row.network_bssid_count),
    wlan_event_count: numberOrNull(row.wlan_event_count),
    sources: parseSources(row.sources_json),
    status: 'complete',
    error: null
  };
}

function parseSources(value: string): CollectorSourceStatus[] {
  try {
    const parsed = JSON.parse(value) as unknown;
    if (!Array.isArray(parsed)) {
      return [];
    }

    return parsed.filter(isCollectorSourceStatus);
  } catch {
    return [];
  }
}

function isCollectorSourceStatus(value: unknown): value is CollectorSourceStatus {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as CollectorSourceStatus).name === 'string' &&
    typeof (value as CollectorSourceStatus).available === 'boolean'
  );
}

function parseCollectorEvent(value: string): CollectorEvent | null {
  try {
    const parsed = JSON.parse(value) as unknown;
    if (
      typeof parsed === 'object' &&
      parsed !== null &&
      typeof (parsed as CollectorEvent).event_type === 'string'
    ) {
      return parsed as CollectorEvent;
    }
  } catch {
    return null;
  }

  return null;
}

function durationSeconds(startedAt: string | null, stoppedAt: string | null): number | null {
  if (!startedAt || !stoppedAt) {
    return null;
  }

  const startedMs = Date.parse(startedAt);
  const stoppedMs = Date.parse(stoppedAt);
  if (!Number.isFinite(startedMs) || !Number.isFinite(stoppedMs) || stoppedMs < startedMs) {
    return null;
  }

  return Math.round((stoppedMs - startedMs) / 1000);
}

function numberOrNull(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}
