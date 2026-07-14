import { readdir, readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { listSqliteBaselineRuns } from './runStore';
import type {
  BaselineRunRecord,
  BaselineRunsResult,
  CollectResult,
  CollectorSourceStatus,
  RunHistoryOptions
} from './types';

const DEFAULT_RUNS_DIR = join('data', 'runs');

export async function listBaselineRuns(options: RunHistoryOptions): Promise<BaselineRunsResult> {
  const runsDir = resolve(options.runsDir ?? DEFAULT_RUNS_DIR);
  const maxRuns = Math.max(1, Math.trunc(options.last));
  const records = options.runsDir
    ? await readRunDirectories(runsDir)
    : await readDefaultRunHistory(maxRuns, options.databaseFile);
  const runs = records.sort(compareRunsNewestFirst).slice(0, maxRuns);

  return {
    ts_utc: new Date().toISOString(),
    runs_dir: runsDir,
    run_count: runs.length,
    runs
  };
}

async function readDefaultRunHistory(maxRuns: number, databaseFile?: string | null): Promise<BaselineRunRecord[]> {
  const [sqliteRuns, legacyRuns] = await Promise.all([
    listSqliteBaselineRuns({ last: maxRuns, databaseFile }),
    readRunDirectories(resolve(DEFAULT_RUNS_DIR))
  ]);

  const byRunId = new Map<string, BaselineRunRecord>();
  for (const record of legacyRuns) {
    byRunId.set(record.run_id, record);
  }
  for (const record of sqliteRuns) {
    byRunId.set(record.run_id, record);
  }

  return [...byRunId.values()];
}

async function readRunDirectories(runsDir: string): Promise<BaselineRunRecord[]> {
  let entries;
  try {
    entries = await readdir(runsDir, { withFileTypes: true });
  } catch (error) {
    if (isNotFound(error)) {
      return [];
    }
    throw error;
  }

  return Promise.all(
    entries
      .filter((entry) => entry.isDirectory())
      .map((entry) => readRunRecord(runsDir, entry.name))
  );
}

async function readRunRecord(runsDir: string, runId: string): Promise<BaselineRunRecord> {
  const outDir = join(runsDir, runId);
  const summaryFile = join(outDir, 'summary.json');

  try {
    const rawSummary = await readFile(summaryFile, 'utf8');
    const summary = JSON.parse(rawSummary) as Partial<CollectResult>;

    return normalizeSummary(summary, runId, outDir, summaryFile);
  } catch (error) {
    if (isNotFound(error)) {
      return incompleteRecord(runId, outDir, summaryFile, 'missing_summary', null);
    }

    return incompleteRecord(
      runId,
      outDir,
      summaryFile,
      'invalid_summary',
      error instanceof Error ? error.message : String(error)
    );
  }
}

function normalizeSummary(
  summary: Partial<CollectResult>,
  fallbackRunId: string,
  fallbackOutDir: string,
  fallbackSummaryFile: string
): BaselineRunRecord {
  const runId = stringOrNull(summary.run_id) ?? fallbackRunId;
  const outDir = stringOrNull(summary.out_dir) ?? fallbackOutDir;
  const startedAt = stringOrNull(summary.started_at_utc);
  const stoppedAt = stringOrNull(summary.stopped_at_utc);

  return {
    run_id: runId,
    out_dir: outDir,
    events_file: stringOrNull(summary.events_file),
    summary_file: stringOrNull(summary.summary_file) ?? fallbackSummaryFile,
    storage: summary.storage ?? 'jsonl',
    database_file: stringOrNull(summary.database_file),
    started_at_utc: startedAt,
    stopped_at_utc: stoppedAt,
    duration_seconds: durationSeconds(startedAt, stoppedAt),
    cancelled: booleanOrNull(summary.cancelled),
    event_count: numberOrNull(summary.event_count),
    snapshot_count: numberOrNull(summary.snapshot_count),
    network_scan_count: numberOrNull(summary.network_scan_count),
    network_bssid_count: numberOrNull(summary.network_bssid_count),
    wlan_event_count: numberOrNull(summary.wlan_event_count),
    sources: sourceStatuses(summary.sources),
    status: 'complete',
    error: null
  };
}

function incompleteRecord(
  runId: string,
  outDir: string,
  summaryFile: string,
  status: BaselineRunRecord['status'],
  error: string | null
): BaselineRunRecord {
  return {
    run_id: runId,
    out_dir: outDir,
    events_file: null,
    summary_file: summaryFile,
    storage: 'jsonl',
    database_file: null,
    started_at_utc: null,
    stopped_at_utc: null,
    duration_seconds: null,
    cancelled: null,
    event_count: null,
    snapshot_count: null,
    network_scan_count: null,
    network_bssid_count: null,
    wlan_event_count: null,
    sources: [],
    status,
    error
  };
}

function compareRunsNewestFirst(left: BaselineRunRecord, right: BaselineRunRecord): number {
  const leftTime = Date.parse(left.started_at_utc ?? '');
  const rightTime = Date.parse(right.started_at_utc ?? '');

  if (Number.isFinite(leftTime) && Number.isFinite(rightTime) && leftTime !== rightTime) {
    return rightTime - leftTime;
  }

  return right.run_id.localeCompare(left.run_id);
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

function sourceStatuses(value: unknown): CollectorSourceStatus[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value
    .map((source) => {
      if (!source || typeof source !== 'object') {
        return null;
      }

      const record = source as Partial<CollectorSourceStatus>;
      if (typeof record.name !== 'string' || typeof record.available !== 'boolean') {
        return null;
      }

      return {
        name: record.name,
        available: record.available,
        detail: typeof record.detail === 'string' ? record.detail : null
      } as CollectorSourceStatus;
    })
    .filter((source): source is CollectorSourceStatus => source !== null);
}

function stringOrNull(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

function numberOrNull(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function booleanOrNull(value: unknown): boolean | null {
  return typeof value === 'boolean' ? value : null;
}

function isNotFound(error: unknown): boolean {
  return error instanceof Error && 'code' in error && error.code === 'ENOENT';
}
