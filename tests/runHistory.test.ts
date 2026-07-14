import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { listBaselineRuns } from '../src/collector/runHistory';
import type { CollectResult } from '../src/collector/types';

let tempDirs: string[] = [];

afterEach(async () => {
  await Promise.all(tempDirs.map((dir) => rm(dir, { recursive: true, force: true })));
  tempDirs = [];
});

describe('listBaselineRuns', () => {
  it('lists saved baseline run summaries newest first', async () => {
    const runsDir = await createTempRunsDir();
    await writeSummary(runsDir, makeSummary('old-run', '2026-06-02T10:00:00.000Z', 10));
    await writeSummary(runsDir, makeSummary('new-run', '2026-06-02T11:00:00.000Z', 20));

    const result = await listBaselineRuns({ last: 10, runsDir });

    expect(result.runs_dir).toBe(runsDir);
    expect(result.run_count).toBe(2);
    expect(result.runs.map((run) => run.run_id)).toEqual(['new-run', 'old-run']);
    expect(result.runs[0]).toMatchObject({
      status: 'complete',
      duration_seconds: 60,
      cancelled: false,
      event_count: 20,
      snapshot_count: 4,
      network_scan_count: 1,
      network_bssid_count: 3,
      wlan_event_count: 2
    });
  });

  it('reports missing and invalid summaries without throwing', async () => {
    const runsDir = await createTempRunsDir();
    await mkdir(join(runsDir, 'missing-summary'), { recursive: true });
    await mkdir(join(runsDir, 'invalid-summary'), { recursive: true });
    await writeFile(join(runsDir, 'invalid-summary', 'summary.json'), '{bad json', 'utf8');

    const result = await listBaselineRuns({ last: 10, runsDir });
    const byId = new Map(result.runs.map((run) => [run.run_id, run]));

    expect(byId.get('missing-summary')).toMatchObject({
      status: 'missing_summary',
      error: null
    });
    expect(byId.get('invalid-summary')).toMatchObject({
      status: 'invalid_summary'
    });
    expect(byId.get('invalid-summary')?.error).toContain('JSON');
  });

  it('returns an empty list when the runs directory does not exist', async () => {
    const runsDir = join(await createTempRunsDir(), 'not-created');

    const result = await listBaselineRuns({ last: 10, runsDir });

    expect(result.run_count).toBe(0);
    expect(result.runs).toEqual([]);
  });
});

async function createTempRunsDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'monitor-runs-'));
  tempDirs.push(dir);
  return dir;
}

async function writeSummary(runsDir: string, summary: CollectResult): Promise<void> {
  const runDir = join(runsDir, summary.run_id);
  await mkdir(runDir, { recursive: true });
  await writeFile(join(runDir, 'summary.json'), `${JSON.stringify(summary, null, 2)}\n`, 'utf8');
}

function makeSummary(runId: string, startedAt: string, eventCount: number): CollectResult {
  const outDir = join('data', 'runs', runId);

  return {
    run_id: runId,
    out_dir: outDir,
    events_file: join(outDir, 'events.jsonl'),
    summary_file: join(outDir, 'summary.json'),
    started_at_utc: startedAt,
    stopped_at_utc: new Date(Date.parse(startedAt) + 60_000).toISOString(),
    cancelled: false,
    event_count: eventCount,
    snapshot_count: 4,
    network_scan_count: 1,
    network_bssid_count: 3,
    wlan_event_count: 2,
    sources: [
      {
        name: 'windows_wlan_autoconfig_operational',
        available: true,
        detail: 'record_count=10'
      }
    ]
  };
}
