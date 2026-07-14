import { readFileSync } from 'node:fs';
import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { getBaselineStatus } from './baselineService';
import { getBaselineEvents, getBaselineTimeline } from './historyService';
import { getBaselineNetworks } from './networkService';
import { listBaselineRuns } from './runHistory';
import type {
  BaselineDiagnosticsBundleResult,
  BaselineDiagnosticsBundleRecord,
  BaselineDiagnosticsBundlesResult,
  BaselineEventsResult,
  BaselineNetworksResult,
  BaselineRunsResult,
  BaselineStatus,
  BaselineTimelineResult,
  DiagnosticsHistoryOptions,
  DiagnosticsOptions
} from './types';

const DEFAULT_DIAGNOSTICS_DIR = join('data', 'diagnostics');

interface DiagnosticsDependencies {
  getStatus?: () => Promise<BaselineStatus>;
  getNetworks?: () => Promise<BaselineNetworksResult>;
  listRuns?: (options: { last: number; runsDir: string | null; databaseFile?: string | null }) => Promise<BaselineRunsResult>;
  getEvents?: (options: { last: number }) => Promise<BaselineEventsResult>;
  getTimeline?: (options: {
    last: number;
    windowMinutes: number;
    minCycles: number;
  }) => Promise<BaselineTimelineResult>;
}

export async function createBaselineDiagnosticsBundle(
  options: DiagnosticsOptions,
  dependencies: DiagnosticsDependencies = {}
): Promise<BaselineDiagnosticsBundleResult> {
  const createdAt = new Date();
  const bundleId = createBundleId(createdAt);
  const outDir = resolve(options.outDir ?? join(DEFAULT_DIAGNOSTICS_DIR, bundleId));
  const files = {
    manifest: join(outDir, 'manifest.json'),
    readme: join(outDir, 'README.txt'),
    status: join(outDir, 'status.json'),
    networks: join(outDir, 'networks.json'),
    runs: join(outDir, 'runs.json'),
    events: join(outDir, 'events.json'),
    timeline: join(outDir, 'timeline.json')
  };

  await mkdir(outDir, { recursive: true });

  const [status, networks, runs, events, timeline] = await Promise.all([
    (dependencies.getStatus ?? getBaselineStatus)(),
    (dependencies.getNetworks ?? getBaselineNetworks)(),
    (dependencies.listRuns ?? listBaselineRuns)({
      last: options.lastRuns,
      runsDir: options.runsDir,
      databaseFile: options.databaseFile
    }),
    (dependencies.getEvents ?? getBaselineEvents)({
      last: options.lastEvents
    }),
    (dependencies.getTimeline ?? getBaselineTimeline)({
      last: options.lastEvents,
      windowMinutes: options.windowMinutes,
      minCycles: options.minCycles
    })
  ]);

  const result: BaselineDiagnosticsBundleResult = {
    schema: 'wifi.baseline_diagnostics.v1',
    bundle_id: bundleId,
    out_dir: outDir,
    created_at_utc: createdAt.toISOString(),
    inputs: {
      runs_dir: options.runsDir,
      last_runs: options.lastRuns,
      last_events: options.lastEvents,
      window_minutes: options.windowMinutes,
      min_cycles: options.minCycles
    },
    runtime: {
      platform: process.platform,
      arch: process.arch,
      node_version: process.version,
      app_version: readPackageVersion()
    },
    files,
    counts: {
      snapshots: status.snapshots.length,
      networks: networks.network_count,
      bssids: networks.bssid_count,
      runs: runs.run_count,
      events: events.events.length,
      timeline: timeline.timeline_count,
      alerts: timeline.alert_count
    }
  };

  await Promise.all([
    writeJson(files.status, status),
    writeJson(files.networks, networks),
    writeJson(files.runs, runs),
    writeJson(files.events, events),
    writeJson(files.timeline, timeline),
    writeFile(files.readme, diagnosticsReadme(result), 'utf8')
  ]);
  await writeJson(files.manifest, result);

  return result;
}

export async function listBaselineDiagnosticsBundles(
  options: DiagnosticsHistoryOptions
): Promise<BaselineDiagnosticsBundlesResult> {
  const diagnosticsDir = resolve(options.diagnosticsDir ?? DEFAULT_DIAGNOSTICS_DIR);
  const maxBundles = Math.max(1, Math.trunc(options.last));
  const records = await readBundleDirectories(diagnosticsDir);
  const bundles = records.sort(compareBundlesNewestFirst).slice(0, maxBundles);

  return {
    ts_utc: new Date().toISOString(),
    diagnostics_dir: diagnosticsDir,
    bundle_count: bundles.length,
    bundles
  };
}

async function readBundleDirectories(diagnosticsDir: string): Promise<BaselineDiagnosticsBundleRecord[]> {
  let entries;
  try {
    entries = await readdir(diagnosticsDir, { withFileTypes: true });
  } catch (error) {
    if (isNotFound(error)) {
      return [];
    }
    throw error;
  }

  return Promise.all(
    entries
      .filter((entry) => entry.isDirectory())
      .map((entry) => readBundleRecord(diagnosticsDir, entry.name))
  );
}

async function readBundleRecord(
  diagnosticsDir: string,
  bundleId: string
): Promise<BaselineDiagnosticsBundleRecord> {
  const outDir = join(diagnosticsDir, bundleId);
  const manifestFile = join(outDir, 'manifest.json');
  const readmeFile = join(outDir, 'README.txt');

  try {
    const rawManifest = await readFile(manifestFile, 'utf8');
    const manifest = JSON.parse(rawManifest) as Partial<BaselineDiagnosticsBundleResult>;

    return normalizeBundleManifest(manifest, bundleId, outDir, manifestFile, readmeFile);
  } catch (error) {
    if (isNotFound(error)) {
      return incompleteBundleRecord(bundleId, outDir, manifestFile, readmeFile, 'missing_manifest', null);
    }

    return incompleteBundleRecord(
      bundleId,
      outDir,
      manifestFile,
      readmeFile,
      'invalid_manifest',
      error instanceof Error ? error.message : String(error)
    );
  }
}

function normalizeBundleManifest(
  manifest: Partial<BaselineDiagnosticsBundleResult>,
  fallbackBundleId: string,
  fallbackOutDir: string,
  fallbackManifestFile: string,
  fallbackReadmeFile: string
): BaselineDiagnosticsBundleRecord {
  return {
    bundle_id: stringOrNull(manifest.bundle_id) ?? fallbackBundleId,
    out_dir: stringOrNull(manifest.out_dir) ?? fallbackOutDir,
    manifest_file: stringOrNull(manifest.files?.manifest) ?? fallbackManifestFile,
    readme_file: stringOrNull(manifest.files?.readme) ?? fallbackReadmeFile,
    created_at_utc: stringOrNull(manifest.created_at_utc),
    counts: countsOrNull(manifest.counts),
    status: 'complete',
    error: null
  };
}

function incompleteBundleRecord(
  bundleId: string,
  outDir: string,
  manifestFile: string,
  readmeFile: string,
  status: BaselineDiagnosticsBundleRecord['status'],
  error: string | null
): BaselineDiagnosticsBundleRecord {
  return {
    bundle_id: bundleId,
    out_dir: outDir,
    manifest_file: manifestFile,
    readme_file: readmeFile,
    created_at_utc: null,
    counts: null,
    status,
    error
  };
}

function compareBundlesNewestFirst(
  left: BaselineDiagnosticsBundleRecord,
  right: BaselineDiagnosticsBundleRecord
): number {
  const leftTime = Date.parse(left.created_at_utc ?? '');
  const rightTime = Date.parse(right.created_at_utc ?? '');

  if (Number.isFinite(leftTime) && Number.isFinite(rightTime) && leftTime !== rightTime) {
    return rightTime - leftTime;
  }

  if (Number.isFinite(leftTime) && !Number.isFinite(rightTime)) {
    return -1;
  }

  if (!Number.isFinite(leftTime) && Number.isFinite(rightTime)) {
    return 1;
  }

  return right.bundle_id.localeCompare(left.bundle_id);
}

function createBundleId(date: Date): string {
  return `${date.toISOString().replace(/[-:.]/g, '').replace('Z', 'Z')}-diagnostics`;
}

async function writeJson(file: string, value: unknown): Promise<void> {
  await writeFile(file, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function diagnosticsReadme(result: BaselineDiagnosticsBundleResult): string {
  return [
    'Windows baseline diagnostics bundle',
    '',
    `Bundle: ${result.bundle_id}`,
    `Created UTC: ${result.created_at_utc}`,
    '',
    'Contents:',
    '- manifest.json: bundle metadata, requested limits, runtime, and counts',
    '- status.json: current Windows Wi-Fi interface snapshot',
    '- networks.json: Windows-managed nearby SSID/BSSID scan result',
    '- runs.json: saved baseline run summaries',
    '- events.json: recent WLAN AutoConfig events',
    '- timeline.json: derived client lifecycle timeline and reconnect-loop alerts',
    '',
    'Phase 1 limitations:',
    '- This bundle is read-only Windows telemetry.',
    '- It does not enable monitor mode.',
    '- It does not switch drivers or change PnP device ownership.',
    '- It does not capture raw 802.11 management frames.',
    '- Treat findings as symptoms/evidence, not proof of deauth/disassociation packets.'
  ].join('\n');
}

function countsOrNull(value: unknown): BaselineDiagnosticsBundleResult['counts'] | null {
  if (!value || typeof value !== 'object') {
    return null;
  }

  const record = value as Partial<BaselineDiagnosticsBundleResult['counts']>;
  if (
    typeof record.snapshots !== 'number' ||
    typeof record.networks !== 'number' ||
    typeof record.bssids !== 'number' ||
    typeof record.runs !== 'number' ||
    typeof record.events !== 'number' ||
    typeof record.timeline !== 'number' ||
    typeof record.alerts !== 'number'
  ) {
    return null;
  }

  return {
    snapshots: record.snapshots,
    networks: record.networks,
    bssids: record.bssids,
    runs: record.runs,
    events: record.events,
    timeline: record.timeline,
    alerts: record.alerts
  };
}

function readPackageVersion(): string | null {
  try {
    const packageJson = JSON.parse(readFileSync(resolve('package.json'), 'utf8')) as { version?: unknown };
    return typeof packageJson.version === 'string' ? packageJson.version : null;
  } catch {
    return null;
  }
}

function stringOrNull(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

function isNotFound(error: unknown): boolean {
  return error instanceof Error && 'code' in error && error.code === 'ENOENT';
}
