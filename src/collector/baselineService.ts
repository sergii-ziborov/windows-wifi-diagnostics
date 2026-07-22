import { mkdir, writeFile } from 'node:fs/promises';
import { hostname } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { createPlatformAdapter } from '../platform';
import { JsonlWriter } from './jsonl';
import { ensureNetworkMacEnrichment } from './macLookup';
import {
  BaselineRunStore,
  openBaselineRunStore,
  sqliteRunEventsUri,
  sqliteRunSummaryUri
} from './runStore';
import { ensureNetworkVulnerabilityIntel } from './vulnerabilityIntel';
import { ensureNetworkSecurityAssessment } from './wifiSecurity';
import type {
  BaselinePlatformAdapter,
  BaselineStatus,
  CollectOptions,
  CollectResult,
  CollectorEvent,
  CollectorStateEvent,
  EventContext
} from './types';

export async function getBaselineStatus(
  adapter: BaselinePlatformAdapter = createPlatformAdapter()
): Promise<BaselineStatus> {
  const context = createEventContext('status');
  const [sources, snapshots] = await Promise.all([
    adapter.getSourceStatus(),
    adapter.getWifiSnapshots(context)
  ]);

  return {
    platform: process.platform,
    host_id: context.hostId,
    ts_utc: new Date().toISOString(),
    sources,
    snapshots
  };
}

export async function collectBaseline(
  options: CollectOptions,
  adapter: BaselinePlatformAdapter = createPlatformAdapter()
): Promise<CollectResult> {
  const startedAt = new Date();
  const context = createEventContext(createRunId(startedAt));
  const sqliteMode = options.outDir === null;
  const store = sqliteMode ? await openBaselineRunStore(options.databaseFile) : null;
  const outDir = store ? dirname(store.databaseFile) : resolve(options.outDir ?? join('data', 'runs', context.runId));
  const eventsFile = store ? sqliteRunEventsUri(store.databaseFile, context.runId) : join(outDir, 'events.jsonl');
  const summaryFile = store ? sqliteRunSummaryUri(store.databaseFile, context.runId) : join(outDir, 'summary.json');
  const writer = store ? new SqliteCollectorWriter(store) : new JsonlWriter(eventsFile);
  const seenRecordIds = new Set<number>();
  let snapshotCount = 0;
  let networkScanCount = 0;
  let networkBssidCount = 0;
  let wlanEventCount = 0;
  let networkScanErrorReported = false;
  let wlanEventErrorReported = false;
  const abortSignal = options.abortSignal;

  if (!store) {
    await mkdir(outDir, { recursive: true });
  }

  const sources = await adapter.getSourceStatus();
  store?.createRun({ context, startedAt, sources });
  await writer.write(createStateEvent(context, 'started', 'Baseline collector started'));
  await writer.write(createStateEvent(context, 'source_status', 'Collector source status', sources));

  try {
    for (const event of await adapter.getRecentWlanEvents(context, options.maxEvents)) {
      if (event.record_id !== null) {
        seenRecordIds.add(event.record_id);
      }
    }
  } catch (error) {
    wlanEventErrorReported = true;
    await writer.write(
      createStateEvent(context, 'error', 'WLAN event source seed error', undefined, formatError(error))
    );
  }

  const stopAt = Date.now() + options.durationSeconds * 1000;

  while (Date.now() <= stopAt && !abortSignal?.aborted) {
    try {
      if (abortSignal?.aborted) {
        break;
      }

      const snapshots = await adapter.getWifiSnapshots(context);
      for (const snapshot of snapshots) {
        await writer.write(snapshot);
        snapshotCount += 1;
      }
    } catch (error) {
      await writer.write(
        createStateEvent(context, 'error', 'Wi-Fi snapshot source error', undefined, formatError(error))
      );
    }

    if (adapter.getNearbyWifiNetworks && !abortSignal?.aborted) {
      try {
        const networks = (await adapter.getNearbyWifiNetworks(context))
          .map(ensureNetworkMacEnrichment)
          .map(ensureNetworkSecurityAssessment)
          .map(ensureNetworkVulnerabilityIntel);
        networkScanCount += 1;
        networkScanErrorReported = false;

        for (const network of networks) {
          await writer.write(network);
          networkBssidCount += 1;
        }
      } catch (error) {
        if (!networkScanErrorReported) {
          networkScanErrorReported = true;
          await writer.write(
            createStateEvent(context, 'error', 'Nearby network scan error', undefined, formatError(error))
          );
        }
      }
    }

    if (abortSignal?.aborted) {
      break;
    }

    try {
      const wlanEvents = await adapter.getRecentWlanEvents(context, options.maxEvents);
      for (const event of wlanEvents.reverse()) {
        if (event.record_id !== null && seenRecordIds.has(event.record_id)) {
          continue;
        }

        if (event.record_id !== null) {
          seenRecordIds.add(event.record_id);
        }

        await writer.write(event);
        wlanEventCount += 1;
      }
    } catch (error) {
      if (!wlanEventErrorReported) {
        wlanEventErrorReported = true;
        await writer.write(
          createStateEvent(context, 'error', 'WLAN event source error', undefined, formatError(error))
        );
      }
    }

    // A sample scheduled exactly at the duration boundary belongs to the next
    // interval. Using `>` made fast CI hosts sleep to that boundary and collect
    // a second sample for a 1 s duration / 1 s interval run.
    if (Date.now() + options.intervalSeconds * 1000 >= stopAt) {
      break;
    }
    await sleep(options.intervalSeconds * 1000, abortSignal);
  }

  const cancelled = Boolean(abortSignal?.aborted);
  if (cancelled) {
    await writer.write(createStateEvent(context, 'cancelled', 'Baseline collector cancelled'));
  }
  await writer.write(createStateEvent(context, 'stopped', 'Baseline collector stopped'));

  const stoppedAt = new Date();
  const result: CollectResult = {
    run_id: context.runId,
    out_dir: outDir,
    events_file: eventsFile,
    summary_file: summaryFile,
    storage: store ? 'sqlite' : 'jsonl',
    database_file: store?.databaseFile ?? null,
    started_at_utc: startedAt.toISOString(),
    stopped_at_utc: stoppedAt.toISOString(),
    cancelled,
    event_count: writer.eventCount,
    snapshot_count: snapshotCount,
    network_scan_count: networkScanCount,
    network_bssid_count: networkBssidCount,
    wlan_event_count: wlanEventCount,
    sources
  };

  if (store) {
    store.finishRun(result);
    store.close();
  } else {
    await writeFile(summaryFile, `${JSON.stringify(result, null, 2)}\n`);
  }
  return result;
}

class SqliteCollectorWriter {
  eventCount = 0;

  constructor(private readonly store: BaselineRunStore) {}

  async write(event: CollectorEvent): Promise<void> {
    this.store.appendEvent(event);
    this.eventCount += 1;
  }
}

function createEventContext(runId: string): EventContext {
  return {
    runId,
    hostId: hostname()
  };
}

function createRunId(date: Date): string {
  const timestamp = date.toISOString().replace(/[-:.]/g, '').replace('Z', 'Z');
  const random = Math.random().toString(36).slice(2, 8);
  return `${timestamp}-${random}`;
}

function createStateEvent(
  context: EventContext,
  state: CollectorStateEvent['state'],
  message: string,
  sources?: CollectorStateEvent['sources'],
  error?: string
): CollectorStateEvent {
  return {
    schema: 'wifi.collector_state.v1',
    event_type: 'collector_state',
    ts_utc: new Date().toISOString(),
    source: 'system',
    run_id: context.runId,
    host_id: context.hostId,
    state,
    message,
    sources,
    error
  };
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  if (signal?.aborted) {
    return Promise.resolve();
  }

  return new Promise((resolveSleep) => {
    const timeout = setTimeout(resolveSleep, ms);
    signal?.addEventListener(
      'abort',
      () => {
        clearTimeout(timeout);
        resolveSleep();
      },
      { once: true }
    );
  });
}

function formatError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export type { CollectorEvent };
