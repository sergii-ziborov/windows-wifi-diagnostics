import { hostname } from 'node:os';
import {
  buildClientTimeline,
  detectReconnectLoops,
  sortWlanEventsChronologically
} from '../analysis/timeline';
import { createPlatformAdapter } from '../platform';
import type {
  BaselineEventsResult,
  BaselinePlatformAdapter,
  BaselineTimelineResult,
  EventContext,
  HistoryOptions,
  TimelineOptions
} from './types';

export async function getBaselineEvents(
  options: HistoryOptions,
  adapter: BaselinePlatformAdapter = createPlatformAdapter()
): Promise<BaselineEventsResult> {
  const context = createEventContext('events');
  const getSourceStatus = adapter.getWlanEventSourceStatus ?? adapter.getSourceStatus;
  const [sources, events] = await Promise.all([
    getSourceStatus.call(adapter),
    adapter.getRecentWlanEvents(context, options.last)
  ]);

  return {
    run_id: context.runId,
    host_id: context.hostId,
    ts_utc: new Date().toISOString(),
    sources,
    order: 'chronological',
    events: sortWlanEventsChronologically(events)
  };
}

export async function getBaselineTimeline(
  options: TimelineOptions,
  adapter: BaselinePlatformAdapter = createPlatformAdapter()
): Promise<BaselineTimelineResult> {
  const context = createEventContext('timeline');
  const getSourceStatus = adapter.getWlanEventSourceStatus ?? adapter.getSourceStatus;
  const [sources, events] = await Promise.all([
    getSourceStatus.call(adapter),
    adapter.getRecentWlanEvents(context, options.last)
  ]);
  const orderedEvents = sortWlanEventsChronologically(events);
  const timeline = buildClientTimeline(orderedEvents, context);
  const alerts = detectReconnectLoops(timeline, context, {
    windowMinutes: options.windowMinutes,
    minCycles: options.minCycles
  });

  return {
    run_id: context.runId,
    host_id: context.hostId,
    ts_utc: new Date().toISOString(),
    sources,
    event_count: orderedEvents.length,
    timeline_count: timeline.length,
    alert_count: alerts.length,
    timeline,
    alerts
  };
}

function createEventContext(runId: string): EventContext {
  return {
    runId,
    hostId: hostname()
  };
}
