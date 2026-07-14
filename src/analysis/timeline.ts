import type {
  ClientLifecycleAction,
  ClientTimelineEvent,
  DetectorAlert,
  EventContext,
  WindowsWifiEvent
} from '../collector/types';

const SUMMARY_FALLBACK = 'WLAN AutoConfig event';
const CYCLE_ACTIONS = new Set<ClientLifecycleAction>([
  'connected',
  'disconnected',
  'association_started',
  'association_succeeded',
  'association_failed',
  'security_started',
  'security_succeeded',
  'security_stopped'
]);
const CYCLE_GROUP_MS = 30_000;

export interface ReconnectLoopDetectorOptions {
  windowMinutes: number;
  minCycles: number;
}

export function sortWlanEventsChronologically(events: WindowsWifiEvent[]): WindowsWifiEvent[] {
  return [...events].sort((left, right) => {
    const leftTime = Date.parse(left.ts_utc);
    const rightTime = Date.parse(right.ts_utc);
    if (leftTime !== rightTime) {
      return leftTime - rightTime;
    }

    return (left.record_id ?? 0) - (right.record_id ?? 0);
  });
}

export function buildClientTimeline(
  events: WindowsWifiEvent[],
  context: EventContext
): ClientTimelineEvent[] {
  return sortWlanEventsChronologically(events).map((event) => {
    const action = classifyWlanEvent(event);

    return {
      schema: 'wifi.client_timeline.v1',
      event_type: 'client_lifecycle',
      ts_utc: event.ts_utc,
      source: 'detector',
      run_id: context.runId,
      host_id: context.hostId,
      action,
      client: event.local_mac,
      ssid: event.ssid,
      adapter: event.adapter,
      event_id: event.event_id,
      record_id: event.record_id,
      summary: firstLine(event.raw_message),
      evidence_event_ids: [evidenceId(event)]
    };
  });
}

export function classifyWlanEvent(event: Pick<WindowsWifiEvent, 'event_id' | 'raw_message'>): ClientLifecycleAction {
  switch (event.event_id) {
    case 8001:
      return 'connected';
    case 8002:
    case 8003:
      return 'disconnected';
    case 11000:
      return 'association_started';
    case 11001:
      return 'association_succeeded';
    case 11002:
      return 'association_failed';
    case 11004:
      return 'security_stopped';
    case 11005:
      return 'security_succeeded';
    case 11010:
      return 'security_started';
    default:
      return classifyByMessage(event.raw_message);
  }
}

export function detectReconnectLoops(
  timeline: ClientTimelineEvent[],
  context: EventContext,
  options: ReconnectLoopDetectorOptions
): DetectorAlert[] {
  const windowMs = options.windowMinutes * 60_000;
  const groups = groupCycles(timeline);
  const alerts: DetectorAlert[] = [];

  for (const [key, cycles] of groups) {
    for (let start = 0; start < cycles.length; start += 1) {
      const startTime = cycles[start].startMs;
      const windowCycles = cycles.filter(
        (cycle) => cycle.startMs >= startTime && cycle.startMs <= startTime + windowMs
      );

      if (windowCycles.length < options.minCycles) {
        continue;
      }

      const evidence = unique(windowCycles.flatMap((cycle) => cycle.evidence));
      const [client, ssid] = splitCycleKey(key);
      const cycleCount = windowCycles.length;
      const score = Math.min(100, 35 + cycleCount * 20);

      alerts.push({
        schema: 'wifi.alert.v1',
        event_type: 'alert',
        ts_utc: new Date(startTime).toISOString(),
        source: 'detector',
        run_id: context.runId,
        host_id: context.hostId,
        alert_type: 'reconnect_loop',
        severity: score >= 80 ? 'high' : score >= 60 ? 'medium' : 'low',
        score,
        client: client || null,
        ssid: ssid || null,
        summary: `${cycleCount} Windows Wi-Fi connect/security cycles within ${options.windowMinutes} minutes`,
        window_start_utc: new Date(startTime).toISOString(),
        window_end_utc: new Date(startTime + windowMs).toISOString(),
        cycle_count: cycleCount,
        evidence_event_ids: evidence,
        false_positive_notes: [
          'Could be normal roaming, AP restart, weak signal, user movement, or client power management',
          'This is a Windows symptom detector; it does not prove raw deauth/disassociation frames'
        ]
      });

      break;
    }
  }

  return alerts;
}

interface CycleGroup {
  startMs: number;
  evidence: string[];
}

function groupCycles(timeline: ClientTimelineEvent[]): Map<string, CycleGroup[]> {
  const groups = new Map<string, CycleGroup[]>();

  for (const event of timeline) {
    if (!CYCLE_ACTIONS.has(event.action)) {
      continue;
    }

    const key = `${event.client ?? ''}\u0000${event.ssid ?? ''}`;
    const eventTime = Date.parse(event.ts_utc);
    if (!Number.isFinite(eventTime)) {
      continue;
    }

    const cycles = groups.get(key) ?? [];
    const current = cycles[cycles.length - 1];

    if (current && eventTime - current.startMs <= CYCLE_GROUP_MS) {
      current.evidence.push(...event.evidence_event_ids);
    } else {
      cycles.push({ startMs: eventTime, evidence: [...event.evidence_event_ids] });
    }

    groups.set(key, cycles);
  }

  return groups;
}

function classifyByMessage(rawMessage: string): ClientLifecycleAction {
  const normalized = rawMessage.toLowerCase();

  if (normalized.includes('successfully connected')) {
    return 'connected';
  }
  if (normalized.includes('disconnected')) {
    return 'disconnected';
  }
  if (normalized.includes('association succeeded')) {
    return 'association_succeeded';
  }
  if (normalized.includes('association failed')) {
    return 'association_failed';
  }
  if (normalized.includes('association started')) {
    return 'association_started';
  }
  if (normalized.includes('security succeeded')) {
    return 'security_succeeded';
  }
  if (normalized.includes('security started')) {
    return 'security_started';
  }
  if (normalized.includes('security stopped')) {
    return 'security_stopped';
  }

  return 'other';
}

function firstLine(rawMessage: string): string {
  return rawMessage
    .split(/\r?\n/)
    .map((line) => line.trim())
    .find((line) => line.length > 0) ?? SUMMARY_FALLBACK;
}

function evidenceId(event: WindowsWifiEvent): string {
  if (event.record_id !== null) {
    return `wlan:${event.record_id}`;
  }

  return `wlan:${event.event_id}:${event.ts_utc}`;
}

function unique(values: string[]): string[] {
  return [...new Set(values)];
}

function splitCycleKey(key: string): [string, string] {
  const [client = '', ssid = ''] = key.split('\u0000');
  return [client, ssid];
}
