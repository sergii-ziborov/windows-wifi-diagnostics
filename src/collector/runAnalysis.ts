import { readFile } from 'node:fs/promises';
import {
  buildClientTimeline,
  detectReconnectLoops,
  sortWlanEventsChronologically
} from '../analysis/timeline';
import { buildEvidenceReport } from './evidenceReport';
import { ensureNetworkMacEnrichment, summarizeMacIntelligence } from './macLookup';
import { listBaselineRuns } from './runHistory';
import { isSqliteRunUri, readSqliteRunEventsFromUri } from './runStore';
import { ensureNetworkVulnerabilityIntel } from './vulnerabilityIntel';
import { ensureNetworkSecurityAssessment } from './wifiSecurity';
import type {
  BaselineRunAnalysisResult,
  BaselineRunNetworkSummary,
  BaselineRunObservation,
  BaselineRunObservationType,
  BaselineRunRecord,
  BaselineRunSnapshotSummary,
  CollectorEvent,
  CollectorSourceStatus,
  CollectorStateEvent,
  EventContext,
  NumericSummary,
  RunAnalysisOptions,
  WindowsWifiEvent,
  WindowsWifiNetwork,
  WindowsWifiSnapshot
} from './types';

const RUN_SEARCH_LIMIT = 10_000;
const RSSI_DROP_THRESHOLD_DB = 10;
const WEAK_RSSI_THRESHOLD_DBM = -75;
const WEAK_SIGNAL_THRESHOLD_PERCENT = 35;
const NEARBY_SIGNAL_DROP_THRESHOLD_PERCENT = 30;
const NEARBY_STRONG_SIGNAL_THRESHOLD_PERCENT = 75;
const NEARBY_HIGH_UTILIZATION_THRESHOLD_PERCENT = 75;
const MAX_NETWORK_OBSERVATIONS_PER_TYPE = 8;

export async function analyzeBaselineRun(
  options: RunAnalysisOptions
): Promise<BaselineRunAnalysisResult> {
  const run = await findRun(options);
  if (run.status !== 'complete' || !run.events_file) {
    throw new Error(`Run ${options.runId} is not analyzable: ${run.status}`);
  }

  const parsed = await readRunEvents(run);
  const snapshots = parsed.events.filter(isWindowsWifiSnapshot);
  const networks = parsed.events
    .filter(isWindowsWifiNetwork)
    .map(ensureNetworkMacEnrichment)
    .map(ensureNetworkSecurityAssessment)
    .map(ensureNetworkVulnerabilityIntel);
  const wlanEvents = sortWlanEventsChronologically(parsed.events.filter(isWindowsWifiEvent));
  const collectorStates = parsed.events.filter(isCollectorStateEvent);
  const hostId = firstHostId(parsed.events) ?? 'unknown';
  const context: EventContext = {
    runId: run.run_id,
    hostId
  };
  const timeline = buildClientTimeline(wlanEvents, context);
  const alerts = detectReconnectLoops(timeline, context, {
    windowMinutes: options.windowMinutes,
    minCycles: options.minCycles
  });
  const observations = sortObservationsChronologically([
    ...detectSnapshotObservations(snapshots, context),
    ...detectNetworkObservations(networks, context)
  ]);
  const snapshotSummary = summarizeSnapshots(snapshots);
  const networkSummary = summarizeNetworks(networks);

  return {
    run_id: run.run_id,
    host_id: hostId,
    ts_utc: new Date().toISOString(),
    out_dir: run.out_dir,
    events_file: run.events_file,
    summary_file: run.summary_file,
    started_at_utc: run.started_at_utc,
    stopped_at_utc: run.stopped_at_utc,
    duration_seconds: run.duration_seconds,
    parsed_event_count: parsed.events.length,
    invalid_line_count: parsed.invalidLineCount,
    event_type_counts: eventTypeCounts(parsed.events),
    collector_errors: collectorStates.filter((event) => event.state === 'error'),
    sources: latestSourceStatus(collectorStates) ?? run.sources,
    snapshots: snapshotSummary,
    networks: networkSummary,
    report: buildEvidenceReport({
      durationSeconds: run.duration_seconds,
      parsedEventCount: parsed.events.length,
      invalidLineCount: parsed.invalidLineCount,
      collectorErrorCount: collectorStates.filter((event) => event.state === 'error').length,
      sources: latestSourceStatus(collectorStates) ?? run.sources,
      snapshots: snapshotSummary,
      networks: networkSummary,
      observations,
      alerts,
      wlanEventCount: wlanEvents.length,
      timelineCount: timeline.length
    }),
    observation_count: observations.length,
    observations,
    wlan_event_count: wlanEvents.length,
    timeline_count: timeline.length,
    alert_count: alerts.length,
    timeline,
    alerts
  };
}

async function findRun(options: RunAnalysisOptions): Promise<BaselineRunRecord> {
  const runs = await listBaselineRuns({
    last: RUN_SEARCH_LIMIT,
    runsDir: options.runsDir,
    databaseFile: options.databaseFile
  });
  const run = runs.runs.find((record) => record.run_id === options.runId);

  if (!run) {
    throw new Error(`Baseline run not found: ${options.runId}`);
  }

  return run;
}

async function readRunEvents(run: BaselineRunRecord): Promise<{ events: CollectorEvent[]; invalidLineCount: number }> {
  if (!run.events_file) {
    return { events: [], invalidLineCount: 0 };
  }

  if (isSqliteRunUri(run.events_file)) {
    return {
      events: await readSqliteRunEventsFromUri(run.events_file),
      invalidLineCount: 0
    };
  }

  return parseJsonlEvents(await readFile(run.events_file, 'utf8'));
}

function parseJsonlEvents(content: string): { events: CollectorEvent[]; invalidLineCount: number } {
  const events: CollectorEvent[] = [];
  let invalidLineCount = 0;

  for (const line of content.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) {
      continue;
    }

    try {
      const parsed = JSON.parse(trimmed) as unknown;
      if (isCollectorEvent(parsed)) {
        events.push(parsed);
      } else {
        invalidLineCount += 1;
      }
    } catch {
      invalidLineCount += 1;
    }
  }

  return { events, invalidLineCount };
}

function isCollectorEvent(value: unknown): value is CollectorEvent {
  if (!isObject(value) || typeof value.event_type !== 'string') {
    return false;
  }

  return (
    value.event_type === 'windows_wifi_snapshot' ||
    value.event_type === 'windows_wifi_event' ||
    value.event_type === 'windows_wifi_network' ||
    value.event_type === 'collector_state'
  );
}

function isWindowsWifiSnapshot(value: CollectorEvent): value is WindowsWifiSnapshot {
  return value.event_type === 'windows_wifi_snapshot';
}

function isWindowsWifiEvent(value: CollectorEvent): value is WindowsWifiEvent {
  return value.event_type === 'windows_wifi_event';
}

function isWindowsWifiNetwork(value: CollectorEvent): value is WindowsWifiNetwork {
  return value.event_type === 'windows_wifi_network';
}

function isCollectorStateEvent(value: CollectorEvent): value is CollectorStateEvent {
  return value.event_type === 'collector_state';
}

function eventTypeCounts(events: CollectorEvent[]): Record<string, number> {
  const counts: Record<string, number> = {};

  for (const event of events) {
    counts[event.event_type] = (counts[event.event_type] ?? 0) + 1;
  }

  return counts;
}

function summarizeSnapshots(snapshots: WindowsWifiSnapshot[]): BaselineRunSnapshotSummary {
  return {
    count: snapshots.length,
    first_ts_utc: firstTimestamp(snapshots),
    last_ts_utc: lastTimestamp(snapshots),
    adapters: uniqueStrings(snapshots.map((snapshot) => snapshot.adapter)),
    interfaces: uniqueStrings(snapshots.map((snapshot) => snapshot.interface_name)),
    states: countNullableStrings(snapshots.map((snapshot) => snapshot.state)),
    ssids: uniqueStrings(snapshots.map((snapshot) => snapshot.ssid)),
    bssids: uniqueStrings(snapshots.map((snapshot) => snapshot.bssid)),
    bands: uniqueStrings(snapshots.map((snapshot) => snapshot.band)),
    channels: uniqueNumbers(snapshots.map((snapshot) => snapshot.channel)),
    rssi_dbm: numericSummary(snapshots.map((snapshot) => snapshot.rssi_dbm)),
    signal_percent: numericSummary(snapshots.map((snapshot) => snapshot.signal_percent))
  };
}

function summarizeNetworks(networks: WindowsWifiNetwork[]): BaselineRunNetworkSummary {
  const ssids = uniqueStrings(networks.map((network) => network.ssid));

  return {
    count: networks.length,
    ssid_count: ssids.length,
    ssids,
    bssids: uniqueStrings(networks.map((network) => network.bssid)),
    bands: uniqueStrings(networks.map((network) => network.band)),
    channels: uniqueNumbers(networks.map((network) => network.channel)),
    authentications: uniqueStrings(networks.map((network) => network.authentication)),
    encryptions: uniqueStrings(networks.map((network) => network.encryption)),
    mac_summary: summarizeMacIntelligence(networks)
  };
}

function detectSnapshotObservations(
  snapshots: WindowsWifiSnapshot[],
  context: EventContext
): BaselineRunObservation[] {
  const orderedSnapshots = [...snapshots].sort((left, right) => {
    const leftTime = Date.parse(left.ts_utc);
    const rightTime = Date.parse(right.ts_utc);
    return leftTime - rightTime;
  });
  const observations: BaselineRunObservation[] = [];
  let weakSignalReported = false;

  for (let index = 0; index < orderedSnapshots.length; index += 1) {
    const current = orderedSnapshots[index];
    const previous = orderedSnapshots[index - 1];

    if (previous) {
      if (changed(previous.state, current.state)) {
        observations.push(
          createSnapshotObservation(
            context,
            current,
            'state_change',
            current.state === 'connected' ? 'medium' : 'high',
            current.state === 'connected' ? 60 : 85,
            `Wi-Fi state changed from ${previous.state} to ${current.state}`,
            previous.state,
            current.state,
            [
              'Could be normal user action, adapter sleep, AP restart, roaming, or Windows network management',
              'This is based on Windows snapshots; it does not prove raw deauth/disassociation frames'
            ]
          )
        );
      }

      if (changed(previous.bssid, current.bssid)) {
        observations.push(
          createSnapshotObservation(
            context,
            current,
            'bssid_change',
            'medium',
            65,
            `BSSID changed from ${previous.bssid} to ${current.bssid}`,
            previous.bssid,
            current.bssid,
            [
              'Could be normal roaming, mesh steering, AP maintenance, or stronger AP selection',
              'This is a Windows association symptom, not raw management-frame evidence'
            ]
          )
        );
      }

      if (changed(previous.channel, current.channel)) {
        observations.push(
          createSnapshotObservation(
            context,
            current,
            'channel_change',
            'medium',
            60,
            `Wi-Fi channel changed from ${previous.channel} to ${current.channel}`,
            previous.channel,
            current.channel,
            [
              'Could be normal roaming, DFS behavior, AP channel change, or band steering',
              'This is derived from periodic snapshots and may miss intermediate transitions'
            ]
          )
        );
      }

      const drop = rssiDrop(previous.rssi_dbm, current.rssi_dbm);
      if (drop >= RSSI_DROP_THRESHOLD_DB) {
        observations.push(
          createSnapshotObservation(
            context,
            current,
            'rssi_drop',
            drop >= 18 ? 'high' : 'medium',
            Math.min(95, 45 + drop * 2),
            `RSSI dropped by ${drop} dB`,
            previous.rssi_dbm,
            current.rssi_dbm,
            [
              'Could be movement, obstruction, power saving, AP load, antenna orientation, or normal RF fading',
              'RSSI drops alone are weak evidence without corroborating WLAN events'
            ]
          )
        );
      }
    }

    if (!weakSignalReported && isWeakSignal(current)) {
      observations.push(
        createSnapshotObservation(
          context,
          current,
          'weak_signal',
          current.rssi_dbm !== null && current.rssi_dbm <= WEAK_RSSI_THRESHOLD_DBM ? 'medium' : 'low',
          50,
          `Weak signal observed at ${current.rssi_dbm ?? 'unknown'} dBm / ${current.signal_percent ?? 'unknown'}%`,
          null,
          current.rssi_dbm ?? current.signal_percent,
          [
            'Could be distance, walls, interference, client power management, or normal RF conditions',
            'Weak signal can cause reconnect symptoms without an active attack'
          ]
        )
      );
      weakSignalReported = true;
    }
  }

  return observations;
}

function detectNetworkObservations(
  networks: WindowsWifiNetwork[],
  context: EventContext
): BaselineRunObservation[] {
  const scans = groupNetworkScans(networks);
  const observations: BaselineRunObservation[] = [];
  const typeCounts = new Map<BaselineRunObservationType, number>();
  const securityReports = new Set<string>();
  const utilizationReports = new Set<string>();

  const pushLimited = (observation: BaselineRunObservation) => {
    const count = typeCounts.get(observation.observation_type) ?? 0;
    if (count >= MAX_NETWORK_OBSERVATIONS_PER_TYPE) {
      return;
    }

    observations.push(observation);
    typeCounts.set(observation.observation_type, count + 1);
  };

  for (const scan of scans) {
    for (const observation of detectMixedSecurityProfiles(scan, context, securityReports)) {
      pushLimited(observation);
    }

    for (const network of scan.networks) {
      const utilization = channelUtilizationPercent(network);
      const reportKey = network.bssid ?? `${network.ssid ?? 'unknown'}:${network.channel ?? 'unknown'}`;
      if (
        utilization !== null &&
        utilization >= NEARBY_HIGH_UTILIZATION_THRESHOLD_PERCENT &&
        !utilizationReports.has(reportKey)
      ) {
        utilizationReports.add(reportKey);
        pushLimited(
          createNetworkObservation(
            context,
            network,
            'nearby_high_utilization',
            utilization >= 90 ? 'high' : 'medium',
            utilization >= 90 ? 85 : 70,
            `Nearby BSSID ${network.bssid ?? 'unknown'} reported high channel utilization (${utilization}%)`,
            null,
            utilization,
            [
              'Could be ordinary venue load, nearby clients, AP airtime management, or Windows scan variability',
              'This is a passive Windows scan symptom, not raw RF packet evidence'
            ]
          )
        );
      }
    }
  }

  for (let index = 1; index < scans.length; index += 1) {
    const previousScan = scans[index - 1];
    const currentScan = scans[index];

    for (const [bssid, current] of currentScan.byBssid) {
      const previous = previousScan.byBssid.get(bssid);
      if (!previous) {
        if (strongSignal(current.signal_percent)) {
          pushLimited(
            createNetworkObservation(
              context,
              current,
              'nearby_bssid_added',
              'low',
              40,
              `Strong nearby BSSID appeared for SSID ${current.ssid ?? 'unknown'}: ${bssid}`,
              null,
              bssid,
              [
                'Could be normal scan coverage, AP beacon timing, roaming environment changes, or movement',
                'A newly visible BSSID alone is not attack evidence'
              ]
            )
          );
        }
        continue;
      }

      if (changed(networkSecurity(previous), networkSecurity(current))) {
        pushLimited(
          createNetworkObservation(
            context,
            current,
            'nearby_security_changed',
            isOpenSecurity(current) ? 'high' : 'medium',
            isOpenSecurity(current) ? 85 : 70,
            `Nearby BSSID ${bssid} security changed from ${networkSecurity(previous)} to ${networkSecurity(current)}`,
            networkSecurity(previous),
            networkSecurity(current),
            [
              'Could be AP reconfiguration, mixed WPA transition mode, parser variance, or a different virtual AP',
              'This is SSID/BSSID metadata from Windows scans, not raw management-frame proof'
            ],
            previous
          )
        );
      }

      if (changed(previous.channel, current.channel)) {
        pushLimited(
          createNetworkObservation(
            context,
            current,
            'nearby_channel_changed',
            'medium',
            60,
            `Nearby BSSID ${bssid} channel changed from ${previous.channel} to ${current.channel}`,
            previous.channel,
            current.channel,
            [
              'Could be DFS, AP channel planning, roaming infrastructure, or scan/parser timing',
              'Channel changes should be correlated with client reconnect symptoms before escalating'
            ],
            previous
          )
        );
      }

      const signalDrop = percentDrop(previous.signal_percent, current.signal_percent);
      if (signalDrop >= NEARBY_SIGNAL_DROP_THRESHOLD_PERCENT) {
        pushLimited(
          createNetworkObservation(
            context,
            current,
            'nearby_signal_drop',
            signalDrop >= 45 ? 'high' : 'medium',
            Math.min(90, 45 + signalDrop),
            `Nearby BSSID ${bssid} signal dropped by ${signalDrop}%`,
            previous.signal_percent,
            current.signal_percent,
            [
              'Could be movement, obstruction, AP load, power changes, antenna orientation, or scan variance',
              'Nearby AP signal changes are weak evidence without WLAN events or repeated patterning'
            ],
            previous
          )
        );
      }
    }

    for (const [bssid, previous] of previousScan.byBssid) {
      if (!currentScan.byBssid.has(bssid) && strongSignal(previous.signal_percent)) {
        pushLimited(
          createNetworkObservation(
            context,
            previous,
            'nearby_bssid_removed',
            'low',
            40,
            `Strong nearby BSSID disappeared for SSID ${previous.ssid ?? 'unknown'}: ${bssid}`,
            bssid,
            null,
            [
              'Could be normal scan coverage, AP beacon timing, roaming environment changes, or movement',
              'A missing BSSID in one Windows scan does not prove interference or deauth'
            ]
          )
        );
      }
    }
  }

  return sortObservationsChronologically(observations);
}

function detectMixedSecurityProfiles(
  scan: NetworkScan,
  context: EventContext,
  reports: Set<string>
): BaselineRunObservation[] {
  const bySsid = new Map<string, WindowsWifiNetwork[]>();

  for (const network of scan.networks) {
    if (!network.ssid) {
      continue;
    }

    bySsid.set(network.ssid, [...(bySsid.get(network.ssid) ?? []), network]);
  }

  const observations: BaselineRunObservation[] = [];
  for (const [ssid, ssidNetworks] of bySsid) {
    const securityProfiles = uniqueStrings(ssidNetworks.map(networkSecurity));
    if (securityProfiles.length <= 1) {
      continue;
    }

    const reportKey = `${ssid}:${securityProfiles.join('|')}`;
    if (reports.has(reportKey)) {
      continue;
    }
    reports.add(reportKey);

    const representative = strongestNetwork(ssidNetworks);
    observations.push(
      createNetworkObservation(
        context,
        representative,
        'nearby_security_changed',
        securityProfiles.some((profile) => profile.toLowerCase().includes('open')) ? 'high' : 'medium',
        securityProfiles.some((profile) => profile.toLowerCase().includes('open')) ? 85 : 70,
        `SSID ${ssid} appeared with multiple security profiles: ${securityProfiles.join(', ')}`,
        null,
        securityProfiles.join(', '),
        [
          'Could be legitimate mixed WPA transition mode, multiple AP profiles, venue configuration, or scan timing',
          'Treat as a passive environment anomaly until correlated with client disconnects or repeated patterning'
        ]
      )
    );
  }

  return observations;
}

function createSnapshotObservation(
  context: EventContext,
  snapshot: WindowsWifiSnapshot,
  observationType: BaselineRunObservationType,
  severity: BaselineRunObservation['severity'],
  score: number,
  summary: string,
  previousValue: string | number | null,
  currentValue: string | number | null,
  falsePositiveNotes: string[]
): BaselineRunObservation {
  return {
    schema: 'wifi.run_observation.v1',
    event_type: 'run_observation',
    ts_utc: snapshot.ts_utc,
    source: 'detector',
    run_id: context.runId,
    host_id: context.hostId,
    observation_type: observationType,
    severity,
    score,
    summary,
    adapter: snapshot.adapter,
    interface_name: snapshot.interface_name,
    ssid: snapshot.ssid,
    bssid: snapshot.bssid,
    channel: snapshot.channel,
    rssi_dbm: snapshot.rssi_dbm,
    signal_percent: snapshot.signal_percent,
    previous_value: previousValue,
    current_value: currentValue,
    evidence_event_ids: [`snapshot:${snapshot.ts_utc}`],
    false_positive_notes: falsePositiveNotes
  };
}

interface NetworkScan {
  ts_utc: string;
  networks: WindowsWifiNetwork[];
  byBssid: Map<string, WindowsWifiNetwork>;
}

function groupNetworkScans(networks: WindowsWifiNetwork[]): NetworkScan[] {
  const byTimestamp = new Map<string, WindowsWifiNetwork[]>();

  for (const network of networks) {
    byTimestamp.set(network.ts_utc, [...(byTimestamp.get(network.ts_utc) ?? []), network]);
  }

  return [...byTimestamp.entries()]
    .map(([tsUtc, scanNetworks]) => ({
      ts_utc: tsUtc,
      networks: scanNetworks,
      byBssid: strongestByBssid(scanNetworks)
    }))
    .sort((left, right) => Date.parse(left.ts_utc) - Date.parse(right.ts_utc));
}

function strongestByBssid(networks: WindowsWifiNetwork[]): Map<string, WindowsWifiNetwork> {
  const byBssid = new Map<string, WindowsWifiNetwork>();

  for (const network of networks) {
    if (!network.bssid) {
      continue;
    }

    const current = byBssid.get(network.bssid);
    if (!current || (network.signal_percent ?? -1) > (current.signal_percent ?? -1)) {
      byBssid.set(network.bssid, network);
    }
  }

  return byBssid;
}

function createNetworkObservation(
  context: EventContext,
  network: WindowsWifiNetwork,
  observationType: BaselineRunObservationType,
  severity: BaselineRunObservation['severity'],
  score: number,
  summary: string,
  previousValue: string | number | null,
  currentValue: string | number | null,
  falsePositiveNotes: string[],
  previousNetwork?: WindowsWifiNetwork
): BaselineRunObservation {
  const evidenceEventIds = previousNetwork
    ? [networkEvidenceId(previousNetwork), networkEvidenceId(network)]
    : [networkEvidenceId(network)];

  return {
    schema: 'wifi.run_observation.v1',
    event_type: 'run_observation',
    ts_utc: network.ts_utc,
    source: 'detector',
    run_id: context.runId,
    host_id: context.hostId,
    observation_type: observationType,
    severity,
    score,
    summary,
    adapter: null,
    interface_name: network.interface_name,
    ssid: network.ssid,
    bssid: network.bssid,
    channel: network.channel,
    rssi_dbm: null,
    signal_percent: network.signal_percent,
    previous_value: previousValue,
    current_value: currentValue,
    evidence_event_ids: evidenceEventIds,
    false_positive_notes: falsePositiveNotes
  };
}

function sortObservationsChronologically(observations: BaselineRunObservation[]): BaselineRunObservation[] {
  return [...observations].sort((left, right) => {
    const leftTime = Date.parse(left.ts_utc);
    const rightTime = Date.parse(right.ts_utc);
    return leftTime - rightTime;
  });
}

function latestSourceStatus(states: CollectorStateEvent[]): CollectorSourceStatus[] | null {
  for (const state of [...states].reverse()) {
    if (state.state === 'source_status' && state.sources) {
      return state.sources;
    }
  }

  return null;
}

function changed<T>(previous: T | null, current: T | null): boolean {
  return previous !== null && current !== null && previous !== current;
}

function rssiDrop(previous: number | null, current: number | null): number {
  if (previous === null || current === null) {
    return 0;
  }

  return Math.max(0, previous - current);
}

function percentDrop(previous: number | null, current: number | null): number {
  if (previous === null || current === null) {
    return 0;
  }

  return Math.max(0, previous - current);
}

function strongSignal(signalPercent: number | null): boolean {
  return signalPercent !== null && signalPercent >= NEARBY_STRONG_SIGNAL_THRESHOLD_PERCENT;
}

function networkSecurity(network: WindowsWifiNetwork): string {
  return [network.authentication, network.encryption].filter(Boolean).join(' / ') || 'unknown';
}

function isOpenSecurity(network: WindowsWifiNetwork): boolean {
  return networkSecurity(network).toLowerCase().includes('open');
}

function channelUtilizationPercent(network: WindowsWifiNetwork): number | null {
  const rawValue = network.raw['Channel Utilization'];
  if (!rawValue) {
    return null;
  }

  const parentheticalPercent = rawValue.match(/\(\s*(\d+(?:\.\d+)?)\s*%\s*\)/);
  const parsed = Number(parentheticalPercent?.[1] ?? rawValue.match(/\d+(?:\.\d+)?/)?.[0]);
  if (!Number.isFinite(parsed)) {
    return null;
  }

  return parsed;
}

function strongestNetwork(networks: WindowsWifiNetwork[]): WindowsWifiNetwork {
  return [...networks].sort((left, right) => (right.signal_percent ?? -1) - (left.signal_percent ?? -1))[0];
}

function networkEvidenceId(network: WindowsWifiNetwork): string {
  return `network:${network.ts_utc}:${network.bssid ?? network.ssid ?? 'unknown'}`;
}

function isWeakSignal(snapshot: WindowsWifiSnapshot): boolean {
  return (
    (snapshot.rssi_dbm !== null && snapshot.rssi_dbm <= WEAK_RSSI_THRESHOLD_DBM) ||
    (snapshot.signal_percent !== null && snapshot.signal_percent <= WEAK_SIGNAL_THRESHOLD_PERCENT)
  );
}

function firstHostId(events: CollectorEvent[]): string | null {
  for (const event of events) {
    if (event.host_id) {
      return event.host_id;
    }
  }

  return null;
}

function firstTimestamp(events: CollectorEvent[]): string | null {
  return sortedTimestamps(events)[0] ?? null;
}

function lastTimestamp(events: CollectorEvent[]): string | null {
  const timestamps = sortedTimestamps(events);
  return timestamps[timestamps.length - 1] ?? null;
}

function sortedTimestamps(events: CollectorEvent[]): string[] {
  return events
    .map((event) => event.ts_utc)
    .filter((value) => Number.isFinite(Date.parse(value)))
    .sort((left, right) => Date.parse(left) - Date.parse(right));
}

function uniqueStrings(values: Array<string | null>): string[] {
  return [...new Set(values.filter((value): value is string => Boolean(value)))].sort();
}

function uniqueNumbers(values: Array<number | null>): number[] {
  return [...new Set(values.filter((value): value is number => typeof value === 'number'))].sort(
    (left, right) => left - right
  );
}

function countNullableStrings(values: Array<string | null>): Record<string, number> {
  const counts: Record<string, number> = {};

  for (const value of values) {
    const key = value || 'unknown';
    counts[key] = (counts[key] ?? 0) + 1;
  }

  return counts;
}

function numericSummary(values: Array<number | null>): NumericSummary | null {
  const numbers = values.filter((value): value is number => typeof value === 'number');
  if (numbers.length === 0) {
    return null;
  }

  const sum = numbers.reduce((total, value) => total + value, 0);

  return {
    min: Math.min(...numbers),
    max: Math.max(...numbers),
    avg: roundOne(sum / numbers.length),
    last: numbers[numbers.length - 1]
  };
}

function roundOne(value: number): number {
  return Math.round(value * 10) / 10;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}
