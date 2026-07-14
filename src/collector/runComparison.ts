import { analyzeBaselineRun } from './runAnalysis';
import type {
  BaselineRunAnalysisResult,
  BaselineRunComparisonMetric,
  BaselineRunComparisonResult,
  NumberSetDelta,
  RunComparisonOptions,
  StringSetDelta
} from './types';

export async function compareBaselineRuns(
  options: RunComparisonOptions
): Promise<BaselineRunComparisonResult> {
  const [baseline, candidate] = await Promise.all([
    analyzeBaselineRun({
      runId: options.baselineRunId,
      runsDir: options.runsDir,
      windowMinutes: options.windowMinutes,
      minCycles: options.minCycles,
      databaseFile: options.databaseFile
    }),
    analyzeBaselineRun({
      runId: options.candidateRunId,
      runsDir: options.runsDir,
      windowMinutes: options.windowMinutes,
      minCycles: options.minCycles,
      databaseFile: options.databaseFile
    })
  ]);
  const scoreDelta = candidate.report.score - baseline.report.score;

  return {
    ts_utc: new Date().toISOString(),
    baseline_run_id: baseline.run_id,
    candidate_run_id: candidate.run_id,
    baseline_report: baseline.report,
    candidate_report: candidate.report,
    score_delta: scoreDelta,
    verdict_changed: baseline.report.verdict !== candidate.report.verdict,
    confidence_changed: baseline.report.confidence !== candidate.report.confidence,
    metrics: {
      parsed_events: metric(baseline.parsed_event_count, candidate.parsed_event_count),
      snapshots: metric(baseline.snapshots.count, candidate.snapshots.count),
      wlan_events: metric(baseline.wlan_event_count, candidate.wlan_event_count),
      timeline: metric(baseline.timeline_count, candidate.timeline_count),
      alerts: metric(baseline.alert_count, candidate.alert_count),
      observations: metric(baseline.observation_count, candidate.observation_count),
      nearby_records: metric(baseline.networks.count, candidate.networks.count),
      nearby_ssids: metric(baseline.networks.ssid_count, candidate.networks.ssid_count),
      nearby_bssids: metric(baseline.networks.bssids.length, candidate.networks.bssids.length),
      nearby_vendors: metric(
        baseline.networks.mac_summary.vendors.length,
        candidate.networks.mac_summary.vendors.length
      ),
      nearby_device_hints: metric(
        baseline.networks.mac_summary.device_hints.length,
        candidate.networks.mac_summary.device_hints.length
      ),
      nearby_unknown_ouis: metric(
        baseline.networks.mac_summary.unknown_ouis.length,
        candidate.networks.mac_summary.unknown_ouis.length
      )
    },
    observation_types: compareObservationTypes(baseline, candidate),
    snapshots: {
      ssids: stringDelta(baseline.snapshots.ssids, candidate.snapshots.ssids),
      bssids: stringDelta(baseline.snapshots.bssids, candidate.snapshots.bssids),
      channels: numberDelta(baseline.snapshots.channels, candidate.snapshots.channels)
    },
    nearby: {
      ssids: stringDelta(baseline.networks.ssids, candidate.networks.ssids),
      bssids: stringDelta(baseline.networks.bssids, candidate.networks.bssids),
      channels: numberDelta(baseline.networks.channels, candidate.networks.channels),
      vendors: stringDelta(bucketValues(baseline.networks.mac_summary.vendors), bucketValues(candidate.networks.mac_summary.vendors)),
      device_hints: stringDelta(
        bucketValues(baseline.networks.mac_summary.device_hints),
        bucketValues(candidate.networks.mac_summary.device_hints)
      ),
      unknown_ouis: stringDelta(
        bucketValues(baseline.networks.mac_summary.unknown_ouis),
        bucketValues(candidate.networks.mac_summary.unknown_ouis)
      )
    },
    summary: comparisonSummary(scoreDelta, baseline, candidate),
    evidence: comparisonEvidence(scoreDelta, baseline, candidate),
    limitations: [
      'This compares two saved Windows baseline analyses; neither run contains raw 802.11 management frames.',
      'Differences in nearby AP visibility can come from scan timing, movement, roaming, Location permission, or RF conditions.',
      'Treat comparison deltas as triage signals to correlate with user-visible disconnect/reconnect times.'
    ],
    next_steps: comparisonNextSteps(scoreDelta, baseline, candidate)
  };
}

function metric(baseline: number, candidate: number): BaselineRunComparisonMetric {
  return {
    baseline,
    candidate,
    delta: candidate - baseline
  };
}

function compareObservationTypes(
  baseline: BaselineRunAnalysisResult,
  candidate: BaselineRunAnalysisResult
): Record<string, BaselineRunComparisonMetric> {
  const baselineCounts = countObservationTypes(baseline);
  const candidateCounts = countObservationTypes(candidate);
  const keys = [...new Set([...Object.keys(baselineCounts), ...Object.keys(candidateCounts)])].sort();
  const result: Record<string, BaselineRunComparisonMetric> = {};

  for (const key of keys) {
    result[key] = metric(baselineCounts[key] ?? 0, candidateCounts[key] ?? 0);
  }

  return result;
}

function countObservationTypes(analysis: BaselineRunAnalysisResult): Record<string, number> {
  const counts: Record<string, number> = {};

  for (const observation of analysis.observations) {
    counts[observation.observation_type] = (counts[observation.observation_type] ?? 0) + 1;
  }

  return counts;
}

function stringDelta(baseline: string[], candidate: string[]): StringSetDelta {
  const baselineSet = new Set(baseline);
  const candidateSet = new Set(candidate);

  return {
    added: sortedStrings([...candidateSet].filter((value) => !baselineSet.has(value))),
    removed: sortedStrings([...baselineSet].filter((value) => !candidateSet.has(value))),
    shared: sortedStrings([...candidateSet].filter((value) => baselineSet.has(value)))
  };
}

function numberDelta(baseline: number[], candidate: number[]): NumberSetDelta {
  const baselineSet = new Set(baseline);
  const candidateSet = new Set(candidate);

  return {
    added: sortedNumbers([...candidateSet].filter((value) => !baselineSet.has(value))),
    removed: sortedNumbers([...baselineSet].filter((value) => !candidateSet.has(value))),
    shared: sortedNumbers([...candidateSet].filter((value) => baselineSet.has(value)))
  };
}

function comparisonSummary(
  scoreDelta: number,
  baseline: BaselineRunAnalysisResult,
  candidate: BaselineRunAnalysisResult
): string {
  if (scoreDelta >= 25) {
    return `Candidate run increased from ${baseline.report.verdict} to ${candidate.report.verdict} with score delta +${scoreDelta}. Review observations before escalating.`;
  }

  if (scoreDelta <= -25) {
    return `Candidate run score decreased by ${Math.abs(scoreDelta)} compared with baseline.`;
  }

  if (baseline.report.verdict !== candidate.report.verdict) {
    return `Verdict changed from ${baseline.report.verdict} to ${candidate.report.verdict}, but score delta is ${scoreDelta}.`;
  }

  return `Candidate run is broadly similar to baseline; score delta is ${scoreDelta}.`;
}

function comparisonEvidence(
  scoreDelta: number,
  baseline: BaselineRunAnalysisResult,
  candidate: BaselineRunAnalysisResult
): string[] {
  const evidence = [
    `Report score ${baseline.report.score} -> ${candidate.report.score} (delta ${formatSigned(scoreDelta)}).`,
    `Verdict ${baseline.report.verdict} -> ${candidate.report.verdict}; confidence ${baseline.report.confidence} -> ${candidate.report.confidence}.`,
    `Alerts ${baseline.alert_count} -> ${candidate.alert_count}; observations ${baseline.observation_count} -> ${candidate.observation_count}.`,
    `Nearby BSSIDs ${baseline.networks.bssids.length} -> ${candidate.networks.bssids.length}; nearby SSIDs ${baseline.networks.ssid_count} -> ${candidate.networks.ssid_count}.`,
    `Nearby vendors ${baseline.networks.mac_summary.vendors.length} -> ${candidate.networks.mac_summary.vendors.length}; local/randomized MACs ${baseline.networks.mac_summary.local_mac_count} -> ${candidate.networks.mac_summary.local_mac_count}.`
  ];

  const addedBssids = stringDelta(baseline.networks.bssids, candidate.networks.bssids).added;
  const removedBssids = stringDelta(baseline.networks.bssids, candidate.networks.bssids).removed;
  if (addedBssids.length > 0) {
    evidence.push(`Nearby BSSIDs added in candidate: ${addedBssids.slice(0, 8).join(', ')}.`);
  }
  if (removedBssids.length > 0) {
    evidence.push(`Nearby BSSIDs missing in candidate: ${removedBssids.slice(0, 8).join(', ')}.`);
  }

  return evidence;
}

function bucketValues(buckets: Array<{ value: string; count: number }>): string[] {
  return buckets.map((bucket) => bucket.value);
}

function comparisonNextSteps(
  scoreDelta: number,
  baseline: BaselineRunAnalysisResult,
  candidate: BaselineRunAnalysisResult
): string[] {
  const nextSteps = [
    'Compare timestamps with user-visible disconnect/reconnect moments.',
    'Repeat both normal and suspected-window runs with the same duration and interval.'
  ];

  if (scoreDelta >= 25 || candidate.report.verdict !== baseline.report.verdict) {
    nextSteps.unshift('Review candidate observations and false-positive notes before treating deltas as hostile activity.');
  }

  if (baseline.report.confidence !== 'high' || candidate.report.confidence !== 'high') {
    nextSteps.push('Use 10-15 minute runs for stronger comparison confidence.');
  }

  return nextSteps;
}

function sortedStrings(values: string[]): string[] {
  return [...values].sort();
}

function sortedNumbers(values: number[]): number[] {
  return [...values].sort((left, right) => left - right);
}

function formatSigned(value: number): string {
  return value > 0 ? `+${value}` : String(value);
}
