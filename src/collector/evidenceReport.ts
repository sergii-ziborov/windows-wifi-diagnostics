import type {
  BaselineRunAnalysisResult,
  BaselineRunEvidenceReport,
  BaselineRunNetworkSummary,
  BaselineRunObservation,
  BaselineRunSnapshotSummary,
  CollectorSourceStatus,
  DetectorAlert
} from './types';

interface EvidenceReportInput {
  durationSeconds: number | null;
  parsedEventCount: number;
  invalidLineCount: number;
  collectorErrorCount: number;
  sources: CollectorSourceStatus[];
  snapshots: BaselineRunSnapshotSummary;
  networks: BaselineRunNetworkSummary;
  observations: BaselineRunObservation[];
  alerts: DetectorAlert[];
  wlanEventCount: number;
  timelineCount: number;
}

export function buildEvidenceReport(input: EvidenceReportInput): BaselineRunEvidenceReport {
  const score = reportScore(input.alerts, input.observations, input.collectorErrorCount);
  const verdict = reportVerdict(score);
  const confidence = reportConfidence(input);
  const evidence = buildEvidence(input);
  const limitations = buildLimitations(input, confidence);
  const nextSteps = buildNextSteps(verdict, confidence, input);

  return {
    verdict,
    confidence,
    score,
    summary: reportSummary(verdict, confidence, score, input),
    evidence,
    limitations,
    next_steps: nextSteps
  };
}

export function formatEvidenceReport(analysis: BaselineRunAnalysisResult): string {
  const lines = [
    `Run: ${analysis.run_id}`,
    `Verdict: ${analysis.report.verdict}`,
    `Confidence: ${analysis.report.confidence}`,
    `Score: ${analysis.report.score}`,
    '',
    analysis.report.summary,
    '',
    'Evidence:'
  ];

  lines.push(...analysis.report.evidence.map((item) => `- ${item}`));
  lines.push('', 'Limitations:');
  lines.push(...analysis.report.limitations.map((item) => `- ${item}`));
  lines.push('', 'Next steps:');
  lines.push(...analysis.report.next_steps.map((item) => `- ${item}`));

  return lines.join('\n');
}

function reportScore(
  alerts: DetectorAlert[],
  observations: BaselineRunObservation[],
  collectorErrorCount: number
): number {
  const alertScore = Math.min(
    65,
    alerts.reduce((total, alert) => total + severityWeight(alert.severity, 16, 28, 42), 0)
  );
  const observationScore = Math.min(
    35,
    observations.reduce(
      (total, observation) => total + severityWeight(observation.severity, 3, 8, 15),
      0
    )
  );
  const reliabilityPenalty = collectorErrorCount > 0 ? Math.min(10, collectorErrorCount * 2) : 0;

  return Math.min(100, Math.max(0, Math.round(alertScore + observationScore + reliabilityPenalty)));
}

function reportVerdict(score: number): BaselineRunEvidenceReport['verdict'] {
  if (score >= 70) {
    return 'suspicious';
  }

  if (score >= 25) {
    return 'watch';
  }

  return 'clean_baseline';
}

function reportConfidence(input: EvidenceReportInput): BaselineRunEvidenceReport['confidence'] {
  const duration = input.durationSeconds ?? 0;
  const sourceAvailability = availableSourceCount(input.sources);
  const hasCoreSources = sourceAvailability >= 2 && input.snapshots.count > 0;
  const hasEnvironmentCoverage = input.networks.count > 0;

  if (duration >= 300 && input.snapshots.count >= 30 && hasCoreSources && hasEnvironmentCoverage) {
    return 'high';
  }

  if (duration >= 60 && input.snapshots.count >= 5 && hasCoreSources) {
    return 'medium';
  }

  return 'low';
}

function reportSummary(
  verdict: BaselineRunEvidenceReport['verdict'],
  confidence: BaselineRunEvidenceReport['confidence'],
  score: number,
  input: EvidenceReportInput
): string {
  if (verdict === 'suspicious') {
    return `Suspicious Windows telemetry pattern detected with ${confidence} coverage confidence (score ${score}). Treat this as triage evidence, not proof of raw deauth/disassociation frames.`;
  }

  if (verdict === 'watch') {
    return `Watch-level symptoms detected with ${confidence} coverage confidence (score ${score}). Correlate with user-visible disconnect times before escalating.`;
  }

  if (input.parsedEventCount === 0) {
    return `No saved evidence was parsed in this run; confidence is ${confidence}.`;
  }

  return `No reconnect-loop alerts or passive AP anomalies were detected in this saved run; confidence is ${confidence} (score ${score}).`;
}

function buildEvidence(input: EvidenceReportInput): string[] {
  const items = [
    `Duration ${formatDuration(input.durationSeconds)}; parsed events ${input.parsedEventCount}; invalid saved records ${input.invalidLineCount}.`,
    `Snapshots ${input.snapshots.count}; WLAN events ${input.wlanEventCount}; lifecycle timeline items ${input.timelineCount}.`,
    `Nearby AP records ${input.networks.count}; SSIDs ${input.networks.ssid_count}; unique BSSIDs ${input.networks.bssids.length}.`,
    `MAC intelligence known vendors ${input.networks.mac_summary.known_vendor_count}; unknown vendors ${input.networks.mac_summary.unknown_vendor_count}; local/randomized MACs ${input.networks.mac_summary.local_mac_count}.`,
    `Sources: ${formatSources(input.sources)}.`
  ];

  if (input.alerts.length > 0) {
    items.push(`Reconnect-loop alerts: ${input.alerts.slice(0, 3).map((alert) => alert.summary).join(' | ')}.`);
  }

  if (input.observations.length > 0) {
    items.push(
      `Top observations: ${input.observations
        .slice(0, 5)
        .map((observation) => `${observation.observation_type} (${observation.severity})`)
        .join(', ')}.`
    );
  }

  if (input.collectorErrorCount > 0) {
    items.push(`Collector errors recorded: ${input.collectorErrorCount}.`);
  }

  return items;
}

function buildLimitations(
  input: EvidenceReportInput,
  confidence: BaselineRunEvidenceReport['confidence']
): string[] {
  const limitations = [
    'This phase uses Windows Event Log and netsh snapshots only; it cannot see raw 802.11 management frames.',
    'Deauth/disassociation attacks cannot be proven from this evidence alone; findings are symptoms to correlate.',
    'Windows nearby AP scans can vary because of scan timing, Location permission, elevation, roaming, and RF conditions.'
  ];

  if (confidence === 'low') {
    limitations.push('Coverage confidence is low; the run is short or missing enough repeated snapshots for strong conclusions.');
  }

  if (input.networks.count === 0) {
    limitations.push('No nearby AP records were captured, so SSID/BSSID/channel environment checks could not run.');
  }

  if (input.wlanEventCount === 0) {
    limitations.push('No WLAN AutoConfig events occurred during the saved run window.');
  }

  return limitations;
}

function buildNextSteps(
  verdict: BaselineRunEvidenceReport['verdict'],
  confidence: BaselineRunEvidenceReport['confidence'],
  input: EvidenceReportInput
): string[] {
  const nextSteps = [
    'Collect a 10-15 minute baseline with the same interval during normal conditions.',
    'Run another saved sample during a suspected incident window and compare summaries.',
    'Correlate report timestamps with user-visible disconnect/reconnect moments.'
  ];

  if (verdict !== 'clean_baseline') {
    nextSteps.unshift('Review the listed observations and false-positive notes before treating this as hostile activity.');
  }

  if (confidence !== 'high' && input.durationSeconds !== null && input.durationSeconds < 300) {
    nextSteps.push('Increase duration to at least 300 seconds for stronger coverage confidence.');
  }

  return nextSteps;
}

function severityWeight(
  severity: 'low' | 'medium' | 'high',
  low: number,
  medium: number,
  high: number
): number {
  if (severity === 'high') {
    return high;
  }

  if (severity === 'medium') {
    return medium;
  }

  return low;
}

function availableSourceCount(sources: CollectorSourceStatus[]): number {
  return sources.filter((source) => source.available).length;
}

function formatSources(sources: CollectorSourceStatus[]): string {
  if (sources.length === 0) {
    return 'none reported';
  }

  return sources
    .map((source) => `${source.name}=${source.available ? 'available' : 'unavailable'}`)
    .join(', ');
}

function formatDuration(value: number | null): string {
  return value === null ? 'unknown' : `${value}s`;
}
