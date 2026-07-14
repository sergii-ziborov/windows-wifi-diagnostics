import { baselineHelpText, parseBaselineArgs } from '../collector/args';
import { collectBaseline, getBaselineStatus } from '../collector/baselineService';
import {
  createBaselineDiagnosticsBundle,
  listBaselineDiagnosticsBundles
} from '../collector/diagnosticsService';
import { formatEvidenceReport } from '../collector/evidenceReport';
import { getBaselineEvents, getBaselineTimeline } from '../collector/historyService';
import { getBaselineNetworks } from '../collector/networkService';
import { analyzeBaselineRun } from '../collector/runAnalysis';
import { compareBaselineRuns } from '../collector/runComparison';
import { listBaselineRuns } from '../collector/runHistory';

async function main(): Promise<void> {
  const command = parseBaselineArgs(process.argv.slice(2));

  if (command.name === 'help') {
    console.log(baselineHelpText());
    return;
  }

  if (command.name === 'status') {
    const status = await getBaselineStatus();
    console.log(JSON.stringify(status, null, 2));
    return;
  }

  if (command.name === 'events') {
    const events = await getBaselineEvents({ last: command.last });
    console.log(JSON.stringify(events, null, 2));
    return;
  }

  if (command.name === 'networks') {
    const networks = await getBaselineNetworks({ refreshScan: true });
    console.log(JSON.stringify(networks, null, 2));
    return;
  }

  if (command.name === 'diagnostics') {
    const diagnostics = await createBaselineDiagnosticsBundle({
      outDir: command.outDir,
      runsDir: command.runsDir,
      databaseFile: command.databaseFile,
      lastRuns: command.lastRuns,
      lastEvents: command.lastEvents,
      windowMinutes: command.windowMinutes,
      minCycles: command.minCycles
    });
    console.log(JSON.stringify(diagnostics, null, 2));
    return;
  }

  if (command.name === 'diagnostics-list') {
    const diagnostics = await listBaselineDiagnosticsBundles({
      last: command.last,
      diagnosticsDir: command.diagnosticsDir
    });
    console.log(JSON.stringify(diagnostics, null, 2));
    return;
  }

  if (command.name === 'runs') {
    const runs = await listBaselineRuns({ last: command.last, runsDir: command.runsDir, databaseFile: command.databaseFile });
    console.log(JSON.stringify(runs, null, 2));
    return;
  }

  if (command.name === 'analyze') {
    const analysis = await analyzeBaselineRun({
      runId: command.runId,
      runsDir: command.runsDir,
      databaseFile: command.databaseFile,
      windowMinutes: command.windowMinutes,
      minCycles: command.minCycles
    });
    console.log(JSON.stringify(analysis, null, 2));
    return;
  }

  if (command.name === 'report') {
    const analysis = await analyzeBaselineRun({
      runId: command.runId,
      runsDir: command.runsDir,
      databaseFile: command.databaseFile,
      windowMinutes: command.windowMinutes,
      minCycles: command.minCycles
    });
    console.log(formatEvidenceReport(analysis));
    return;
  }

  if (command.name === 'compare') {
    const comparison = await compareBaselineRuns({
      baselineRunId: command.baselineRunId,
      candidateRunId: command.candidateRunId,
      runsDir: command.runsDir,
      databaseFile: command.databaseFile,
      windowMinutes: command.windowMinutes,
      minCycles: command.minCycles
    });
    console.log(JSON.stringify(comparison, null, 2));
    return;
  }

  if (command.name === 'timeline') {
    const timeline = await getBaselineTimeline({
      last: command.last,
      windowMinutes: command.windowMinutes,
      minCycles: command.minCycles
    });
    console.log(JSON.stringify(timeline, null, 2));
    return;
  }

  const result = await collectBaseline({
    durationSeconds: command.durationSeconds,
    intervalSeconds: command.intervalSeconds,
    outDir: command.outDir,
    databaseFile: command.databaseFile,
    maxEvents: command.maxEvents
  });
  console.log(JSON.stringify(result, null, 2));
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
