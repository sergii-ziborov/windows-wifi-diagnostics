import type {
  CollectOptions,
  DiagnosticsHistoryOptions,
  DiagnosticsOptions,
  HistoryOptions,
  RunAnalysisOptions,
  RunComparisonOptions,
  RunHistoryOptions,
  TimelineOptions
} from './types';

export type BaselineCliCommand =
  | { name: 'status' }
  | { name: 'networks' }
  | ({ name: 'diagnostics' } & DiagnosticsOptions)
  | ({ name: 'diagnostics-list' } & DiagnosticsHistoryOptions)
  | ({ name: 'collect' } & CollectOptions)
  | ({ name: 'analyze' } & RunAnalysisOptions)
  | ({ name: 'report' } & RunAnalysisOptions)
  | ({ name: 'compare' } & RunComparisonOptions)
  | ({ name: 'runs' } & RunHistoryOptions)
  | ({ name: 'events' } & HistoryOptions)
  | ({ name: 'timeline' } & TimelineOptions)
  | { name: 'help' };

const DEFAULT_DURATION_SECONDS = 600;
const DEFAULT_INTERVAL_SECONDS = 5;
const DEFAULT_MAX_EVENTS = 100;
const DEFAULT_HISTORY_EVENTS = 200;
const DEFAULT_HISTORY_RUNS = 20;
const DEFAULT_WINDOW_MINUTES = 10;
const DEFAULT_MIN_CYCLES = 2;

export function parseBaselineArgs(argv: string[]): BaselineCliCommand {
  const [command = 'status', ...rest] = argv;

  if (command === 'help' || command === '--help' || command === '-h') {
    return { name: 'help' };
  }

  if (command === 'status') {
    return { name: 'status' };
  }

  if (command === 'networks') {
    return { name: 'networks' };
  }

  if (command === 'diagnostics') {
    return { name: 'diagnostics', ...parseDiagnosticsOptions(rest) };
  }

  if (command === 'diagnostics-list') {
    return { name: 'diagnostics-list', ...parseDiagnosticsHistoryOptions(rest) };
  }

  if (command === 'events') {
    return { name: 'events', ...parseHistoryOptions(rest) };
  }

  if (command === 'analyze') {
    return { name: 'analyze', ...parseRunAnalysisOptions(rest) };
  }

  if (command === 'report') {
    return { name: 'report', ...parseRunAnalysisOptions(rest) };
  }

  if (command === 'compare') {
    return { name: 'compare', ...parseRunComparisonOptions(rest) };
  }

  if (command === 'runs') {
    return { name: 'runs', ...parseRunHistoryOptions(rest) };
  }

  if (command === 'timeline') {
    return { name: 'timeline', ...parseTimelineOptions(rest) };
  }

  if (command !== 'collect') {
    throw new Error(`Unknown baseline command: ${command}`);
  }

  const options: CollectOptions = {
    durationSeconds: DEFAULT_DURATION_SECONDS,
    intervalSeconds: DEFAULT_INTERVAL_SECONDS,
    outDir: null,
    maxEvents: DEFAULT_MAX_EVENTS
  };

  for (let index = 0; index < rest.length; index += 1) {
    const arg = rest[index];
    const next = rest[index + 1];

    if (arg === '--duration') {
      options.durationSeconds = readPositiveNumber('--duration', next);
      index += 1;
      continue;
    }

    if (arg === '--interval') {
      options.intervalSeconds = readPositiveNumber('--interval', next);
      index += 1;
      continue;
    }

    if (arg === '--out') {
      if (!next) {
        throw new Error('--out requires a value');
      }
      options.outDir = next;
      index += 1;
      continue;
    }

    if (arg === '--db') {
      if (!next) {
        throw new Error('--db requires a value');
      }
      options.databaseFile = next;
      index += 1;
      continue;
    }

    if (arg === '--max-events') {
      options.maxEvents = readPositiveNumber('--max-events', next);
      index += 1;
      continue;
    }

    throw new Error(`Unknown option: ${arg}`);
  }

  return { name: 'collect', ...options };
}

export function baselineHelpText(): string {
  return [
    'Usage:',
    '  npm run baseline:status',
    '  npm run baseline:networks',
    '  npm run baseline:diagnostics -- --last-runs 20 --last-events 200',
    '  npm run baseline:diagnostics:list -- --last 20',
    '  npm run baseline:runs -- --last 20',
    '  npm run baseline:analyze -- --run <run-id>',
    '  npm run baseline:report -- --run <run-id>',
    '  npm run baseline:compare -- --baseline <run-id> --candidate <run-id>',
    '  npm run baseline:events -- --last 200',
    '  npm run baseline:timeline -- --last 200 --window-minutes 10 --min-cycles 2',
    '  npm run baseline:collect -- --duration 600 --interval 5 [--db data/monitor.sqlite] [--out data/runs/custom-jsonl]',
    '  npm run baseline:sample',
    '',
    'Commands:',
    '  status   Print current Wi-Fi status JSON',
    '  networks Print nearby SSID/BSSID/channel/signal JSON',
    '  diagnostics Write a read-only baseline diagnostics bundle',
    '  diagnostics-list Print saved diagnostics bundle summaries',
    '  runs     Print saved baseline run summaries',
    '  analyze  Analyze one saved baseline run',
    '  report   Print a compact saved-run evidence report',
    '  compare  Compare two saved baseline runs',
    '  events   Print recent WLAN AutoConfig history JSON',
    '  timeline Print derived lifecycle timeline and reconnect-loop alerts',
    '  collect  Write Windows Wi-Fi baseline events to SQLite by default; --out writes JSONL export'
  ].join('\n');
}

function parseDiagnosticsHistoryOptions(args: string[]): DiagnosticsHistoryOptions {
  const options: DiagnosticsHistoryOptions = {
    last: DEFAULT_HISTORY_RUNS,
    diagnosticsDir: null
  };

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    const next = args[index + 1];

    if (arg === '--last') {
      options.last = readPositiveNumber('--last', next);
      index += 1;
      continue;
    }

    if (arg === '--dir') {
      if (!next) {
        throw new Error('--dir requires a value');
      }
      options.diagnosticsDir = next;
      index += 1;
      continue;
    }

    throw new Error(`Unknown option: ${arg}`);
  }

  return options;
}

function parseDiagnosticsOptions(args: string[]): DiagnosticsOptions {
  const options: DiagnosticsOptions = {
    outDir: null,
    runsDir: null,
    lastRuns: DEFAULT_HISTORY_RUNS,
    lastEvents: DEFAULT_HISTORY_EVENTS,
    windowMinutes: DEFAULT_WINDOW_MINUTES,
    minCycles: DEFAULT_MIN_CYCLES
  };

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    const next = args[index + 1];

    if (arg === '--out') {
      if (!next) {
        throw new Error('--out requires a value');
      }
      options.outDir = next;
      index += 1;
      continue;
    }

    if (arg === '--runs-dir') {
      if (!next) {
        throw new Error('--runs-dir requires a value');
      }
      options.runsDir = next;
      index += 1;
      continue;
    }

    if (arg === '--db') {
      if (!next) {
        throw new Error('--db requires a value');
      }
      options.databaseFile = next;
      index += 1;
      continue;
    }

    if (arg === '--last-runs') {
      options.lastRuns = readPositiveNumber('--last-runs', next);
      index += 1;
      continue;
    }

    if (arg === '--last-events') {
      options.lastEvents = readPositiveNumber('--last-events', next);
      index += 1;
      continue;
    }

    if (arg === '--window-minutes') {
      options.windowMinutes = readPositiveNumber('--window-minutes', next);
      index += 1;
      continue;
    }

    if (arg === '--min-cycles') {
      options.minCycles = readPositiveNumber('--min-cycles', next);
      index += 1;
      continue;
    }

    throw new Error(`Unknown option: ${arg}`);
  }

  return options;
}

function parseRunComparisonOptions(args: string[]): RunComparisonOptions {
  const options: RunComparisonOptions = {
    baselineRunId: '',
    candidateRunId: '',
    runsDir: null,
    windowMinutes: DEFAULT_WINDOW_MINUTES,
    minCycles: DEFAULT_MIN_CYCLES
  };

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    const next = args[index + 1];

    if (arg === '--baseline') {
      if (!next) {
        throw new Error('--baseline requires a value');
      }
      options.baselineRunId = next;
      index += 1;
      continue;
    }

    if (arg === '--candidate') {
      if (!next) {
        throw new Error('--candidate requires a value');
      }
      options.candidateRunId = next;
      index += 1;
      continue;
    }

    if (arg === '--dir') {
      if (!next) {
        throw new Error('--dir requires a value');
      }
      options.runsDir = next;
      index += 1;
      continue;
    }

    if (arg === '--db') {
      if (!next) {
        throw new Error('--db requires a value');
      }
      options.databaseFile = next;
      index += 1;
      continue;
    }

    if (arg === '--window-minutes') {
      options.windowMinutes = readPositiveNumber('--window-minutes', next);
      index += 1;
      continue;
    }

    if (arg === '--min-cycles') {
      options.minCycles = readPositiveNumber('--min-cycles', next);
      index += 1;
      continue;
    }

    throw new Error(`Unknown option: ${arg}`);
  }

  if (!options.baselineRunId) {
    throw new Error('--baseline is required');
  }

  if (!options.candidateRunId) {
    throw new Error('--candidate is required');
  }

  return options;
}

function parseRunAnalysisOptions(args: string[]): RunAnalysisOptions {
  const options: RunAnalysisOptions = {
    runId: '',
    runsDir: null,
    windowMinutes: DEFAULT_WINDOW_MINUTES,
    minCycles: DEFAULT_MIN_CYCLES
  };

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    const next = args[index + 1];

    if (arg === '--run') {
      if (!next) {
        throw new Error('--run requires a value');
      }
      options.runId = next;
      index += 1;
      continue;
    }

    if (arg === '--dir') {
      if (!next) {
        throw new Error('--dir requires a value');
      }
      options.runsDir = next;
      index += 1;
      continue;
    }

    if (arg === '--db') {
      if (!next) {
        throw new Error('--db requires a value');
      }
      options.databaseFile = next;
      index += 1;
      continue;
    }

    if (arg === '--window-minutes') {
      options.windowMinutes = readPositiveNumber('--window-minutes', next);
      index += 1;
      continue;
    }

    if (arg === '--min-cycles') {
      options.minCycles = readPositiveNumber('--min-cycles', next);
      index += 1;
      continue;
    }

    throw new Error(`Unknown option: ${arg}`);
  }

  if (!options.runId) {
    throw new Error('--run is required');
  }

  return options;
}

function parseRunHistoryOptions(args: string[]): RunHistoryOptions {
  const options: RunHistoryOptions = {
    last: DEFAULT_HISTORY_RUNS,
    runsDir: null
  };

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    const next = args[index + 1];

    if (arg === '--last') {
      options.last = readPositiveNumber('--last', next);
      index += 1;
      continue;
    }

    if (arg === '--dir') {
      if (!next) {
        throw new Error('--dir requires a value');
      }
      options.runsDir = next;
      index += 1;
      continue;
    }

    if (arg === '--db') {
      if (!next) {
        throw new Error('--db requires a value');
      }
      options.databaseFile = next;
      index += 1;
      continue;
    }

    throw new Error(`Unknown option: ${arg}`);
  }

  return options;
}

function parseHistoryOptions(args: string[]): HistoryOptions {
  const options: HistoryOptions = {
    last: DEFAULT_HISTORY_EVENTS
  };

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    const next = args[index + 1];

    if (arg === '--last') {
      options.last = readPositiveNumber('--last', next);
      index += 1;
      continue;
    }

    throw new Error(`Unknown option: ${arg}`);
  }

  return options;
}

function parseTimelineOptions(args: string[]): TimelineOptions {
  const options: TimelineOptions = {
    last: DEFAULT_HISTORY_EVENTS,
    windowMinutes: DEFAULT_WINDOW_MINUTES,
    minCycles: DEFAULT_MIN_CYCLES
  };

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    const next = args[index + 1];

    if (arg === '--last') {
      options.last = readPositiveNumber('--last', next);
      index += 1;
      continue;
    }

    if (arg === '--window-minutes') {
      options.windowMinutes = readPositiveNumber('--window-minutes', next);
      index += 1;
      continue;
    }

    if (arg === '--min-cycles') {
      options.minCycles = readPositiveNumber('--min-cycles', next);
      index += 1;
      continue;
    }

    throw new Error(`Unknown option: ${arg}`);
  }

  return options;
}

function readPositiveNumber(name: string, value: string | undefined): number {
  if (!value) {
    throw new Error(`${name} requires a value`);
  }

  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive number`);
  }

  return parsed;
}
