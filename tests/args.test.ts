import { describe, expect, it } from 'vitest';
import { baselineHelpText, parseBaselineArgs } from '../src/collector/args';

describe('parseBaselineArgs', () => {
  it('defaults to status', () => {
    expect(parseBaselineArgs([])).toEqual({ name: 'status' });
  });

  it('parses networks command', () => {
    expect(parseBaselineArgs(['networks'])).toEqual({ name: 'networks' });
  });

  it('parses collect options', () => {
    expect(
      parseBaselineArgs([
        'collect',
        '--duration',
        '30',
        '--interval',
        '2',
        '--out',
        'data/custom',
        '--db',
        'data/custom.sqlite',
        '--max-events',
        '50'
      ])
    ).toEqual({
      name: 'collect',
      durationSeconds: 30,
      intervalSeconds: 2,
      outDir: 'data/custom',
      databaseFile: 'data/custom.sqlite',
      maxEvents: 50
    });
  });

  it('parses events options', () => {
    expect(parseBaselineArgs(['events', '--last', '25'])).toEqual({
      name: 'events',
      last: 25
    });
  });

  it('parses diagnostics options', () => {
    expect(
      parseBaselineArgs([
        'diagnostics',
        '--out',
        'data/custom-diagnostics',
        '--runs-dir',
        'data/custom-runs',
        '--last-runs',
        '3',
        '--last-events',
        '25',
        '--window-minutes',
        '15',
        '--min-cycles',
        '4'
      ])
    ).toEqual({
      name: 'diagnostics',
      outDir: 'data/custom-diagnostics',
      runsDir: 'data/custom-runs',
      lastRuns: 3,
      lastEvents: 25,
      windowMinutes: 15,
      minCycles: 4
    });
  });

  it('parses diagnostics history options', () => {
    expect(parseBaselineArgs(['diagnostics-list', '--last', '7', '--dir', 'data/custom-diagnostics'])).toEqual({
      name: 'diagnostics-list',
      last: 7,
      diagnosticsDir: 'data/custom-diagnostics'
    });
  });

  it('parses run history options', () => {
    expect(parseBaselineArgs(['runs', '--last', '4', '--dir', 'data/custom-runs', '--db', 'data/custom.sqlite'])).toEqual({
      name: 'runs',
      last: 4,
      runsDir: 'data/custom-runs',
      databaseFile: 'data/custom.sqlite'
    });
  });

  it('parses run analysis options', () => {
    expect(
      parseBaselineArgs([
        'analyze',
        '--run',
        'run-1',
        '--dir',
        'data/custom-runs',
        '--window-minutes',
        '20',
        '--min-cycles',
        '3'
      ])
    ).toEqual({
      name: 'analyze',
      runId: 'run-1',
      runsDir: 'data/custom-runs',
      windowMinutes: 20,
      minCycles: 3
    });
  });

  it('parses run report options', () => {
    expect(
      parseBaselineArgs([
        'report',
        '--run',
        'run-1',
        '--dir',
        'data/custom-runs',
        '--window-minutes',
        '20',
        '--min-cycles',
        '3'
      ])
    ).toEqual({
      name: 'report',
      runId: 'run-1',
      runsDir: 'data/custom-runs',
      windowMinutes: 20,
      minCycles: 3
    });
  });

  it('parses run comparison options', () => {
    expect(
      parseBaselineArgs([
        'compare',
        '--baseline',
        'normal-run',
        '--candidate',
        'incident-run',
        '--dir',
        'data/custom-runs',
        '--window-minutes',
        '20',
        '--min-cycles',
        '3'
      ])
    ).toEqual({
      name: 'compare',
      baselineRunId: 'normal-run',
      candidateRunId: 'incident-run',
      runsDir: 'data/custom-runs',
      windowMinutes: 20,
      minCycles: 3
    });
  });

  it('requires a run id for analysis', () => {
    expect(() => parseBaselineArgs(['analyze'])).toThrow('--run is required');
  });

  it('parses timeline options', () => {
    expect(
      parseBaselineArgs([
        'timeline',
        '--last',
        '100',
        '--window-minutes',
        '15',
        '--min-cycles',
        '3'
      ])
    ).toEqual({
      name: 'timeline',
      last: 100,
      windowMinutes: 15,
      minCycles: 3
    });
  });

  it('rejects unknown options', () => {
    expect(() => parseBaselineArgs(['collect', '--bad'])).toThrow('Unknown option');
  });

  it('prints help for baseline acceptance commands', () => {
    const help = baselineHelpText();

    expect(help).toContain('npm run baseline:sample');
    expect(help).toContain('npm run baseline:diagnostics -- --last-runs 20 --last-events 200');
    expect(help).toContain('npm run baseline:diagnostics:list -- --last 20');
    expect(help).toContain('npm run baseline:report -- --run <run-id>');
    expect(help).toContain('npm run baseline:compare -- --baseline <run-id> --candidate <run-id>');
  });
});
