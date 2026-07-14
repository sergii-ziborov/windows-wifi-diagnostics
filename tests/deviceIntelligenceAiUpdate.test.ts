import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  claudePrintArgs,
  runAiThreatReview,
  runDeviceIntelligenceUpdate,
  runProcess,
  windowsTaskkillArgs
} from '../src/collector/deviceIntelligence';
import type { WindowsWifiNetwork } from '../src/collector/types';

describe('device AI update runner', () => {
  it('saves a smart local update without running an external AI process', async () => {
    const tempDir = await mkdtemp(join(tmpdir(), 'monitor-smart-ai-'));

    try {
      const result = await runDeviceIntelligenceUpdate({
        provider: 'smart',
        network: makeNetwork({
          mac_enrichment: {
            normalized_mac: '48:4a:e9:00:00:01',
            oui: '48:4a:e9',
            vendor: 'Hewlett Packard Enterprise',
            address_scope: 'global',
            device_hint: 'enterprise managed access point',
            confidence: 'high',
            source: 'local_oui_seed.v1',
            notes: []
          },
          security_assessment: {
            posture: 'standard',
            attack_difficulty: 'medium',
            danger_level: 'low',
            label: 'LOW | Password-dependent',
            summary: 'WPA2-Personal with CCMP/AES is common but depends on password quality.',
            notes: []
          }
        }),
        databaseFile: join(tempDir, 'run.sqlite'),
        processRunner: async () => {
          throw new Error('smart update should not run an external process');
        }
      });

      expect(result.provider).toBe('smart');
      expect(result.available).toBe(true);
      expect(result.saved).toBe(true);
      expect(result.job.status).toBe('saved');
      expect(result.job.command).toBe('local smart device update');
      expect(result.override?.source).toBe('local.smart_device_update');
      expect(result.override?.vendor).toBe('Hewlett Packard Enterprise');
      expect(result.override?.device_role).toBe('access_point');
      expect(result.raw_output).toContain('candidate');
    } finally {
      await rm(tempDir, { recursive: true, force: true });
    }
  });

  it('returns a visible timeout result with job metadata', async () => {
    const result = await runDeviceIntelligenceUpdate({
      provider: 'codex',
      network: makeNetwork(),
      skipProviderCheck: true,
      processRunner: async (_provider, _prompt, options) => ({
        command: 'codex',
        status: null,
        stdout: '',
        stderr: '',
        notFound: false,
        timedOut: true,
        cancelled: false,
        startedAtUtc: '2026-06-04T10:00:00.000Z',
        finishedAtUtc: '2026-06-04T10:00:45.000Z',
        durationMs: 45_000,
        timeoutMs: options.timeoutMs
      })
    });

    expect(result.saved).toBe(false);
    expect(result.job.status).toBe('timeout');
    expect(result.error).toContain('timed out');
  });

  it('keeps raw output when AI returns invalid JSON', async () => {
    const result = await runDeviceIntelligenceUpdate({
      provider: 'codex',
      network: makeNetwork(),
      skipProviderCheck: true,
      processRunner: async (_provider, _prompt, options) => ({
        command: 'codex',
        status: 0,
        stdout: 'not json',
        stderr: '',
        notFound: false,
        timedOut: false,
        cancelled: false,
        startedAtUtc: '2026-06-04T10:00:00.000Z',
        finishedAtUtc: '2026-06-04T10:00:02.000Z',
        durationMs: 2_000,
        timeoutMs: options.timeoutMs
      })
    });

    expect(result.saved).toBe(false);
    expect(result.job.status).toBe('failed');
    expect(result.raw_output).toBe('not json');
    expect(result.error).toContain('not valid JSON');
  });

  it('kills the process tree when a process times out', async () => {
    let killedPid: number | null = null;
    const result = await runProcess('node', ['-e', 'setTimeout(() => {}, 100000)'], undefined, {
      timeoutMs: 50,
      killProcessTree: async (pid) => {
        killedPid = pid;
      }
    });

    expect(result.timedOut).toBe(true);
    expect(killedPid).toBeGreaterThan(0);
  });

  it('builds Windows taskkill process-tree arguments', () => {
    expect(windowsTaskkillArgs(1234)).toEqual(['/PID', '1234', '/T', '/F']);
  });

  it('keeps Claude prompts out of command-line arguments', () => {
    expect(claudePrintArgs()).toEqual(['-p']);
  });

  it('returns a visible AI threat review error when provider launch fails with ENAMETOOLONG', async () => {
    const result = await runAiThreatReview({
      provider: 'codex',
      scope: 'map',
      networks: [makeNetwork()],
      processRunner: async () => {
        throw new Error('spawn ENAMETOOLONG');
      }
    });

    expect(result.review).toBeNull();
    expect(result.job?.status).toBe('failed');
    expect(result.error).toContain('too long');
  });

  it('keeps AI threat review prompts compact for large maps', async () => {
    let promptLength = 0;
    const result = await runAiThreatReview({
      provider: 'codex',
      scope: 'map',
      networks: Array.from({ length: 60 }, (_value, index) =>
        makeNetwork({
          ssid: `Large Test AP ${index}`,
          bssid: `48:4a:e9:00:${index.toString(16).padStart(2, '0')}:01`,
          raw: {
            long_value: 'x'.repeat(2000)
          }
        })
      ),
      processRunner: async (_provider, prompt, options) => {
        promptLength = prompt.length;
        return {
          command: 'codex',
          status: 0,
          stdout: JSON.stringify({
            verdict: 'watch',
            severity: 'medium',
            confidence: 'medium',
            summary: 'Large map reviewed from compact evidence.',
            findings: [],
            recommended_next_steps: ['Continue passive observation.'],
            false_positive_notes: ['Dense AP environments can look noisy.']
          }),
          stderr: '',
          notFound: false,
          timedOut: false,
          cancelled: false,
          startedAtUtc: '2026-06-04T10:00:00.000Z',
          finishedAtUtc: '2026-06-04T10:00:02.000Z',
          durationMs: 2_000,
          timeoutMs: options.timeoutMs
        };
      }
    });

    expect(promptLength).toBeGreaterThan(0);
    expect(promptLength).toBeLessThanOrEqual(12_000);
    expect(result.review?.verdict).toBe('watch');
  });
});

function makeNetwork(overrides: Partial<WindowsWifiNetwork> = {}): WindowsWifiNetwork {
  return {
    schema: 'wifi.windows_baseline.v1',
    event_type: 'windows_wifi_network',
    ts_utc: '2026-06-04T10:00:00.000Z',
    source: 'baseline',
    run_id: 'test-run',
    host_id: 'test-host',
    interface_name: 'Wi-Fi',
    ssid: 'Test AP',
    network_type: 'Infrastructure',
    authentication: 'WPA2-Personal',
    encryption: 'CCMP',
    bssid: '48:4a:e9:00:00:01',
    signal_percent: 80,
    radio_type: '802.11ac',
    band: '5 GHz',
    channel: 36,
    basic_rates_mbps: [],
    other_rates_mbps: [],
    raw: {},
    ...overrides
  };
}
