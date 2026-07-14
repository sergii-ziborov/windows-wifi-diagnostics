import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { JsonlWriter } from '../src/collector/jsonl';
import type { CollectorStateEvent } from '../src/collector/types';

let tempDir: string | null = null;

afterEach(async () => {
  if (tempDir) {
    await rm(tempDir, { recursive: true, force: true });
    tempDir = null;
  }
});

describe('JsonlWriter', () => {
  it('writes one valid JSON object per line', async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'monitor-jsonl-'));
    const filePath = join(tempDir, 'events.jsonl');
    const writer = new JsonlWriter(filePath);
    const event: CollectorStateEvent = {
      schema: 'wifi.collector_state.v1',
      event_type: 'collector_state',
      ts_utc: '2026-06-02T12:00:00.000Z',
      source: 'system',
      run_id: 'test-run',
      host_id: 'test-host',
      state: 'started',
      message: 'started'
    };

    await writer.write(event);
    await writer.write({ ...event, state: 'stopped', message: 'stopped' });

    const lines = (await readFile(filePath, 'utf8')).trim().split('\n');
    expect(lines).toHaveLength(2);
    expect(JSON.parse(lines[0])).toMatchObject({ state: 'started' });
    expect(JSON.parse(lines[1])).toMatchObject({ state: 'stopped' });
    expect(writer.eventCount).toBe(2);
  });
});
