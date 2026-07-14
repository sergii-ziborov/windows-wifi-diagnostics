import { mkdir, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import type { CollectorEvent } from './types';

export class JsonlWriter {
  private count = 0;

  constructor(private readonly filePath: string) {}

  get eventCount(): number {
    return this.count;
  }

  async write(event: CollectorEvent): Promise<void> {
    await mkdir(dirname(this.filePath), { recursive: true });
    await writeFile(this.filePath, `${JSON.stringify(event)}\n`, { flag: 'a' });
    this.count += 1;
  }
}
