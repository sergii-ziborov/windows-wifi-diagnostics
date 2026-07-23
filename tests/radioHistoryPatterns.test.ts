import { describe, expect, it } from 'vitest';
import { analyzeRadioPresence } from '../src/renderer/src/radioHistoryPatterns';

const DAY_MS = 24 * 60 * 60 * 1_000;

describe('radio history presence patterns', () => {
  it('marks a newly observed identity without overstating stability', () => {
    const now = Date.UTC(2026, 6, 23, 12);
    const pattern = analyzeRadioPresence([now - 10_000], [now - 10_000], now)!;

    expect(pattern.presenceClass).toBe('new');
    expect(pattern.windows.every((window) => window.state === 'insufficient')).toBe(true);
  });

  it('recognizes sampled stability across 1, 7 and 30 day windows', () => {
    const now = Date.UTC(2026, 6, 23, 12);
    const sessions = Array.from({ length: 10 }, (_, index) => now - index * 12 * 60 * 60 * 1_000);
    const pattern = analyzeRadioPresence(sessions, sessions, now)!;

    expect(pattern.presenceClass).toBe('stable');
    expect(pattern.windows.find((window) => window.days === 1)?.state).toBe('stable');
    expect(pattern.windows.find((window) => window.days === 7)?.coveragePercent).toBe(100);
  });

  it('detects a weekday recurrence only from multiple sampled weeks', () => {
    const friday = Date.UTC(2026, 6, 24, 12);
    const observed = [friday - 21 * DAY_MS, friday - 14 * DAY_MS, friday - 7 * DAY_MS, friday];
    const sessions = Array.from({ length: 22 }, (_, index) => friday - index * DAY_MS);
    const pattern = analyzeRadioPresence(observed, sessions, friday)!;

    expect(pattern.presenceClass).toBe('weekday');
    expect(pattern.weekdayLabel).toBe('Friday');
    expect(pattern.weekdaySharePercent).toBe(100);
  });

  it('marks old evidence as dormant', () => {
    const now = Date.UTC(2026, 6, 23, 12);
    const pattern = analyzeRadioPresence(
      [now - 20 * DAY_MS, now - 15 * DAY_MS],
      [now - 20 * DAY_MS, now - 15 * DAY_MS, now],
      now
    )!;

    expect(pattern.presenceClass).toBe('dormant');
  });
});
