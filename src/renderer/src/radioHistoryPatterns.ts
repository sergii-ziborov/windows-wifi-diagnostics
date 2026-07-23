export type RadioPresenceClass = 'new' | 'stable' | 'weekday' | 'recurring' | 'intermittent' | 'dormant';
export type RadioStabilityState = 'stable' | 'intermittent' | 'not-seen' | 'insufficient';

export interface RadioStabilityWindow {
  days: 1 | 7 | 30;
  eligibleSessions: number;
  seenSessions: number;
  coveragePercent: number;
  distinctDays: number;
  state: RadioStabilityState;
}

export interface RadioPresencePattern {
  firstSeenMs: number;
  lastSeenMs: number;
  observedSessions: number;
  observedDays: number;
  presenceClass: RadioPresenceClass;
  summary: string;
  weekdayLabel: string | null;
  weekdaySharePercent: number;
  windows: RadioStabilityWindow[];
}

const DAY_MS = 24 * 60 * 60 * 1_000;
const WEEKDAYS = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];

export function analyzeRadioPresence(
  observedSessionMs: readonly number[],
  allSessionMs: readonly number[],
  nowMs = Date.now()
): RadioPresencePattern | null {
  const observed = uniqueTimes(observedSessionMs).filter((value) => value <= nowMs);
  if (!observed.length) return null;
  const sessions = uniqueTimes(allSessionMs).filter((value) => value <= nowMs);
  const firstSeenMs = observed[0];
  const lastSeenMs = observed.at(-1)!;
  const observedDayValues = uniqueDays(observed);
  const weekday = dominantWeekday(observedDayValues);
  const windows = ([1, 7, 30] as const).map((days) =>
    analyzeWindow(days, observed, sessions, firstSeenMs, nowMs)
  );
  const ageMs = Math.max(0, nowMs - lastSeenMs);
  const spanMs = Math.max(0, lastSeenMs - firstSeenMs);
  const recentStable = windows.find((window) => window.state === 'stable');
  let presenceClass: RadioPresenceClass;
  let summary: string;

  if (ageMs > 7 * DAY_MS) {
    presenceClass = 'dormant';
    summary = `Not observed for ${Math.floor(ageMs / DAY_MS)} days`;
  } else if (nowMs - firstSeenMs <= DAY_MS && spanMs < DAY_MS) {
    presenceClass = 'new';
    summary = 'First observed in the last 24 hours';
  } else if (recentStable) {
    presenceClass = 'stable';
    summary = `Stable in sampled ${recentStable.days}-day window (${recentStable.coveragePercent}% scan coverage)`;
  } else if (weekday.label && observedDayValues.length >= 2 && weekday.sharePercent >= 60 && spanMs >= 6 * DAY_MS) {
    presenceClass = 'weekday';
    summary = `${weekday.label} pattern (${weekday.matchingDays}/${observedDayValues.length} observed days)`;
  } else if (observedDayValues.length >= 3) {
    presenceClass = 'recurring';
    summary = `Recurring across ${observedDayValues.length} sampled days`;
  } else {
    presenceClass = 'intermittent';
    summary = 'Intermittent in the available scan history';
  }

  return {
    firstSeenMs,
    lastSeenMs,
    observedSessions: observed.length,
    observedDays: observedDayValues.length,
    presenceClass,
    summary,
    weekdayLabel: weekday.label,
    weekdaySharePercent: weekday.sharePercent,
    windows
  };
}

function analyzeWindow(
  days: 1 | 7 | 30,
  observed: number[],
  sessions: number[],
  firstSeenMs: number,
  nowMs: number
): RadioStabilityWindow {
  const cutoff = Math.max(firstSeenMs, nowMs - days * DAY_MS);
  const eligible = sessions.filter((value) => value >= cutoff);
  const seen = observed.filter((value) => value >= cutoff);
  const coveragePercent = Math.round(100 * seen.length / Math.max(1, eligible.length));
  const minimumSessions = days === 1 ? 2 : days === 7 ? 3 : 4;
  let state: RadioStabilityState = 'insufficient';
  if (eligible.length >= minimumSessions) {
    state = seen.length === 0 ? 'not-seen' : coveragePercent >= 70 ? 'stable' : 'intermittent';
  }
  return {
    days,
    eligibleSessions: eligible.length,
    seenSessions: seen.length,
    coveragePercent,
    distinctDays: uniqueDays(seen).length,
    state
  };
}

function dominantWeekday(dayValues: Date[]): {
  label: string | null;
  sharePercent: number;
  matchingDays: number;
} {
  const counts = Array.from({ length: 7 }, () => 0);
  dayValues.forEach((date) => {
    counts[date.getDay()] += 1;
  });
  const matchingDays = Math.max(...counts);
  if (!matchingDays) return { label: null, sharePercent: 0, matchingDays: 0 };
  const weekday = counts.indexOf(matchingDays);
  return {
    label: WEEKDAYS[weekday],
    sharePercent: Math.round(100 * matchingDays / dayValues.length),
    matchingDays
  };
}

function uniqueTimes(values: readonly number[]): number[] {
  return [...new Set(values.filter(Number.isFinite).map(Math.round))].sort((left, right) => left - right);
}

function uniqueDays(values: readonly number[]): Date[] {
  const dates = new Map<string, Date>();
  values.forEach((value) => {
    const date = new Date(value);
    const key = `${date.getFullYear()}-${date.getMonth()}-${date.getDate()}`;
    dates.set(key, new Date(date.getFullYear(), date.getMonth(), date.getDate()));
  });
  return [...dates.values()].sort((left, right) => left.getTime() - right.getTime());
}
