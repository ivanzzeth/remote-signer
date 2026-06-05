/** Matches JSON keys that store Go time.Duration as nanoseconds in settings snapshots. */
export const DURATION_KEY_RE =
  /(?:^window$|^interval$|timeout|_age|_window|_after|_interval|_ttl|_period)$/;

const NS_PER = {
  ns: 1,
  us: 1_000,
  µs: 1_000,
  ms: 1_000_000,
  s: 1_000_000_000,
  m: 60_000_000_000,
  h: 3_600_000_000_000,
} as const;

export function isDurationField(key: string, value: unknown): boolean {
  return typeof value === "number" && DURATION_KEY_RE.test(key);
}

export function formatDuration(ns: number): string {
  if (ns === 0) return "0s";
  if (ns % NS_PER.h === 0) return `${ns / NS_PER.h}h`;
  if (ns % NS_PER.m === 0) return `${ns / NS_PER.m}m`;
  if (ns % NS_PER.s === 0) return `${ns / NS_PER.s}s`;
  if (ns % NS_PER.ms === 0) return `${ns / NS_PER.ms}ms`;
  return `${ns}ns`;
}

export function parseDuration(s: string): number | null {
  const m = s.trim().match(/^(-?\d+(?:\.\d+)?)\s*(ns|us|µs|ms|s|m|h)$/i);
  if (!m) return null;
  const n = parseFloat(m[1]);
  const unit = m[2].toLowerCase() as keyof typeof NS_PER;
  return Math.round(n * NS_PER[unit]);
}
