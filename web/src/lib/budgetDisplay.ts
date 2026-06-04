import type { RuleBudget } from "remote-signer-client";

export function unitLabel(b: { unit_display?: string; unit: string }): string {
  return b.unit_display?.trim() || b.unit;
}

export function pctUsed(b: { spent: string; max_total: string }): number {
  const max = Number(b.max_total);
  if (!Number.isFinite(max) || max <= 0) return 0;
  const spent = Number(b.spent);
  if (!Number.isFinite(spent)) return 0;
  return (spent / max) * 100;
}

export function formatBudgetPeriod(period?: string): string | null {
  if (!period) return null;
  const hours = period.match(/^(\d+)h/);
  if (hours) return `every ${hours[1]}h`;
  const days = period.match(/^(\d+)h0m0s$/);
  if (days) {
    const h = Number(days[1]);
    if (h % 24 === 0 && h >= 24) return `every ${h / 24}d`;
  }
  return period;
}

export function formatPeriodWindow(start?: string, end?: string): string | null {
  if (!start || !end) return null;
  const s = new Date(start);
  const e = new Date(end);
  if (Number.isNaN(s.getTime()) || Number.isNaN(e.getTime())) return null;
  const fmt = (d: Date) =>
    d.toISOString().replace("T", " ").replace(/\.\d{3}Z$/, " UTC");
  return `${fmt(s)}  →  ${fmt(e)}`;
}

export function timeUntil(iso?: string): string | null {
  if (!iso) return null;
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return null;
  const ms = t - Date.now();
  if (ms <= 0) return "now";
  const h = Math.floor(ms / 3600000);
  const m = Math.floor((ms % 3600000) / 60000);
  if (h > 0) return `in ${h}h ${m}m`;
  return `in ${m}m`;
}

export function categorizeRuleBudgets(rows: RuleBudget[]) {
  const stale = rows.filter((r) => r.is_stale_placeholder);
  const active = rows.filter((r) => r.enforces_limit && !r.is_stale_placeholder);
  const taken = new Set([...stale, ...active].map((r) => r.id));
  const other = rows.filter((r) => !taken.has(r.id));
  return { active, other, stale };
}

export type RuleBudgetGroup = ReturnType<typeof categorizeRuleBudgets>;
