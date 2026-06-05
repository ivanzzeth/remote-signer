import { useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import type { Rule, RuleBudget } from "remote-signer-client";
import { Badge, Empty, ErrorBanner, Loading } from "./ui";
import { ProgressBar } from "../pages/Budgets";
import {
  categorizeRuleBudgets,
  formatBudgetPeriod,
  formatPeriodWindow,
  pctUsed,
  timeUntil,
  unitLabel,
} from "../lib/budgetDisplay";

export function RuleBudgetsPanel({
  rule,
  budgets,
  loading,
  error,
  busy,
  onRefresh,
  onResetAll,
}: {
  rule: Rule;
  budgets: RuleBudget[] | undefined;
  loading: boolean;
  error: string | null;
  busy: boolean;
  onRefresh: () => void;
  onResetAll: () => void;
}) {
  const [showOther, setShowOther] = useState(false);
  const [showStale, setShowStale] = useState(false);

  const periodLabel = formatBudgetPeriod(rule.budget_period);
  const sample = budgets?.find((b) => b.period_start && b.period_ends_at);
  const windowLabel = formatPeriodWindow(sample?.period_start, sample?.period_ends_at);
  const groups = budgets ? categorizeRuleBudgets(budgets) : null;

  return (
    <div className="space-y-3">
      {periodLabel && (
        <div className="rounded-md border border-ink-200 bg-ink-50 px-3 py-2 text-xs text-ink-700">
          <div className="font-medium text-ink-900">Budget period</div>
          <div>{periodLabel} · auto-renew at period end</div>
          {windowLabel && <div className="mt-1 font-mono text-[11px]">{windowLabel}</div>}
          {sample?.period_ends_at && (
            <div className="mt-0.5 text-ink-500">
              Next renew {timeUntil(sample.period_ends_at)}
            </div>
          )}
        </div>
      )}

      <div className="rounded-md border border-sky-200 bg-sky-50 px-3 py-2 text-xs text-sky-900">
        Signature and dynamic budgets are debited per chain as{" "}
        <span className="font-mono">{`{chain_id}:sign_count`}</span>. Reset rows under{" "}
        <strong>Active limits</strong>, not unused template rows.
      </div>

      <div className="flex items-center justify-between gap-2">
        <h3 className="text-xs font-semibold uppercase tracking-wide text-ink-500">
          Budgets
        </h3>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={onRefresh}
            disabled={busy}
            className="rounded-md border border-ink-200 px-2 py-1 text-xs text-ink-700 hover:bg-ink-100 disabled:opacity-50"
          >
            Refresh
          </button>
          <button
            type="button"
            onClick={onResetAll}
            disabled={busy || !groups?.active.length}
            className="rounded-md border border-ink-300 px-2 py-1 text-xs text-ink-700 hover:bg-ink-100 disabled:opacity-50"
            data-testid="rule-budgets-reset-all"
          >
            Reset all enforcing
          </button>
        </div>
      </div>

      {loading && <Loading />}
      {error && <ErrorBanner msg={error} />}

      {budgets && budgets.length === 0 && (
        <Empty msg="No budgets attached to this rule." />
      )}

      {groups && budgets && budgets.length > 0 && (
        <div className="space-y-4">
          <BudgetGroupTable
            title="Active limits"
            rows={groups.active}
            emptyHint="No enforcing budget rows yet."
          />

          {groups.other.length > 0 && (
            <CollapsibleGroup
              title={`Other tracked units (${groups.other.length})`}
              open={showOther}
              onToggle={() => setShowOther((v) => !v)}
            >
              <BudgetGroupTable rows={groups.other} compact />
            </CollapsibleGroup>
          )}

          {groups.stale.length > 0 && (
            <CollapsibleGroup
              title={`Unused template rows (${groups.stale.length})`}
              open={showStale}
              onToggle={() => setShowStale((v) => !v)}
              muted
            >
              <BudgetGroupTable rows={groups.stale} compact muted />
            </CollapsibleGroup>
          )}
        </div>
      )}
    </div>
  );
}

function CollapsibleGroup({
  title,
  open,
  onToggle,
  muted,
  children,
}: {
  title: string;
  open: boolean;
  onToggle: () => void;
  muted?: boolean;
  children: ReactNode;
}) {
  return (
    <div className={muted ? "opacity-80" : undefined}>
      <button
        type="button"
        onClick={onToggle}
        className="mb-1 flex w-full items-center gap-1 text-left text-xs font-medium text-ink-600 hover:text-ink-900"
      >
        <span>{open ? "▼" : "▶"}</span>
        {title}
      </button>
      {open && children}
    </div>
  );
}

function BudgetGroupTable({
  title,
  rows,
  emptyHint,
  compact,
  muted,
}: {
  title?: string;
  rows: RuleBudget[];
  emptyHint?: string;
  compact?: boolean;
  muted?: boolean;
}) {
  if (rows.length === 0 && emptyHint) {
    return <p className="text-xs text-ink-500">{emptyHint}</p>;
  }
  if (rows.length === 0) return null;

  return (
    <div>
      {title && (
        <div className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-ink-500">
          {title}
        </div>
      )}
      <table className={`w-full text-left text-sm ${muted ? "text-ink-500" : ""}`}>
        <thead className="text-xs uppercase text-ink-500">
          <tr>
            <th className="py-1 pr-3 font-normal">Unit</th>
            <th className="py-1 pr-3 font-normal">Spent / Max</th>
            {!compact && <th className="py-1 pr-3 font-normal">Tx</th>}
            <th className="py-1 font-normal">Status</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((b) => (
            <BudgetRow key={b.id} b={b} compact={compact} muted={muted} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function BudgetRow({
  b,
  compact,
  muted,
}: {
  b: RuleBudget;
  compact?: boolean;
  muted?: boolean;
}) {
  const pct = pctUsed(b);
  const label = unitLabel(b);
  const active = b.enforces_limit && !b.is_stale_placeholder;
  const chainDebit = /^\d+:/.test(b.unit);

  return (
    <tr className={`border-t border-ink-100 ${active ? "border-l-2 border-l-green-500 bg-green-50/30" : ""}`}>
      <td className="py-1 pr-3 align-top">
        <Link
          to={`/budgets/${encodeURIComponent(b.id)}`}
          className="text-xs text-ink-800 hover:text-accent-600 hover:underline"
        >
          {label}
        </Link>
        {!compact && (
          <div className="font-mono text-[10px] text-ink-400">{b.unit}</div>
        )}
        {chainDebit && active && (
          <div className="mt-0.5">
            <Badge tone="neutral">chain debit</Badge>
          </div>
        )}
      </td>
      <td className="py-1 pr-3 align-top">
        {b.enforces_limit ? (
          <>
            <ProgressBar pct={pct} />
            <div className="mt-0.5 font-mono text-[11px]">
              {b.spent} / {b.max_total}
            </div>
          </>
        ) : (
          <span className="font-mono text-[11px]">
            {b.spent} / {b.max_total || "-1"}
          </span>
        )}
      </td>
      {!compact && (
        <td className="py-1 pr-3 font-mono text-xs">
          {b.tx_count}
          {b.max_tx_count ? ` / ${b.max_tx_count}` : ""}
        </td>
      )}
      <td className="py-1 align-top">
        {b.is_stale_placeholder ? (
          <Badge tone="neutral">Unused</Badge>
        ) : active ? (
          <Badge tone="green">Active</Badge>
        ) : (
          <Badge tone="neutral">Tracked</Badge>
        )}
        {b.alert_sent && !muted && (
          <Badge tone="red">Alert</Badge>
        )}
      </td>
    </tr>
  );
}
