import { useEffect, useState } from "react";
import { APIError, type Rule, type RuleBudget } from "remote-signer-client";
import {
  Badge,
  Card,
  Empty,
  ErrorBanner,
  Loading,
  PageHeader,
} from "../components/ui";
import { getClient } from "../lib/auth";

interface BudgetRow {
  rule: Rule;
  budget: RuleBudget;
}

/**
 * Per-rule spending budget overview. Each rule can pin one budget per
 * unit (eth / usdt / chain:token); the simulation engine debits them
 * as requests get signed. This page fans out across every rule so the
 * operator can spot a budget approaching its limit in one glance
 * rather than expanding each rule on /rules.
 */
export function Budgets() {
  const [rows, setRows] = useState<BudgetRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [nonce, setNonce] = useState(0);

  useEffect(() => {
    const client = getClient();
    if (!client) return;
    let mounted = true;
    setLoading(true);
    setError(null);
    (async () => {
      try {
        const rulesResp = await client.evm.rules.list();
        const all: BudgetRow[] = [];
        // The daemon has no /budgets endpoint, so we fan out per rule.
        // Rule count stays small in practice; parallelise the fetch so
        // the page renders in one round-trip's worth of latency.
        const lists = await Promise.all(
          rulesResp.rules.map((r) =>
            client.evm.rules
              .listBudgets(r.id)
              .then((b) => ({ rule: r, budgets: b }))
              .catch(() => ({ rule: r, budgets: [] as RuleBudget[] })),
          ),
        );
        for (const { rule, budgets } of lists) {
          for (const b of budgets) {
            all.push({ rule, budget: b });
          }
        }
        if (!mounted) return;
        // Sort hottest first so the operator's eye lands on what's
        // close to limit. Ties broken by rule name for stable order.
        all.sort((a, b) => {
          const pa = pctUsed(a.budget);
          const pb = pctUsed(b.budget);
          if (pa !== pb) return pb - pa;
          return a.rule.name.localeCompare(b.rule.name);
        });
        setRows(all);
      } catch (e) {
        if (mounted) setError(formatErr(e));
      } finally {
        if (mounted) setLoading(false);
      }
    })();
    return () => {
      mounted = false;
    };
  }, [nonce]);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Budgets"
        subtitle="Per-rule spend limits the simulation engine debits as requests sign."
        actions={
          <button
            type="button"
            onClick={() => setNonce((n) => n + 1)}
            className="rounded-md border border-ink-200 px-3 py-1 text-xs text-ink-700 hover:bg-ink-100"
          >
            Refresh
          </button>
        }
      />

      <Card>
        {loading && <Loading />}
        {error && <ErrorBanner msg={error} />}
        {rows &&
          (rows.length === 0 ? (
            <Empty msg="No budgets configured. Attach one to a rule via the CLI or templates to start tracking spend." />
          ) : (
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase text-ink-500">
                <tr>
                  <th className="py-1 pr-3 font-normal">Rule</th>
                  <th className="py-1 pr-3 font-normal">Unit</th>
                  <th className="py-1 pr-3 font-normal w-[20rem]">
                    Spent / Max
                  </th>
                  <th className="py-1 pr-3 font-normal">Tx count</th>
                  <th className="py-1 font-normal">Alert</th>
                </tr>
              </thead>
              <tbody>
                {rows.map(({ rule, budget }) => (
                  <BudgetRowView key={budget.id} rule={rule} budget={budget} />
                ))}
              </tbody>
            </table>
          ))}
      </Card>
    </div>
  );
}

function BudgetRowView({
  rule,
  budget,
}: {
  rule: Rule;
  budget: RuleBudget;
}) {
  const pct = pctUsed(budget);
  return (
    <tr className="border-t border-ink-100">
      <td className="py-1 pr-3">
        <div className="text-ink-900">{rule.name}</div>
        <div className="font-mono text-[11px] text-ink-500">{rule.id}</div>
      </td>
      <td className="py-1 pr-3 font-mono text-xs text-ink-700">
        {budget.unit}
      </td>
      <td className="py-1 pr-3">
        <ProgressBar pct={pct} />
        <div className="mt-0.5 font-mono text-[11px] text-ink-700">
          {budget.spent} / {budget.max_total}
        </div>
      </td>
      <td className="py-1 pr-3 font-mono text-xs text-ink-700">
        {budget.tx_count}
        {budget.max_tx_count > 0 ? ` / ${budget.max_tx_count}` : ""}
      </td>
      <td className="py-1">
        <AlertBadge pct={pct} threshold={budget.alert_pct} sent={budget.alert_sent} />
      </td>
    </tr>
  );
}

export function ProgressBar({ pct }: { pct: number }) {
  const clamped = Math.max(0, Math.min(100, pct));
  const tone =
    clamped >= 100
      ? "bg-red-500"
      : clamped >= 80
        ? "bg-yellow-500"
        : "bg-green-500";
  return (
    <div className="h-2 w-full overflow-hidden rounded-full bg-ink-100">
      <div
        className={`h-full ${tone} transition-all`}
        style={{ width: `${clamped}%` }}
      />
    </div>
  );
}

function AlertBadge({
  pct,
  threshold,
  sent,
}: {
  pct: number;
  threshold: number;
  sent: boolean;
}) {
  if (sent) return <Badge tone="red">alert sent · {threshold}%</Badge>;
  if (pct >= threshold) return <Badge tone="yellow">at {threshold}%</Badge>;
  return <span className="text-[11px] text-ink-500">{threshold}% threshold</span>;
}

// pctUsed returns spent/max_total * 100. Both fields are decimal strings
// from the daemon; we parse via Number which is fine for the magnitudes
// budgets carry (≤ 1e30-ish; way below MAX_SAFE_INTEGER for human-readable
// units like ETH / USDT). Returns 0 when max is zero / missing.
export function pctUsed(b: { spent: string; max_total: string }): number {
  const max = Number(b.max_total);
  if (!isFinite(max) || max <= 0) return 0;
  const spent = Number(b.spent);
  if (!isFinite(spent)) return 0;
  return (spent / max) * 100;
}

function formatErr(e: unknown): string {
  if (e instanceof APIError) return `HTTP ${e.statusCode}: ${e.message}`;
  if (e instanceof Error) return e.message;
  return String(e);
}
