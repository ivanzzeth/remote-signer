import { useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { APIError, type BudgetEntry } from "remote-signer-client";
import {
  Badge,
  Card,
  Empty,
  ErrorBanner,
  Loading,
  PageHeader,
  shorten,
} from "../components/ui";
import { useApi } from "../lib/useApi";
import { BudgetForm } from "../components/BudgetForm";

/**
 * Operator budgets overview. Single GET /api/v1/evm/budgets call: the
 * daemon returns every budget row annotated with kind ("rule" or
 * "simulation"), so we can group them without fanning out per-rule and
 * — more importantly — without losing the synthetic simulation budgets
 * (rule_id "sim:0x...") that the per-rule listing can't see at all.
 *
 * Two sections rendered in priority order: rule budgets first (they
 * back a configured policy and are the operator's primary lever),
 * simulation budgets second (system-level guardrails the fallback rule
 * accrues against signers under it).
 */
export function Budgets() {
  const [creating, setCreating] = useState(false);
  const [searchParams] = useSearchParams();
  // signer filter — set when arriving from a sign request detail page's
  // simulation-approval link, so the operator lands on the row that
  // approved their request without scanning.
  const signerFilter = (searchParams.get("signer") || "").toLowerCase();

  const { data, loading, error, reload } = useApi(
    (c) => c.evm.budgets.list(),
    [],
  );

  const entries = data?.budgets ?? [];
  const filtered = signerFilter
    ? entries.filter((e) =>
        (e.signer_address || "").toLowerCase() === signerFilter,
      )
    : entries;
  const sortedByHot = [...filtered].sort(
    (a, b) => pctUsed(b) - pctUsed(a) || compareName(a, b),
  );
  const ruleRows = sortedByHot.filter((e) => e.kind === "rule");
  const simRows = sortedByHot.filter((e) => e.kind === "simulation");

  return (
    <div className="space-y-6">
      <PageHeader
        title="Budgets"
        subtitle="Spend limits the daemon debits as it signs — by rule and by simulation fallback."
        actions={
          <div className="flex gap-2">
            <button
              type="button"
              onClick={reload}
              className="rounded-md border border-ink-200 px-3 py-1 text-xs text-ink-700 hover:bg-ink-100"
            >
              Refresh
            </button>
            <button
              type="button"
              onClick={() => setCreating((v) => !v)}
              className="rounded-md bg-accent-500 px-3 py-1 text-xs font-medium text-white hover:bg-accent-600"
              data-testid="budget-new"
            >
              {creating ? "Cancel" : "New budget"}
            </button>
          </div>
        }
      />

      {signerFilter && (
        <div className="flex items-center gap-2 rounded-md border border-ink-200 bg-white px-3 py-2 text-xs text-ink-700">
          <span>
            Filtered by signer{" "}
            <span className="font-mono">{shorten(signerFilter)}</span>
          </span>
          <Link
            to="/budgets"
            className="ml-auto text-accent-600 hover:text-accent-500"
          >
            clear
          </Link>
        </div>
      )}

      {creating && (
        <Card title="New budget">
          <BudgetForm
            mode="create"
            onCancel={() => setCreating(false)}
            onSaved={() => {
              setCreating(false);
              reload();
            }}
          />
        </Card>
      )}

      {loading && <Loading />}
      {error && <ErrorBanner msg={error} />}

      {data && filtered.length === 0 && (
        <Card>
          <Empty
            msg={
              signerFilter
                ? "No budgets match this signer filter yet — clear the filter to see all rows."
                : "No budgets recorded. Create one with the New button, or wait for a rule/simulation to trigger one."
            }
          />
        </Card>
      )}

      {ruleRows.length > 0 && (
        <Card title="Rule budgets">
          <BudgetTable rows={ruleRows} showRule />
        </Card>
      )}

      {simRows.length > 0 && (
        <Card
          title="Simulation budgets"
          actions={
            <span className="text-[11px] text-ink-500">
              Created by the simulation fallback; tracked per signer.
            </span>
          }
        >
          <BudgetTable rows={simRows} showRule={false} />
        </Card>
      )}
    </div>
  );
}

function BudgetTable({
  rows,
  showRule,
}: {
  rows: BudgetEntry[];
  showRule: boolean;
}) {
  return (
    <table className="w-full text-left text-sm">
      <thead className="text-xs uppercase text-ink-500">
        <tr>
          <th className="py-1 pr-3 font-normal">
            {showRule ? "Rule" : "Signer"}
          </th>
          <th className="py-1 pr-3 font-normal">Unit</th>
          <th className="py-1 pr-3 font-normal w-[20rem]">Spent / Max</th>
          <th className="py-1 pr-3 font-normal">Tx count</th>
          <th className="py-1 font-normal">Alert</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((b) => (
          <BudgetRowView key={b.id} entry={b} />
        ))}
      </tbody>
    </table>
  );
}

function BudgetRowView({ entry }: { entry: BudgetEntry }) {
  const navigate = useNavigate();
  const pct = pctUsed(entry);
  return (
    <tr
      className="cursor-pointer border-t border-ink-100 hover:bg-ink-50"
      onClick={() => navigate(`/budgets/${encodeURIComponent(entry.id)}`)}
      data-testid={`budget-row-${entry.id}`}
    >
      <td className="py-1 pr-3 align-top">
        <PrimaryCell entry={entry} />
      </td>
      <td className="py-1 pr-3 font-mono text-xs text-ink-700">
        {entry.unit}
      </td>
      <td className="py-1 pr-3">
        <ProgressBar pct={pct} />
        <div className="mt-0.5 font-mono text-[11px] text-ink-700">
          {entry.spent} / {entry.max_total}
        </div>
      </td>
      <td className="py-1 pr-3 font-mono text-xs text-ink-700">
        {entry.tx_count}
        {entry.max_tx_count > 0 ? ` / ${entry.max_tx_count}` : ""}
      </td>
      <td className="py-1">
        <AlertBadge
          pct={pct}
          threshold={entry.alert_pct}
          sent={entry.alert_sent}
        />
      </td>
    </tr>
  );
}

function PrimaryCell({ entry }: { entry: BudgetEntry }) {
  if (entry.kind === "rule" && entry.rule_id && !entry.rule_id.startsWith("sim:")) {
    return (
      <>
        <Link
          to="/rules"
          className="text-ink-900 hover:text-accent-600 hover:underline"
          onClick={(e) => e.stopPropagation()}
        >
          {entry.rule_name || entry.rule_id}
        </Link>
        <div className="font-mono text-[11px] text-ink-500">
          {entry.rule_type ? `${entry.rule_type} · ` : ""}
          {entry.rule_id}
        </div>
      </>
    );
  }
  if (entry.kind === "rule") {
    return (
      <>
        <div className="text-ink-900">{entry.rule_name || entry.rule_id}</div>
        <div className="font-mono text-[11px] text-ink-500">
          {entry.rule_type ? `${entry.rule_type} · ` : ""}
          {entry.rule_id}
        </div>
      </>
    );
  }
  // Simulation budget — show signer address prominently.
  return (
    <>
      <div className="font-mono text-xs text-ink-900">
        {entry.signer_address ? shorten(entry.signer_address) : entry.rule_id}
      </div>
      <div className="font-mono text-[11px] text-ink-500">
        simulation fallback
      </div>
    </>
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
  return (
    <span className="text-[11px] text-ink-500">{threshold}% threshold</span>
  );
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

function compareName(a: BudgetEntry, b: BudgetEntry): number {
  const an = a.kind === "rule" ? a.rule_name || a.rule_id : a.signer_address || a.rule_id;
  const bn = b.kind === "rule" ? b.rule_name || b.rule_id : b.signer_address || b.rule_id;
  return an.localeCompare(bn);
}

// Kept for backwards-compat with code that imported it before this
// rewrite; consumers now read via the SDK directly. Tag as unused-safe.
export function formatErr(e: unknown): string {
  if (e instanceof APIError) return `HTTP ${e.statusCode}: ${e.message}`;
  if (e instanceof Error) return e.message;
  return String(e);
}
