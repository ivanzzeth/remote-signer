import { useState, type ReactNode } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { APIError, type BudgetEntry } from "remote-signer-client";
import {
  Badge,
  Card,
  ErrorBanner,
  Loading,
  PageHeader,
} from "../components/ui";
import { getClient } from "../lib/auth";
import { useApi } from "../lib/useApi";
import { BudgetForm } from "../components/BudgetForm";
import { ProgressBar, pctUsed } from "./Budgets";

/**
 * Per-budget detail view. Shows everything the row stores, plus
 * three admin gestures: edit limits, reset spend counters, delete.
 *
 * Simulation budgets are a special case here — the daemon refuses
 * POST creates for them, but PATCH/RESET/DELETE are still legal so
 * an operator can tighten an auto-created threshold or wipe spend
 * after a known false-positive.
 */
export function BudgetDetail() {
  const { id = "" } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [editing, setEditing] = useState(false);
  const [mutationError, setMutationError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const { data, loading, error, reload } = useApi(
    (c) => c.evm.budgets.get(id),
    [id],
  );

  async function reset() {
    if (!confirm("Reset spent + tx_count to zero?")) return;
    const c = getClient();
    if (!c) return;
    setBusy(true);
    setMutationError(null);
    try {
      await c.evm.budgets.reset(id);
      reload();
    } catch (e) {
      setMutationError(formatErr(e));
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    if (!confirm("Delete this budget? Simulation budgets will be auto-recreated on next outflow.")) return;
    const c = getClient();
    if (!c) return;
    setBusy(true);
    setMutationError(null);
    try {
      await c.evm.budgets.delete(id);
      navigate("/budgets");
    } catch (e) {
      setMutationError(formatErr(e));
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <Link
          to="/budgets"
          className="text-xs text-accent-600 hover:text-accent-500"
        >
          ← all budgets
        </Link>
        <button
          type="button"
          onClick={reload}
          className="rounded-md border border-ink-200 px-3 py-1 text-xs text-ink-700 hover:bg-ink-100"
        >
          Refresh
        </button>
      </div>

      {loading && <Loading />}
      {error && <ErrorBanner msg={error} />}
      {mutationError && <ErrorBanner msg={mutationError} />}

      {data && !editing && (
        <BudgetView
          budget={data}
          busy={busy}
          onEdit={() => setEditing(true)}
          onReset={reset}
          onDelete={remove}
        />
      )}

      {data && editing && (
        <Card title="Edit budget">
          <BudgetForm
            mode="edit"
            initial={data}
            onCancel={() => setEditing(false)}
            onSaved={() => {
              setEditing(false);
              reload();
            }}
          />
        </Card>
      )}
    </div>
  );
}

function BudgetView({
  budget,
  busy,
  onEdit,
  onReset,
  onDelete,
}: {
  budget: BudgetEntry;
  busy: boolean;
  onEdit: () => void;
  onReset: () => void;
  onDelete: () => void;
}) {
  const pct = pctUsed(budget);
  return (
    <>
      <PageHeader
        title={
          budget.kind === "rule"
            ? budget.rule_name || budget.rule_id
            : "Simulation budget"
        }
        subtitle={
          <span className="font-mono text-xs">
            {budget.kind === "simulation"
              ? `Signer ${budget.signer_address}`
              : `${budget.rule_type || "rule"} · ${budget.rule_id}`}
          </span>
        }
        actions={
          <Badge
            tone={budget.kind === "simulation" ? "yellow" : "neutral"}
          >
            {budget.kind}
          </Badge>
        }
      />

      <Card title="Usage">
        <div className="space-y-3">
          <ProgressBar pct={pct} />
          <div className="flex justify-between font-mono text-sm">
            <span className="text-ink-900" data-testid="budget-spent">
              {budget.spent}
            </span>
            <span className="text-ink-500" data-testid="budget-max-total">
              / {budget.max_total}
            </span>
          </div>
          <div className="text-xs text-ink-500">
            {pct.toFixed(1)}% of total ·{" "}
            <span data-testid="budget-tx-count">{budget.tx_count}</span>
            {budget.max_tx_count > 0 ? ` / ${budget.max_tx_count}` : ""} tx
          </div>
        </div>
      </Card>

      <Card title="Configuration">
        <FieldGrid>
          <Field label="ID">
            <Mono>{budget.id}</Mono>
          </Field>
          <Field label="Unit">
            <Mono>{budget.unit}</Mono>
          </Field>
          <Field label="Max total">
            <Mono>{budget.max_total}</Mono>
          </Field>
          <Field label="Max per tx">
            <Mono>{budget.max_per_tx || "-1"}</Mono>
          </Field>
          {budget.max_tx_count > 0 && (
            <Field label="Max tx count">
              <Mono>{budget.max_tx_count}</Mono>
            </Field>
          )}
          <Field label="Alert at">
            <Mono>{budget.alert_pct}%</Mono>
          </Field>
          <Field label="Alert sent">
            <Mono>{budget.alert_sent ? "yes" : "no"}</Mono>
          </Field>
          <Field label="Created">
            <Mono>{budget.created_at}</Mono>
          </Field>
          <Field label="Updated">
            <Mono>{budget.updated_at}</Mono>
          </Field>
        </FieldGrid>
      </Card>

      <Card title="Actions">
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={onEdit}
            disabled={busy}
            className="rounded-md bg-accent-500 px-3 py-1.5 text-sm font-medium text-white hover:bg-accent-600 disabled:opacity-50"
            data-testid="budget-edit"
          >
            Edit limits
          </button>
          <button
            type="button"
            onClick={onReset}
            disabled={busy}
            className="rounded-md border border-ink-300 px-3 py-1.5 text-sm text-ink-700 hover:bg-ink-100 disabled:opacity-50"
            data-testid="budget-reset"
          >
            Reset spend
          </button>
          <button
            type="button"
            onClick={onDelete}
            disabled={busy}
            className="rounded-md border border-red-300 px-3 py-1.5 text-sm text-red-700 hover:bg-red-50 disabled:opacity-50"
            data-testid="budget-delete"
          >
            Delete
          </button>
        </div>
      </Card>
    </>
  );
}

function FieldGrid({ children }: { children: ReactNode }) {
  return <dl className="divide-y divide-ink-100 text-sm">{children}</dl>;
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[140px_1fr] gap-4 py-2">
      <dt className="text-ink-500">{label}</dt>
      <dd className="min-w-0 break-all text-ink-900">{children}</dd>
    </div>
  );
}

function Mono({ children }: { children: ReactNode }) {
  return (
    <span className="font-mono text-xs tabular-nums text-ink-900">
      {children}
    </span>
  );
}

function formatErr(e: unknown): string {
  if (e instanceof APIError) return `HTTP ${e.statusCode}: ${e.message}`;
  if (e instanceof Error) return e.message;
  return String(e);
}
