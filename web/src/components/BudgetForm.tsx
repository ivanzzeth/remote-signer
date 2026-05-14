import { useEffect, useState } from "react";
import {
  APIError,
  type BudgetEntry,
  type Rule,
} from "remote-signer-client";
import { getClient } from "../lib/auth";

interface FormState {
  rule_id: string;
  unit: string;
  max_total: string;
  max_per_tx: string;
  max_tx_count: string;
  alert_pct: string;
  spent: string;
  tx_count: string;
}

const ZERO = {
  rule_id: "",
  unit: "",
  max_total: "",
  max_per_tx: "-1",
  max_tx_count: "0",
  alert_pct: "80",
  spent: "0",
  tx_count: "0",
};

/**
 * Shared create/edit form for budgets. Create mode lets the operator
 * pick a rule from a dropdown (loaded via evm.rules.list); edit mode
 * pins rule_id + unit (the row's identity, immutable) and only exposes
 * the mutable limit fields.
 *
 * Returns the new/updated row via onSaved so callers don't have to
 * refetch — the parent page already knows enough to swap state.
 */
export function BudgetForm({
  mode,
  initial,
  onCancel,
  onSaved,
}: {
  mode: "create" | "edit";
  initial?: BudgetEntry;
  onCancel: () => void;
  onSaved: (saved: BudgetEntry | null) => void;
}) {
  const [state, setState] = useState<FormState>(() =>
    initial
      ? {
          rule_id: initial.rule_id,
          unit: initial.unit,
          max_total: initial.max_total,
          max_per_tx: initial.max_per_tx,
          max_tx_count: String(initial.max_tx_count),
          alert_pct: String(initial.alert_pct),
          spent: initial.spent,
          tx_count: String(initial.tx_count),
        }
      : ZERO,
  );
  const [rules, setRules] = useState<Rule[] | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const isEdit = mode === "edit";

  useEffect(() => {
    if (isEdit) return;
    const c = getClient();
    if (!c) return;
    let mounted = true;
    c.evm.rules
      .list()
      .then((r) => {
        if (!mounted) return;
        // Hide sim:* — the server refuses POST against those anyway,
        // so offering them in the dropdown would just produce 403s.
        setRules(r.rules.filter((x) => !x.id.startsWith("sim:")));
      })
      .catch(() => mounted && setRules([]));
    return () => {
      mounted = false;
    };
  }, [isEdit]);

  function set<K extends keyof FormState>(k: K, v: FormState[K]) {
    setState((s) => ({ ...s, [k]: v }));
  }

  const selectedRule = rules?.find((r) => r.id === state.rule_id) || null;
  const meteringWarning =
    !isEdit &&
    selectedRule &&
    !ruleHasBudgetMetering(selectedRule)
      ? "This rule has no budget_metering config — the row will be created but won't be debited by any sign request."
      : null;

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    const c = getClient();
    if (!c) return;
    setSubmitting(true);
    setError(null);
    try {
      if (isEdit && initial) {
        const updated = await c.evm.budgets.update(initial.id, {
          max_total: state.max_total,
          max_per_tx: state.max_per_tx,
          max_tx_count: parseInt(state.max_tx_count, 10) || 0,
          alert_pct: parseInt(state.alert_pct, 10) || 0,
          spent: state.spent,
          tx_count: parseInt(state.tx_count, 10) || 0,
        });
        onSaved(updated);
      } else {
        const created = await c.evm.budgets.create({
          rule_id: state.rule_id.trim(),
          unit: state.unit.trim(),
          max_total: state.max_total,
          max_per_tx: state.max_per_tx || undefined,
          max_tx_count: parseInt(state.max_tx_count, 10) || 0,
          alert_pct: parseInt(state.alert_pct, 10) || 80,
        });
        onSaved(created);
      }
    } catch (ex) {
      setError(formatErr(ex));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form onSubmit={submit} className="space-y-4">
      {error && (
        <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-800">
          {error}
        </div>
      )}

      {!isEdit && (
        <>
          <Row label="Rule" required>
            {rules === null ? (
              <span className="text-sm text-ink-500">Loading rules…</span>
            ) : (
              <select
                value={state.rule_id}
                onChange={(e) => set("rule_id", e.target.value)}
                required
                className="w-full rounded-md border border-ink-300 px-2 py-1 text-sm"
                data-testid="budget-form-rule"
              >
                <option value="">— select a rule —</option>
                {rules.map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.name} ({r.type})
                  </option>
                ))}
              </select>
            )}
          </Row>
          <Row label="Unit" required help="e.g. 1:native, 1:0xA0b8…">
            <input
              type="text"
              value={state.unit}
              onChange={(e) => set("unit", e.target.value)}
              required
              className="w-full rounded-md border border-ink-300 px-2 py-1 font-mono text-sm"
              placeholder="1:native"
              data-testid="budget-form-unit"
            />
          </Row>
        </>
      )}

      {isEdit && initial && (
        <Row label="Identity" help="Immutable — rule + unit pin the row's hash.">
          <div className="font-mono text-xs text-ink-700">
            {initial.rule_id} · {initial.unit}
          </div>
        </Row>
      )}

      <Row
        label="Max total"
        required
        help='"-1" = unlimited; integer wei or token base units.'
      >
        <input
          type="text"
          value={state.max_total}
          onChange={(e) => set("max_total", e.target.value)}
          required
          className="w-full rounded-md border border-ink-300 px-2 py-1 font-mono text-sm"
          placeholder="1000000000000000000"
          data-testid="budget-form-max-total"
        />
      </Row>
      <Row label="Max per tx">
        <input
          type="text"
          value={state.max_per_tx}
          onChange={(e) => set("max_per_tx", e.target.value)}
          className="w-full rounded-md border border-ink-300 px-2 py-1 font-mono text-sm"
          placeholder="-1"
          data-testid="budget-form-max-per-tx"
        />
      </Row>
      <Row label="Max tx count" help="0 = unlimited">
        <input
          type="number"
          value={state.max_tx_count}
          onChange={(e) => set("max_tx_count", e.target.value)}
          min={0}
          className="w-full rounded-md border border-ink-300 px-2 py-1 font-mono text-sm"
        />
      </Row>
      <Row label="Alert at %" help="0–100; daemon notifies once when spent ≥ this">
        <input
          type="number"
          value={state.alert_pct}
          onChange={(e) => set("alert_pct", e.target.value)}
          min={0}
          max={100}
          className="w-full rounded-md border border-ink-300 px-2 py-1 font-mono text-sm"
        />
      </Row>

      {isEdit && (
        <>
          <Row label="Spent" help="Override the running counter">
            <input
              type="text"
              value={state.spent}
              onChange={(e) => set("spent", e.target.value)}
              className="w-full rounded-md border border-ink-300 px-2 py-1 font-mono text-sm"
            />
          </Row>
          <Row label="Tx count">
            <input
              type="number"
              value={state.tx_count}
              onChange={(e) => set("tx_count", e.target.value)}
              min={0}
              className="w-full rounded-md border border-ink-300 px-2 py-1 font-mono text-sm"
            />
          </Row>
        </>
      )}

      {meteringWarning && (
        <div className="rounded-md border border-yellow-200 bg-yellow-50 px-3 py-2 text-xs text-yellow-800">
          {meteringWarning}
        </div>
      )}

      <div className="flex gap-2 pt-2">
        <button
          type="submit"
          disabled={submitting}
          className="rounded-md bg-accent-500 px-3 py-1.5 text-sm font-medium text-white hover:bg-accent-600 disabled:opacity-50"
          data-testid="budget-form-submit"
        >
          {isEdit ? "Save" : "Create"}
        </button>
        <button
          type="button"
          onClick={onCancel}
          className="rounded-md border border-ink-200 px-3 py-1.5 text-sm text-ink-700 hover:bg-ink-100"
        >
          Cancel
        </button>
      </div>
    </form>
  );
}

function Row({
  label,
  required,
  help,
  children,
}: {
  label: string;
  required?: boolean;
  help?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="grid grid-cols-[140px_1fr] gap-4">
      <label className="pt-1 text-sm text-ink-700">
        {label}
        {required && <span className="ml-1 text-red-500">*</span>}
      </label>
      <div>
        {children}
        {help && <div className="mt-1 text-[11px] text-ink-500">{help}</div>}
      </div>
    </div>
  );
}

// ruleHasBudgetMetering peeks at the rule's config to tell whether the
// daemon will ever actually debit a budget for it. Loosely tested — a
// false negative just shows the warning; false positives leave it
// silent (acceptable).
function ruleHasBudgetMetering(rule: Rule): boolean {
  const cfg = rule.config as Record<string, unknown> | undefined;
  if (!cfg) return false;
  const metering = cfg["budget_metering"] as
    | { method?: string }
    | undefined;
  if (metering?.method && metering.method !== "" && metering.method !== "none") {
    return true;
  }
  return false;
}

function formatErr(e: unknown): string {
  if (e instanceof APIError) return `HTTP ${e.statusCode}: ${e.message}`;
  if (e instanceof Error) return e.message;
  return String(e);
}
