import { Fragment, useState } from "react";
import {
  APIError,
  type CreateRuleRequest,
  type Rule,
  type RuleMode,
  type RuleType,
  type RuleVariableDef,
  type ValidateRuleResponse,
} from "remote-signer-client";
import { AppliedToPicker } from "../components/AppliedToPicker";
import {
  Badge,
  Card,
  CodeBlock,
  Empty,
  ErrorBanner,
  Loading,
  PageHeader,
} from "../components/ui";
import { getClient } from "../lib/auth";
import { useApi } from "../lib/useApi";

const RULE_TYPES: RuleType[] = [
  "evm_address_list",
  "evm_contract_method",
  "evm_value_limit",
  "evm_solidity_expression",
  "evm_js",
  "evm_dynamic_blocklist",
  "evm_internal_transfer",
  "signer_restriction",
  "chain_restriction",
  "sign_type_restriction",
  "message_pattern",
];

const SIGN_TYPES = [
  "hash",
  "raw_message",
  "eip191",
  "personal",
  "typed_data",
  "transaction",
] as const;

// Per-type starter config the daemon validates against. The typed editor
// (see RuleConfigEditor below) renders fields keyed off the same shape.
const ZERO_ADDR = "0x0000000000000000000000000000000000000000";
const CONFIG_TEMPLATES: Record<RuleType, Record<string, unknown>> = {
  evm_address_list: { addresses: [ZERO_ADDR] },
  evm_contract_method: {
    contract_address: ZERO_ADDR,
    method_signatures: ["transfer(address,uint256)"],
  },
  evm_value_limit: { max_value: "1000000000000000000" },
  evm_solidity_expression: { expression: "value < 1e18" },
  evm_js: {
    script:
      "// Receives `input` (the sign request) and must export validate(input).\n// Return { valid: bool, reason?: string }.\nfunction validate(input) {\n  return { valid: true };\n}",
    sign_type_filter: "",
  },
  evm_dynamic_blocklist: { sources: [] },
  evm_internal_transfer: { signer_addresses: [ZERO_ADDR] },
  signer_restriction: { signer_addresses: [ZERO_ADDR] },
  chain_restriction: { chain_ids: ["1"] },
  sign_type_restriction: { sign_types: ["personal"] },
  message_pattern: { pattern: "^0x[0-9a-fA-F]+$" },
};

/**
 * Lists every rule (whitelist/blocklist) registered on the daemon. This
 * is the operator's first stop when a sign request was unexpectedly
 * denied or auto-approved — the rule set is the source of truth.
 *
 * Mutations: create (with per-type config template), toggle enabled,
 * delete. The create form deliberately keeps `config` as a raw JSON
 * textarea — each rule type has a different config schema and the daemon
 * already validates on PUT, so a generic editor is cheaper than seven
 * typed forms without sacrificing safety.
 */
export function Rules() {
  const { data, loading, error, reload } = useApi((c) => c.evm.rules.list());
  const [mutationError, setMutationError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [editing, setEditing] = useState<string | null>(null);
  const [batchValidating, setBatchValidating] = useState(false);
  const [batchValidationResults, setBatchValidationResults] = useState<ValidateRuleResponse[] | null>(null);

  async function batchValidate() {
    const client = getClient();
    if (!client) return;
    setBatchValidationResults(null);
    setMutationError(null);
    setBatchValidating(true);
    try {
      const resp = await client.evm.rules.batchValidate();
      setBatchValidationResults(resp.results);
    } catch (e) {
      setMutationError(formatMutationError(e));
    } finally {
      setBatchValidating(false);
    }
  }

  async function create(input: CreateRuleRequest) {
    const client = getClient();
    if (!client) return;
    setMutationError(null);
    try {
      await client.evm.rules.create(input);
      setShowCreate(false);
      reload();
    } catch (e) {
      setMutationError(formatMutationError(e));
    }
  }

  async function approve(id: string) {
    const client = getClient();
    if (!client) return;
    setBusy(id);
    setMutationError(null);
    try {
      await client.evm.rules.approve(id);
      reload();
    } catch (e) {
      setMutationError(formatMutationError(e));
    } finally {
      setBusy(null);
    }
  }

  async function reject(id: string) {
    const reason = prompt("Reject this rule — reason?");
    if (reason === null) return; // user cancelled
    const client = getClient();
    if (!client) return;
    setBusy(id);
    setMutationError(null);
    try {
      await client.evm.rules.reject(id, reason);
      reload();
    } catch (e) {
      setMutationError(formatMutationError(e));
    } finally {
      setBusy(null);
    }
  }

  async function update(
    id: string,
    patch: { name?: string; description?: string; config?: Record<string, unknown>; variables?: Record<string, string>; matrix?: Record<string, any>[]; priority?: number; budget_period?: string; applied_to?: string[] },
  ) {
    const client = getClient();
    if (!client) return;
    setBusy(id);
    setMutationError(null);
    try {
      await client.evm.rules.update(id, patch);
      setEditing(null);
      reload();
    } catch (e) {
      setMutationError(formatMutationError(e));
    } finally {
      setBusy(null);
    }
  }

  async function toggle(id: string, currentEnabled: boolean) {
    const client = getClient();
    if (!client) return;
    setBusy(id);
    setMutationError(null);
    try {
      await client.evm.rules.toggle(id, !currentEnabled);
      reload();
    } catch (e) {
      setMutationError(formatMutationError(e));
    } finally {
      setBusy(null);
    }
  }

  async function destroy(id: string, name: string) {
    if (!confirm(`Delete rule "${name}"? This cannot be undone.`)) return;
    const client = getClient();
    if (!client) return;
    setBusy(id);
    setMutationError(null);
    try {
      await client.evm.rules.delete(id);
      reload();
    } catch (e) {
      setMutationError(formatMutationError(e));
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Rules"
        subtitle="EVM whitelist/blocklist policies that gate sign requests."
        actions={
          <>
            <button
              type="button"
              onClick={() => setShowCreate((s) => !s)}
              className="rounded-md bg-accent-500 px-3 py-1 text-xs font-medium text-white hover:bg-accent-600"
            >
              {showCreate ? "Cancel" : "New rule"}
            </button>
            <button
              type="button"
              onClick={reload}
              className="rounded-md border border-ink-200 px-3 py-1 text-xs text-ink-700 hover:bg-ink-100"
            >
              Refresh
            </button>
            <button
              type="button"
              onClick={batchValidate}
              disabled={batchValidating}
              className="rounded-md border border-ink-200 px-3 py-1 text-xs text-ink-700 hover:bg-ink-100 disabled:opacity-50"
            >
              {batchValidating ? "Validating…" : "Validate all"}
            </button>
          </>
        }
      />

      {mutationError && <ErrorBanner msg={mutationError} />}

      {batchValidationResults && (
        <Card title="Batch validation results">
          <div className="space-y-3">
            <div className="flex gap-3 text-xs text-ink-600">
              <span className="text-green-700">
                {batchValidationResults.filter((r) => r.valid).length} passed
              </span>
              {batchValidationResults.filter((r) => !r.valid).length > 0 && (
                <span className="text-red-700">
                  {batchValidationResults.filter((r) => !r.valid).length} failed
                </span>
              )}
              <span>{batchValidationResults.length} total</span>
            </div>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setBatchValidationResults(null)}
                className="rounded-md border border-ink-200 px-2 py-0.5 text-xs text-ink-700 hover:bg-ink-100"
              >
                Dismiss
              </button>
            </div>
            {batchValidationResults.map((r, i) => (
              <div key={i} className="flex items-start gap-2 text-xs">
                <span className={r.valid ? "mt-0.5 text-green-600" : "mt-0.5 text-red-600"}>
                  {r.valid ? "✓" : "✗"}
                </span>
                <div className="flex-1">
                  <div className="text-ink-700">{r.rule_name}</div>
                  {!r.valid && r.error && (
                    <div className="text-red-500">{r.error}</div>
                  )}
                  {r.results && r.results.length > 0 && (
                    <div className="mt-1 space-y-1 pl-4">
                      {r.results.map((tc, j) => (
                        <div key={j} className="flex items-center gap-1.5 text-[11px]">
                          <span className={tc.passed ? "text-green-600" : "text-red-600"}>
                            {tc.passed ? "✓" : "✗"}
                          </span>
                          <span className="text-ink-600">{tc.name}</span>
                          {!tc.passed && tc.reason && (
                            <span className="text-red-400">— {tc.reason}</span>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}

      {showCreate && <CreateForm onSubmit={create} />}

      <Card>
        {loading && <Loading />}
        {error && <ErrorBanner msg={error} />}
        {data &&
          (data.rules.length === 0 ? (
            <Empty msg="No rules defined. Sign requests will be evaluated against the daemon's default policy (manual approval if configured)." />
          ) : (
            <table className="w-full text-left text-sm" style={{ tableLayout: "fixed" }}>
              <thead className="text-xs uppercase text-ink-500">
                <tr>
                  <th className="py-1 pr-3 font-normal">Name</th>
                  <th className="py-1 pr-1 w-10 text-center font-normal">#</th>
                  <th className="py-1 pr-3 font-normal">Type</th>
                  <th className="py-1 pr-3 font-normal">Mode</th>
                  <th className="py-1 pr-3 font-normal">Source</th>
                  <th className="py-1 pr-3 font-normal">Status</th>
                  <th className="py-1 font-normal">Actions</th>
                </tr>
              </thead>
              <tbody>
                {data.rules.map((r) => (
                  <Fragment key={r.id}>
                  <tr
                    className="cursor-pointer border-t border-ink-100 hover:bg-ink-50"
                    onClick={() =>
                      setExpanded((id) => (id === r.id ? null : r.id))
                    }
                  >
                    <td className="py-1 pr-3">
                      <div className="text-ink-900">{r.name}</div>
                      <div className="font-mono text-[11px] text-ink-500">
                        {r.id}
                      </div>
                    </td>
                    <td className="py-1 pr-3 w-10 text-center font-mono text-xs text-ink-500">
                      {r.priority}
                    </td>
                    <td className="py-1 pr-3 font-mono text-xs text-ink-700">
                      {r.type}
                    </td>
                    <td className="py-1 pr-3">
                      <Badge tone={r.mode === "whitelist" ? "green" : "red"}>
                        {r.mode}
                      </Badge>
                    </td>
                    <td className="py-1 pr-3 text-xs text-ink-500">
                      {r.source}
                    </td>
                    <td className="py-1 pr-3">
                      <div className="flex flex-col gap-1">
                        <Badge tone={r.enabled ? "green" : "neutral"}>
                          {r.enabled ? "enabled" : "disabled"}
                        </Badge>
                        {r.status && r.status !== "active" && (
                          <Badge
                            tone={
                              r.status === "pending_approval"
                                ? "yellow"
                                : "red"
                            }
                          >
                            {r.status}
                          </Badge>
                        )}
                      </div>
                    </td>
                    <td className="py-1">
                      <div
                        className="flex flex-wrap gap-2"
                        onClick={(e) => e.stopPropagation()}
                      >
                        {r.status === "pending_approval" ? (
                          <>
                            <button
                              type="button"
                              disabled={busy === r.id}
                              onClick={() => approve(r.id)}
                              className="rounded-md bg-accent-500 px-2 py-0.5 text-xs font-medium text-white hover:bg-accent-600 disabled:opacity-50"
                            >
                              Approve
                            </button>
                            <button
                              type="button"
                              disabled={busy === r.id}
                              onClick={() => reject(r.id)}
                              className="rounded-md border border-red-200 px-2 py-0.5 text-xs text-red-700 hover:bg-red-50 disabled:opacity-50"
                            >
                              Reject
                            </button>
                          </>
                        ) : null}
                        <button
                          type="button"
                          disabled={busy === r.id || r.immutable}
                          onClick={() => toggle(r.id, r.enabled)}
                          title={
                            r.immutable
                              ? "immutable rule (set in config.yaml)"
                              : ""
                          }
                          className="rounded-md border border-ink-200 px-2 py-0.5 text-xs text-ink-700 hover:bg-ink-100 disabled:opacity-50"
                        >
                          {r.enabled ? "Disable" : "Enable"}
                        </button>
                        <button
                          type="button"
                          disabled={busy === r.id || r.immutable}
                          onClick={() => {
                            if (editing === r.id) {
                              setEditing(null);
                            } else {
                              setEditing(r.id);
                              // Force the detail panel open so the form
                              // renders even if the operator never clicked
                              // the row to expand it.
                              setExpanded(r.id);
                            }
                          }}
                          className="rounded-md border border-ink-200 px-2 py-0.5 text-xs text-ink-700 hover:bg-ink-100 disabled:opacity-50"
                        >
                          {editing === r.id ? "Cancel" : "Edit"}
                        </button>
                        <button
                          type="button"
                          disabled={busy === r.id || r.immutable}
                          onClick={() => destroy(r.id, r.name)}
                          className="rounded-md border border-red-200 px-2 py-0.5 text-xs text-red-700 hover:bg-red-50 disabled:opacity-50"
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                  {expanded === r.id && (
                    <tr className="border-t border-ink-100 bg-ink-50">
                      <td colSpan={6} className="min-w-0 overflow-x-auto px-4 py-3">
                        <RuleDetailPanel
                          rule={r}
                          editing={editing === r.id}
                          onCancelEdit={() => setEditing(null)}
                          onSave={(patch) => update(r.id, patch)}
                          busy={busy === r.id}
                        />
                      </td>
                    </tr>
                  )}
                  </Fragment>
                ))}
              </tbody>
            </table>
          ))}
      </Card>
    </div>
  );
}

function RuleDetailPanel({
  rule,
  editing,
  onCancelEdit,
  onSave,
  busy,
}: {
  rule: Rule;
  editing: boolean;
  onCancelEdit: () => void;
  onSave: (patch: {
    name?: string;
    description?: string;
    config?: Record<string, unknown>;
    variables?: Record<string, string>;
    matrix?: Record<string, any>[];
    priority?: number;
  }) => void;
  busy: boolean;
}) {
  const budgets = useApi(
    (c) => c.evm.rules.listBudgets(rule.id),
    [rule.id],
  );
  const signersApi = useApi((c) => c.evm.signers.list(), [editing]);
  const [name, setName] = useState(rule.name);
  const [description, setDescription] = useState(rule.description ?? "");
  const [editPriority, setEditPriority] = useState(rule.priority);
  const [editBudgetPeriod, setEditBudgetPeriod] = useState(rule.budget_period || "");
  const [editAppliedTo, setEditAppliedTo] = useState(rule.applied_to || []);
  const [config, setConfig] = useState<Record<string, unknown>>(() => ({
    ...rule.config,
  }));
  const [advanced, setAdvanced] = useState(false);
  const [rawJson, setRawJson] = useState(() =>
    JSON.stringify(rule.config, null, 2),
  );
  const [editVars, setEditVars] = useState<Record<string, string>>(() =>
    (rule.variables && Object.keys(rule.variables).length > 0) ? { ...rule.variables } : {},
  );
  const [editMatrix, setEditMatrix] = useState(() =>
    rule.matrix && Array.isArray(rule.matrix) ? JSON.stringify(rule.matrix, null, 2) : "",
  );
  const [showVarsEditor, setShowVarsEditor] = useState(false);
  const [showMatrixEditor, setShowMatrixEditor] = useState(false);
  const [parseError, setParseError] = useState<string | null>(null);
  const [validating, setValidating] = useState(false);
  const [validationResult, setValidationResult] = useState<ValidateRuleResponse | null>(null);
  const [validationError, setValidationError] = useState<string | null>(null);

  async function validateRule() {
    setValidationResult(null);
    setValidationError(null);
    const c = getClient();
    if (!c) return;
    setValidating(true);
    try {
      const resp = await c.evm.rules.validate(rule.id);
      setValidationResult(resp);
    } catch (e) {
      setValidationError(formatMutationError(e));
    } finally {
      setValidating(false);
    }
  }

  function save() {
    setParseError(null);
    let payload: Record<string, unknown> = config;
    if (advanced) {
      try {
        payload = JSON.parse(rawJson);
      } catch (e) {
        setParseError(e instanceof Error ? e.message : "invalid JSON");
        return;
      }
    }
    const patch: {
      name?: string;
      description?: string;
      config?: Record<string, unknown>;
      variables?: Record<string, string>;
      matrix?: Record<string, any>[];
      priority?: number;
      budget_period?: string;
      applied_to?: string[];
    } = {
      name: name.trim(),
      description: description.trim(),
      config: payload,
    };
    if (Object.keys(editVars).length > 0) {
      patch.variables = { ...editVars };
    } else if (rule.variables && Object.keys(rule.variables).length > 0) {
      patch.variables = {};
    }
    if (editMatrix.trim()) {
      try {
        patch.matrix = JSON.parse(editMatrix);
      } catch (e) {
        setParseError("Matrix: " + (e instanceof Error ? e.message : "invalid JSON"));
        return;
      }
    } else if (rule.matrix && Array.isArray(rule.matrix) && rule.matrix.length > 0) {
      patch.matrix = [];
    }
    if (editPriority !== rule.priority) {
      patch.priority = editPriority;
    }
    if (editBudgetPeriod !== rule.budget_period) {
      patch.budget_period = editBudgetPeriod || undefined;
    }
    if (JSON.stringify(editAppliedTo) !== JSON.stringify(rule.applied_to)) {
      patch.applied_to = editAppliedTo;
    }
    onSave(patch);
  }

  return (
    <div className="space-y-4" onClick={(e) => e.stopPropagation()}>
      {editing ? (
        <div className="space-y-3">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-ink-500">
            Edit rule
          </h3>
          <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
            <div>
              <label className="mb-1 block text-[11px] uppercase tracking-wide text-ink-500">
                Name
              </label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="w-full rounded-md border border-ink-300 px-2 py-1 text-sm"
              />
            </div>
            <div>
              <label className="mb-1 block text-[11px] uppercase tracking-wide text-ink-500">
                Priority
              </label>
              <input
                type="number"
                min={1}
                value={editPriority}
                onChange={(e) => setEditPriority(parseInt(e.target.value, 10) || 1)}
                className="w-full rounded-md border border-ink-300 px-2 py-1 text-sm"
              />
            </div>
            <div>
              <label className="mb-1 block text-[11px] uppercase tracking-wide text-ink-500">
                Budget Renewal
              </label>
              <input
                type="text"
                placeholder="24h"
                value={editBudgetPeriod}
                onChange={(e) => setEditBudgetPeriod(e.target.value)}
                className="w-full rounded-md border border-ink-300 px-2 py-1 text-sm"
              />
              <div className="text-[10px] text-ink-400 mt-0.5">
                Period like 24h, 7d. Empty = no auto-renew.
              </div>
            </div>
            <div>
              <label className="mb-1 block text-[11px] uppercase tracking-wide text-ink-500">
                Description
              </label>
              <input
                type="text"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                className="w-full rounded-md border border-ink-300 px-2 py-1 text-sm"
              />
            </div>
          </div>
          <div>
            <div className="mb-1 flex items-center justify-between">
              <label className="block text-[11px] uppercase tracking-wide text-ink-500">
                Config
              </label>
              <label className="flex items-center gap-2 text-[11px] text-ink-500">
                <input
                  type="checkbox"
                  checked={advanced}
                  onChange={(e) => {
                    const next = e.target.checked;
                    if (next) {
                      setRawJson(JSON.stringify(config, null, 2));
                    } else {
                      try {
                        setConfig(JSON.parse(rawJson));
                      } catch {
                        /* leave raw JSON for the operator to fix */
                      }
                    }
                    setAdvanced(next);
                  }}
                />
                Advanced (raw JSON)
              </label>
            </div>
            {advanced ? (
              <textarea
                value={rawJson}
                onChange={(e) => setRawJson(e.target.value)}
                rows={Math.min(16, rawJson.split("\n").length + 1)}
                spellCheck={false}
                className="block w-full rounded-md border border-ink-300 p-2 font-mono text-[11px]"
              />
            ) : (
              <RuleConfigEditor
                type={rule.type}
                value={config}
                onChange={setConfig}
                signers={
                  signersApi.data?.signers.map((s) => s.address) ?? []
                }
              />
            )}
          </div>
          {parseError && <ErrorBanner msg={parseError} />}

          {/* Variables / Matrix editors */}
          {(rule.type === "evm_js") && (
            <div className="space-y-2 rounded-md border border-ink-200 p-3">
              <div className="flex items-center justify-between">
                <span className="text-[11px] uppercase tracking-wide text-ink-500">
                  Variables / Matrix
                </span>
              </div>

              {/* Typed variable editor when variable_defs are available */}
              {rule.variable_defs && rule.variable_defs.length > 0 ? (
                <TypedVariablesEditor
                  defs={rule.variable_defs}
                  values={editVars}
                  onChange={(name, val) => setEditVars((s) => ({ ...s, [name]: val }))}
                />
              ) : (
                <div>
                  <button
                    type="button"
                    onClick={() => setShowVarsEditor((s) => !s)}
                    className="flex w-full items-center justify-between rounded-md border border-ink-100 px-2 py-1 text-left text-xs text-ink-700 hover:bg-ink-50"
                  >
                    <span>
                      Variables{" "}
                      <span className="text-ink-400">
                        ({Object.keys(editVars).length} keys)
                      </span>
                    </span>
                    <span className="text-[10px] text-ink-500">{showVarsEditor ? "▲" : "▼"}</span>
                  </button>
                  {showVarsEditor && (
                    <div className="mt-1">
                      <textarea
                        value={JSON.stringify(editVars, null, 2)}
                        onChange={(e) => {
                          try {
                            const parsed = JSON.parse(e.target.value);
                            setEditVars(parsed);
                          } catch {
                            // let operator fix JSON
                          }
                        }}
                        rows={Math.max(3, Object.keys(editVars).length + 2)}
                        spellCheck={false}
                        placeholder='{"max_amount_in": "5000000000000000000"}'
                        className="block w-full rounded-md border border-ink-300 p-2 font-mono text-[11px]"
                      />
                      <div className="mt-1 text-[10px] text-ink-500">
                        Clear to reset (sends empty object).
                      </div>
                    </div>
                  )}
                </div>
              )}

              <div>
                <button
                  type="button"
                  onClick={() => setShowMatrixEditor((s) => !s)}
                  className="flex w-full items-center justify-between rounded-md border border-ink-100 px-2 py-1 text-left text-xs text-ink-700 hover:bg-ink-50"
                >
                  <span>
                    Matrix{" "}
                    <span className="text-ink-400">
                      ({rule.matrix && Array.isArray(rule.matrix) ? (rule.matrix as Record<string, any>[]).length : 0} rows)
                    </span>
                  </span>
                  <span className="text-[10px] text-ink-500">{showMatrixEditor ? "▲" : "▼"}</span>
                </button>
                {showMatrixEditor && (
                  <div className="mt-1">
                    <textarea
                      value={editMatrix}
                      onChange={(e) => setEditMatrix(e.target.value)}
                      rows={Math.max(6, editMatrix.split("\n").length)}
                      spellCheck={false}
                      placeholder='[{"chain_id": "1", "v2_router_address": "0x..."}]'
                      className="block w-full rounded-md border border-ink-300 p-2 font-mono text-[11px]"
                    />
                    <div className="mt-1 text-[10px] text-ink-500">
                      JSON array of objects, each with &quot;chain_id&quot;. Clear to remove all rows.
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {parseError && <ErrorBanner msg={parseError} />}
          <div className="border-t border-ink-200 pt-3 mb-2">
            <label className="mb-1 block text-[11px] uppercase tracking-wide text-ink-500">
              Applied To (which API keys this rule applies to)
            </label>
            <AppliedToPicker value={editAppliedTo} onChange={setEditAppliedTo} />
          </div>
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={onCancelEdit}
              disabled={busy}
              className="rounded-md border border-ink-200 px-2 py-0.5 text-xs text-ink-700 hover:bg-ink-100 disabled:opacity-50"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={save}
              disabled={busy}
              className="rounded-md bg-accent-500 px-2 py-0.5 text-xs font-medium text-white hover:bg-accent-600 disabled:opacity-50"
            >
              {busy ? "Saving…" : "Save"}
            </button>
          </div>
        </div>
      ) : (
        <div>
          <div className="mb-2 flex items-center justify-between">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-ink-500">
              Config
            </h3>
            {rule.type === "evm_js" && (
              <button
                type="button"
                onClick={validateRule}
                disabled={validating}
                className="rounded-md border border-ink-200 px-2 py-0.5 text-xs text-ink-700 hover:bg-ink-100 disabled:opacity-50"
              >
                {validating ? "Validating…" : "Validate"}
              </button>
            )}
          </div>
          <CodeBlock
            body={JSON.stringify(rule.config, null, 2)}
            lang="json"
            maxH={24}
            title="Config"
          />
          {(rule.owner || rule.approved_by) && (
            <div className="mt-3 flex flex-wrap gap-x-6 gap-y-1 text-xs text-ink-500">
              <span>
                <span className="text-ink-400">Priority</span>{" "}
                <span className="font-mono text-ink-700">{rule.priority}</span>
              </span>
              {rule.owner && (
                <span>
                  <span className="text-ink-400">Created by</span>{" "}
                  <span className="font-mono text-ink-700">{rule.owner}</span>
                </span>
              )}
              {rule.approved_by && (
                <span>
                  <span className="text-ink-400">Approved by</span>{" "}
                  <span className="font-mono text-ink-700">{rule.approved_by}</span>
                </span>
              )}
            </div>
          )}

          {rule.variables && Object.keys(rule.variables).length > 0 && (
            <div className="mt-3">
              <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-ink-500">
                Variables
              </h3>
              {rule.variable_defs && rule.variable_defs.length > 0 ? (
                <VariablesViewTable defs={rule.variable_defs} />
              ) : (
                <CodeBlock
                  body={JSON.stringify(rule.variables, null, 2)}
                  lang="json"
                  maxH={12}
                  title="Variables"
                />
              )}
            </div>
          )}

          {rule.matrix && Array.isArray(rule.matrix) && (rule.matrix as Record<string, any>[]).length > 0 && (
            <div className="mt-3">
              <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-ink-500">
                Matrix
              </h3>
              <RuleMatrixTable matrix={rule.matrix as Record<string, any>[]} />
            </div>
          )}
        </div>
      )}

      {validationError && <ErrorBanner msg={validationError} />}

      {validationResult && (
        <div className="space-y-2 rounded-md border border-ink-200 bg-ink-50 p-2">
          <div className="flex items-center gap-3 text-xs text-ink-600">
            <span className="font-semibold uppercase tracking-wide text-ink-500">
              Validation
            </span>
            <span className={validationResult.valid ? "text-green-700" : "text-red-700"}>
              {validationResult.valid ? "passed" : "failed"}
            </span>
            {validationResult.results && (
              <>
                <span className="text-green-700">
                  {validationResult.results.filter((tc) => tc.passed).length} passed
                </span>
                {validationResult.results.filter((tc) => !tc.passed).length > 0 && (
                  <span className="text-red-700">
                    {validationResult.results.filter((tc) => !tc.passed).length} failed
                  </span>
                )}
                <span>{validationResult.results.length} total</span>
              </>
            )}
          </div>
          {!validationResult.valid && validationResult.error && (
            <div className="text-xs text-red-500">{validationResult.error}</div>
          )}
          {validationResult.results?.map((tc, i) => (
            <div key={i} className="flex items-start gap-2 text-xs">
              <span className={tc.passed ? "mt-0.5 text-green-600" : "mt-0.5 text-red-600"}>
                {tc.passed ? "✓" : "✗"}
              </span>
              <div className="flex-1">
                <div className="text-ink-700">{tc.name}</div>
                {!tc.passed && tc.reason && (
                  <div className="text-red-400">— {tc.reason}</div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      <div>
        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-ink-500">
          Budgets
        </h3>
        {budgets.loading && <Loading />}
        {budgets.error && <ErrorBanner msg={budgets.error} />}
        {budgets.data &&
          (budgets.data.length === 0 ? (
            <Empty msg="No budgets attached to this rule." />
          ) : (
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase text-ink-500">
                <tr>
                  <th className="py-1 pr-3 font-normal">Unit</th>
                  <th className="py-1 pr-3 font-normal">Spent / Max</th>
                  <th className="py-1 pr-3 font-normal">Tx</th>
                  <th className="py-1 font-normal">Alert</th>
                </tr>
              </thead>
              <tbody>
                {budgets.data.map((b) => (
                  <tr key={b.id} className="border-t border-ink-100">
                    <td className="py-1 pr-3 font-mono text-xs text-ink-700">
                      {b.unit}
                    </td>
                    <td className="py-1 pr-3 font-mono text-xs text-ink-700">
                      {b.spent} / {b.max_total}
                    </td>
                    <td className="py-1 pr-3 font-mono text-xs text-ink-700">
                      {b.tx_count}
                      {b.max_tx_count ? ` / ${b.max_tx_count}` : ""}
                    </td>
                    <td className="py-1">
                      <Badge tone={b.alert_sent ? "red" : "neutral"}>
                        {b.alert_pct}% {b.alert_sent ? "(sent)" : ""}
                      </Badge>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ))}
      </div>
    </div>
  );
}

function CreateForm({
  onSubmit,
}: {
  onSubmit: (req: CreateRuleRequest) => void;
}) {
  const signersApi = useApi((c) => c.evm.signers.list());
  const apiKeysApi = useApi((c) => c.apiKeys.list());

  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [type, setType] = useState<RuleType>("evm_address_list");
  const [mode, setMode] = useState<RuleMode>("whitelist");
  const [chainType, setChainType] = useState("evm");
  const [chainId, setChainId] = useState("");
  const [apiKeyId, setApiKeyId] = useState("");
  const [signerAddress, setSignerAddress] = useState("");
  const [appliedTo, setAppliedTo] = useState<string[]>([]);
  const [enabled, setEnabled] = useState(true);
  const [config, setConfig] = useState<Record<string, unknown>>(() => ({
    ...CONFIG_TEMPLATES.evm_address_list,
  }));
  const [advanced, setAdvanced] = useState(false);
  const [rawJson, setRawJson] = useState(() =>
    JSON.stringify(CONFIG_TEMPLATES.evm_address_list, null, 2),
  );
  const [parseError, setParseError] = useState<string | null>(null);

  // Switching rule type swaps in that type's config skeleton. We only
  // overwrite when the current config still matches a known template so
  // in-progress edits aren't clobbered.
  function onTypeChange(next: RuleType) {
    setType(next);
    const isTemplate = Object.values(CONFIG_TEMPLATES).some(
      (tpl) => JSON.stringify(tpl) === JSON.stringify(config),
    );
    if (isTemplate) {
      const tpl = { ...CONFIG_TEMPLATES[next] };
      setConfig(tpl);
      setRawJson(JSON.stringify(tpl, null, 2));
    }
  }

  function submit(e: React.FormEvent) {
    e.preventDefault();
    setParseError(null);
    let payload: Record<string, unknown> = config;
    if (advanced) {
      try {
        payload = JSON.parse(rawJson);
      } catch (err) {
        setParseError(err instanceof Error ? err.message : "config: invalid JSON");
        return;
      }
    }
    onSubmit({
      name: name.trim(),
      ...(description.trim() ? { description: description.trim() } : {}),
      type,
      mode,
      ...(chainType ? { chain_type: chainType } : {}),
      ...(chainId ? { chain_id: chainId } : {}),
      ...(apiKeyId ? { api_key_id: apiKeyId } : {}),
      ...(signerAddress ? { signer_address: signerAddress } : {}),
      ...(appliedTo.length > 0 ? { applied_to: appliedTo } : {}),
      config: payload,
      enabled,
    });
  }

  return (
    <Card title="New rule">
      <form onSubmit={submit} className="space-y-3">
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          <Field label="Name" value={name} onChange={setName} required />
          <Field
            label="Description (optional)"
            value={description}
            onChange={setDescription}
          />
          <div>
            <label className="mb-1 block text-[11px] uppercase tracking-wide text-ink-500">
              Type
            </label>
            <select
              value={type}
              onChange={(e) => onTypeChange(e.target.value as RuleType)}
              className="w-full rounded-md border border-ink-300 px-2 py-1 text-sm"
            >
              {RULE_TYPES.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="mb-1 block text-[11px] uppercase tracking-wide text-ink-500">
              Mode
            </label>
            <select
              value={mode}
              onChange={(e) => setMode(e.target.value as RuleMode)}
              className="w-full rounded-md border border-ink-300 px-2 py-1 text-sm"
            >
              <option value="whitelist">whitelist</option>
              <option value="blocklist">blocklist</option>
            </select>
          </div>
          <Field
            label="Chain type"
            value={chainType}
            onChange={setChainType}
          />
          <Field
            label="Chain id (optional)"
            value={chainId}
            onChange={setChainId}
          />
          <ScopePicker
            label="API key id (optional scope)"
            value={apiKeyId}
            onChange={setApiKeyId}
            options={
              apiKeysApi.data?.keys.map((k) => ({
                value: k.id,
                label: k.name && k.name !== k.id ? `${k.id} · ${k.name}` : k.id,
              })) ?? []
            }
            loading={apiKeysApi.loading}
            placeholder="(any API key)"
          />
          <ScopePicker
            label="Signer address (optional scope)"
            value={signerAddress}
            onChange={setSignerAddress}
            options={
              signersApi.data?.signers.map((s) => ({
                value: s.address,
                label: s.display_name
                  ? `${s.address} · ${s.display_name}`
                  : s.address,
              })) ?? []
            }
            loading={signersApi.loading}
            placeholder="(any signer)"
          />
        </div>

        <div>
          <label className="mb-1 block text-[11px] uppercase tracking-wide text-ink-500">
            Applied to
          </label>
          <AppliedToPicker value={appliedTo} onChange={setAppliedTo} />
          <div className="mt-1 text-[11px] text-ink-500">
            Which API keys this rule constrains. Empty defaults to{" "}
            <code>self</code> (the current key); admins can target other
            keys or <code>*</code> for all.
          </div>
        </div>

        <div>
          <div className="mb-1 flex items-center justify-between">
            <label className="block text-[11px] uppercase tracking-wide text-ink-500">
              Config
            </label>
            <label className="flex items-center gap-2 text-[11px] text-ink-500">
              <input
                type="checkbox"
                checked={advanced}
                onChange={(e) => {
                  const next = e.target.checked;
                  if (next) {
                    setRawJson(JSON.stringify(config, null, 2));
                  } else {
                    try {
                      setConfig(JSON.parse(rawJson));
                    } catch {
                      /* leave raw JSON for the operator to fix */
                    }
                  }
                  setAdvanced(next);
                }}
              />
              Advanced (raw JSON)
            </label>
          </div>
          {advanced ? (
            <textarea
              value={rawJson}
              onChange={(e) => setRawJson(e.target.value)}
              rows={Math.min(16, rawJson.split("\n").length + 1)}
              spellCheck={false}
              className="block w-full rounded-md border border-ink-300 p-2 font-mono text-[11px]"
            />
          ) : (
            <RuleConfigEditor
              type={type}
              value={config}
              onChange={setConfig}
              signers={
                signersApi.data?.signers.map((s) => s.address) ?? []
              }
            />
          )}
        </div>
        {parseError && <ErrorBanner msg={parseError} />}
        <label className="flex items-center gap-2 text-sm text-ink-700">
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => setEnabled(e.target.checked)}
          />
          enabled
        </label>
        <div className="flex justify-end">
          <button
            type="submit"
            disabled={!name.trim()}
            className="rounded-md bg-accent-500 px-3 py-1.5 text-sm font-medium text-white hover:bg-accent-600 disabled:cursor-not-allowed disabled:bg-ink-300"
          >
            Create rule
          </button>
        </div>
      </form>
    </Card>
  );
}

function Field({
  label,
  value,
  onChange,
  required,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  required?: boolean;
}) {
  return (
    <div>
      <label className="mb-1 block text-[11px] uppercase tracking-wide text-ink-500">
        {label}
      </label>
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        required={required}
        className="w-full rounded-md border border-ink-300 px-2 py-1 text-sm"
      />
    </div>
  );
}

// ScopePicker: optional-scope dropdown sourced from the live API key /
// signer rosters. Renders a free-text fallback when the operator wants to
// reference something the daemon doesn't know about yet (e.g. a key id
// that exists only in config.yaml, or a typo'd address for a test).
function ScopePicker({
  label,
  value,
  onChange,
  options,
  loading,
  placeholder,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: { value: string; label: string }[];
  loading: boolean;
  placeholder: string;
}) {
  const known = options.some((o) => o.value === value);
  const isCustom = value !== "" && !known && !loading;
  return (
    <div>
      <label className="mb-1 block text-[11px] uppercase tracking-wide text-ink-500">
        {label}
      </label>
      <div className="flex gap-2">
        <select
          value={isCustom ? "__custom__" : value}
          onChange={(e) => {
            const next = e.target.value;
            if (next === "__custom__") return; // keep current custom value
            onChange(next);
          }}
          className="flex-1 rounded-md border border-ink-300 px-2 py-1 font-mono text-xs"
        >
          <option value="">{placeholder}</option>
          {options.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
          {isCustom && (
            <option value="__custom__">custom: {value}</option>
          )}
        </select>
        {isCustom && (
          <button
            type="button"
            onClick={() => onChange("")}
            className="rounded-md border border-ink-200 px-2 py-1 text-xs text-ink-500 hover:bg-ink-100"
          >
            clear
          </button>
        )}
      </div>
    </div>
  );
}

// --- Typed per-rule-type config editor --------------------------------------

function RuleConfigEditor({
  type,
  value,
  onChange,
  signers,
}: {
  type: RuleType;
  value: Record<string, unknown>;
  onChange: (next: Record<string, unknown>) => void;
  signers: string[];
}) {
  switch (type) {
    case "evm_address_list":
      return (
        <AddressListEditor
          field="addresses"
          value={value}
          onChange={onChange}
          hint="Address whitelist/blocklist — matches the EVM `to` of the request."
        />
      );
    case "evm_internal_transfer":
    case "signer_restriction":
      return (
        <AddressListEditor
          field="signer_addresses"
          value={value}
          onChange={onChange}
          signers={signers}
          hint={
            type === "signer_restriction"
              ? "Limits which signers this rule applies to."
              : "Whitelisted destination signers for same-owner internal transfers."
          }
        />
      );
    case "evm_contract_method":
      return <ContractMethodEditor value={value} onChange={onChange} />;
    case "evm_value_limit":
      return (
        <SingleStringField
          fieldKey="max_value"
          value={value}
          onChange={onChange}
          label="Max value (wei or human-readable units)"
          placeholder="1000000000000000000"
        />
      );
    case "evm_solidity_expression":
      return (
        <SingleStringField
          fieldKey="expression"
          value={value}
          onChange={onChange}
          label="Solidity expression"
          multiline
          placeholder="value < 1e18 && to == addr(0xabc...)"
        />
      );
    case "evm_js":
      return <JSScriptEditor value={value} onChange={onChange} />;
    case "evm_dynamic_blocklist":
      return <DynamicBlocklistEditor value={value} onChange={onChange} />;
    case "chain_restriction":
      return (
        <StringArrayEditor
          field="chain_ids"
          label="Allowed chain IDs"
          placeholder="1, 137, 42161 …"
          value={value}
          onChange={onChange}
        />
      );
    case "sign_type_restriction":
      return <SignTypeEditor value={value} onChange={onChange} />;
    case "message_pattern":
      return (
        <SingleStringField
          fieldKey="pattern"
          value={value}
          onChange={onChange}
          label="Regex pattern (RE2)"
          placeholder="^0x[0-9a-fA-F]+$"
        />
      );
    default:
      return (
        <pre className="overflow-x-auto rounded border border-ink-200 bg-ink-50 p-2 font-mono text-[11px] text-ink-700">
          {JSON.stringify(value, null, 2)}
        </pre>
      );
  }
}

function AddressListEditor({
  field,
  value,
  onChange,
  signers,
  hint,
}: {
  field: string;
  value: Record<string, unknown>;
  onChange: (v: Record<string, unknown>) => void;
  signers?: string[];
  hint: string;
}) {
  const items = (value[field] as string[] | undefined) ?? [];
  function set(next: string[]) {
    onChange({ ...value, [field]: next });
  }
  return (
    <div className="space-y-2 rounded-md border border-ink-200 p-3">
      <div className="text-[11px] text-ink-500">{hint}</div>
      {items.map((addr, i) => (
        <div key={i} className="flex items-center gap-2">
          {signers && signers.length > 0 ? (
            <select
              value={signers.includes(addr) ? addr : "__custom__"}
              onChange={(e) => {
                const next = e.target.value;
                if (next === "__custom__") return;
                const arr = [...items];
                arr[i] = next;
                set(arr);
              }}
              className="flex-1 rounded-md border border-ink-300 px-2 py-1 font-mono text-xs"
            >
              <option value="">— pick a signer —</option>
              {signers.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
              {addr && !signers.includes(addr) && (
                <option value="__custom__">custom: {addr}</option>
              )}
            </select>
          ) : (
            <input
              type="text"
              value={addr}
              onChange={(e) => {
                const arr = [...items];
                arr[i] = e.target.value;
                set(arr);
              }}
              placeholder="0x…"
              className="flex-1 rounded-md border border-ink-300 px-2 py-1 font-mono text-xs"
            />
          )}
          {/* free-text fallback when picking 'custom' */}
          {signers && (
            <input
              type="text"
              value={addr}
              onChange={(e) => {
                const arr = [...items];
                arr[i] = e.target.value;
                set(arr);
              }}
              placeholder="or paste 0x…"
              className="w-44 rounded-md border border-ink-300 px-2 py-1 font-mono text-xs"
            />
          )}
          <button
            type="button"
            onClick={() => set(items.filter((_, j) => j !== i))}
            className="rounded-md border border-red-200 px-2 py-0.5 text-xs text-red-700 hover:bg-red-50"
          >
            ×
          </button>
        </div>
      ))}
      <button
        type="button"
        onClick={() => set([...items, ""])}
        className="rounded-md border border-ink-200 px-2 py-0.5 text-xs text-ink-700 hover:bg-ink-100"
      >
        + Add address
      </button>
    </div>
  );
}

function ContractMethodEditor({
  value,
  onChange,
}: {
  value: Record<string, unknown>;
  onChange: (v: Record<string, unknown>) => void;
}) {
  const contractAddress = (value.contract_address as string) ?? "";
  const methods = (value.method_signatures as string[] | undefined) ?? [];
  return (
    <div className="space-y-3 rounded-md border border-ink-200 p-3">
      <div>
        <label className="mb-1 block text-[11px] uppercase tracking-wide text-ink-500">
          Contract address
        </label>
        <input
          type="text"
          value={contractAddress}
          onChange={(e) =>
            onChange({ ...value, contract_address: e.target.value })
          }
          placeholder="0x…"
          className="w-full rounded-md border border-ink-300 px-2 py-1 font-mono text-xs"
        />
      </div>
      <div>
        <label className="mb-1 block text-[11px] uppercase tracking-wide text-ink-500">
          Method signatures (one per line)
        </label>
        <textarea
          value={methods.join("\n")}
          onChange={(e) =>
            onChange({
              ...value,
              method_signatures: e.target.value
                .split("\n")
                .map((s) => s.trim())
                .filter(Boolean),
            })
          }
          rows={Math.max(2, methods.length + 1)}
          spellCheck={false}
          placeholder="transfer(address,uint256)&#10;approve(address,uint256)"
          className="block w-full rounded-md border border-ink-300 p-2 font-mono text-[11px]"
        />
      </div>
    </div>
  );
}

function SingleStringField({
  fieldKey,
  label,
  value,
  onChange,
  multiline,
  placeholder,
}: {
  fieldKey: string;
  label: string;
  value: Record<string, unknown>;
  onChange: (v: Record<string, unknown>) => void;
  multiline?: boolean;
  placeholder?: string;
}) {
  const v = (value[fieldKey] as string | undefined) ?? "";
  return (
    <div className="rounded-md border border-ink-200 p-3">
      <label className="mb-1 block text-[11px] uppercase tracking-wide text-ink-500">
        {label}
      </label>
      {multiline ? (
        <textarea
          value={v}
          onChange={(e) => onChange({ ...value, [fieldKey]: e.target.value })}
          rows={4}
          spellCheck={false}
          placeholder={placeholder}
          className="block w-full rounded-md border border-ink-300 p-2 font-mono text-[11px]"
        />
      ) : (
        <input
          type="text"
          value={v}
          onChange={(e) => onChange({ ...value, [fieldKey]: e.target.value })}
          placeholder={placeholder}
          className="w-full rounded-md border border-ink-300 px-2 py-1 font-mono text-xs"
        />
      )}
    </div>
  );
}

function JSScriptEditor({
  value,
  onChange,
}: {
  value: Record<string, unknown>;
  onChange: (v: Record<string, unknown>) => void;
}) {
  const script = (value.script as string) ?? "";
  const signTypeFilter = (value.sign_type_filter as string) ?? "";
  return (
    <div className="space-y-3 rounded-md border border-ink-200 p-3">
      <div>
        <label className="mb-1 block text-[11px] uppercase tracking-wide text-ink-500">
          Script — must export <code>validate(input)</code> returning{" "}
          <code>&#123; valid, reason? &#125;</code>
        </label>
        <textarea
          value={script}
          onChange={(e) => onChange({ ...value, script: e.target.value })}
          rows={12}
          spellCheck={false}
          placeholder="function validate(input) {&#10;  // input.signer, input.payload, input.chain_id, …&#10;  return { valid: input.payload.value < 1e18 };&#10;}"
          className="block w-full rounded-md border border-ink-300 p-2 font-mono text-[11px]"
        />
      </div>
      <div>
        <label className="mb-1 block text-[11px] uppercase tracking-wide text-ink-500">
          sign_type_filter (optional, comma-separated)
        </label>
        <input
          type="text"
          value={signTypeFilter}
          onChange={(e) =>
            onChange({ ...value, sign_type_filter: e.target.value })
          }
          placeholder="typed_data,transaction"
          className="w-full rounded-md border border-ink-300 px-2 py-1 font-mono text-xs"
        />
      </div>
    </div>
  );
}

function DynamicBlocklistEditor({
  value,
  onChange,
}: {
  value: Record<string, unknown>;
  onChange: (v: Record<string, unknown>) => void;
}) {
  const sources = (value.sources as Array<Record<string, unknown>> | undefined) ?? [];
  function set(next: Array<Record<string, unknown>>) {
    onChange({ ...value, sources: next });
  }
  return (
    <div className="space-y-2 rounded-md border border-ink-200 p-3">
      <div className="text-[11px] text-ink-500">
        URLs the daemon polls to refresh the blocklist. Each entry needs a
        `name` + `url`; format defaults to plain newline-separated 0x
        addresses.
      </div>
      {sources.map((src, i) => (
        <div key={i} className="grid grid-cols-1 gap-1 rounded-md border border-ink-100 p-2 md:grid-cols-[10rem_1fr_auto]">
          <input
            type="text"
            value={(src.name as string) ?? ""}
            onChange={(e) => {
              const arr = [...sources];
              arr[i] = { ...src, name: e.target.value };
              set(arr);
            }}
            placeholder="ofac"
            className="rounded-md border border-ink-300 px-2 py-1 font-mono text-xs"
          />
          <input
            type="text"
            value={(src.url as string) ?? ""}
            onChange={(e) => {
              const arr = [...sources];
              arr[i] = { ...src, url: e.target.value };
              set(arr);
            }}
            placeholder="https://example.com/blocklist.txt"
            className="rounded-md border border-ink-300 px-2 py-1 font-mono text-xs"
          />
          <button
            type="button"
            onClick={() => set(sources.filter((_, j) => j !== i))}
            className="rounded-md border border-red-200 px-2 py-0.5 text-xs text-red-700 hover:bg-red-50"
          >
            ×
          </button>
        </div>
      ))}
      <button
        type="button"
        onClick={() => set([...sources, { name: "", url: "" }])}
        className="rounded-md border border-ink-200 px-2 py-0.5 text-xs text-ink-700 hover:bg-ink-100"
      >
        + Add source
      </button>
    </div>
  );
}

function StringArrayEditor({
  field,
  label,
  placeholder,
  value,
  onChange,
}: {
  field: string;
  label: string;
  placeholder: string;
  value: Record<string, unknown>;
  onChange: (v: Record<string, unknown>) => void;
}) {
  const items = (value[field] as string[] | undefined) ?? [];
  return (
    <div className="rounded-md border border-ink-200 p-3">
      <label className="mb-1 block text-[11px] uppercase tracking-wide text-ink-500">
        {label}
      </label>
      <textarea
        value={items.join("\n")}
        onChange={(e) =>
          onChange({
            ...value,
            [field]: e.target.value
              .split("\n")
              .map((s) => s.trim())
              .filter(Boolean),
          })
        }
        rows={Math.max(2, items.length + 1)}
        spellCheck={false}
        placeholder={placeholder}
        className="block w-full rounded-md border border-ink-300 p-2 font-mono text-xs"
      />
    </div>
  );
}

function SignTypeEditor({
  value,
  onChange,
}: {
  value: Record<string, unknown>;
  onChange: (v: Record<string, unknown>) => void;
}) {
  const picked = new Set((value.sign_types as string[] | undefined) ?? []);
  function toggle(t: string) {
    const next = new Set(picked);
    if (next.has(t)) next.delete(t);
    else next.add(t);
    onChange({ ...value, sign_types: Array.from(next) });
  }
  return (
    <div className="rounded-md border border-ink-200 p-3">
      <div className="mb-2 text-[11px] uppercase tracking-wide text-ink-500">
        Allowed sign types
      </div>
      <div className="flex flex-wrap gap-2">
        {SIGN_TYPES.map((t) => {
          const on = picked.has(t);
          return (
            <button
              type="button"
              key={t}
              onClick={() => toggle(t)}
              className={`rounded-md border px-2 py-1 text-xs font-mono ${
                on
                  ? "border-accent-500 bg-accent-50 text-accent-700"
                  : "border-ink-200 text-ink-500 hover:bg-ink-100"
              }`}
            >
              {t}
            </button>
          );
        })}
      </div>
    </div>
  );
}

function formatMutationError(e: unknown): string {
  if (e instanceof APIError) return `HTTP ${e.statusCode}: ${e.message}`;
  if (e instanceof Error) return e.message;
  return String(e);
}

function TypedVariablesEditor({
  defs,
  values,
  onChange,
}: {
  defs: RuleVariableDef[];
  values: Record<string, string>;
  onChange: (name: string, val: string) => void;
}) {
  return (
    <div className="space-y-3">
      {defs.map((def) => {
        const value = values[def.name] ?? "";
        const label = def.label || def.name;
        const hasDefault = def.default_value !== undefined && def.default_value !== "";

        // bool → checkbox
        if (def.type === "bool") {
          const checked = value === "true";
          return (
            <div key={def.name} className="flex items-center gap-3 rounded-md border border-ink-100 p-2">
              <div className="flex-1">
                <div className="text-xs text-ink-700">{label}</div>
                {def.description && <div className="text-[10px] text-ink-500">{def.description}</div>}
              </div>
              <label className="inline-flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={checked}
                  onChange={(e) => onChange(def.name, e.target.checked ? "true" : "false")}
                />
                <span className="text-xs text-ink-600">{checked ? "true" : "false"}</span>
              </label>
              {hasDefault && <span className="text-[10px] text-ink-400">default: {def.default_value}</span>}
            </div>
          );
        }

        // address_list / bigint_list / json → textarea
        if (def.type === "address_list" || def.type === "bigint_list" || def.type === "json") {
          const rows = def.type === "json" ? 4 : 2;
          return (
            <div key={def.name} className="rounded-md border border-ink-100 p-2">
              <div className="mb-1 flex items-center justify-between">
                <span className="text-xs text-ink-700">{label}</span>
                {def.required && <span className="text-[10px] text-red-500">required</span>}
              </div>
              {def.description && <div className="mb-1 text-[10px] text-ink-500">{def.description}</div>}
              <textarea
                value={value}
                onChange={(e) => onChange(def.name, e.target.value)}
                rows={rows}
                spellCheck={false}
                placeholder={def.placeholder || def.default_value || ""}
                className="w-full rounded-md border border-ink-300 px-2 py-1 font-mono text-[11px]"
              />
              {hasDefault && <div className="mt-1 text-[10px] text-ink-400">default: {def.default_value}</div>}
            </div>
          );
        }

        // enum → select
        if (def.type === "enum" && def.options && def.options.length > 0) {
          return (
            <div key={def.name} className="rounded-md border border-ink-100 p-2">
              <div className="mb-1 flex items-center justify-between">
                <span className="text-xs text-ink-700">{label}</span>
                {def.required && <span className="text-[10px] text-red-500">required</span>}
              </div>
              {def.description && <div className="mb-1 text-[10px] text-ink-500">{def.description}</div>}
              <select
                value={value}
                onChange={(e) => onChange(def.name, e.target.value)}
                className="w-full rounded-md border border-ink-300 px-2 py-1 font-mono text-[11px]"
              >
                <option value="">—</option>
                {def.options.map((opt) => (
                  <option key={opt} value={opt}>{opt}</option>
                ))}
              </select>
              {hasDefault && <div className="mt-1 text-[10px] text-ink-400">default: {def.default_value}</div>}
            </div>
          );
        }

        // address / bigint / bytes / bytes4 → monospace input
        // string / duration → regular input
        const isMono =
          def.type === "address" ||
          def.type === "bigint" ||
          def.type === "bytes" ||
          def.type === "bytes4";

        return (
          <div key={def.name} className="rounded-md border border-ink-100 p-2">
            <div className="mb-1 flex items-center justify-between">
              <span className="text-xs text-ink-700">
                {label}
                {def.type && (
                  <span className="ml-1 font-mono text-[10px] uppercase text-ink-400">[{def.type}]</span>
                )}
              </span>
              {def.required && <span className="text-[10px] text-red-500">required</span>}
            </div>
            {def.description && <div className="mb-1 text-[10px] text-ink-500">{def.description}</div>}
            <input
              type={def.sensitive ? "password" : "text"}
              value={value}
              onChange={(e) => onChange(def.name, e.target.value)}
              placeholder={def.placeholder || def.default_value || ""}
              className={`w-full rounded-md border border-ink-300 px-2 py-1 text-sm ${isMono ? "font-mono" : ""}`}
            />
            {hasDefault && <div className="mt-1 text-[10px] text-ink-400">default: {def.default_value}</div>}
            {def.hint && <div className="mt-1 text-[10px] text-ink-500">{def.hint}</div>}
          </div>
        );
      })}
    </div>
  );
}

function VariablesViewTable({ defs }: { defs: RuleVariableDef[] }) {
  return (
    <div className="overflow-x-auto rounded-md border border-ink-200">
      <table className="w-full text-left text-xs">
        <thead>
          <tr className="border-b border-ink-200 bg-ink-50">
            <th className="whitespace-nowrap px-2 py-1.5 font-mono font-normal text-ink-500">Name</th>
            <th className="whitespace-nowrap px-2 py-1.5 font-normal text-ink-500">Type</th>
            <th className="whitespace-nowrap px-2 py-1.5 font-normal text-ink-500">Value</th>
            <th className="whitespace-nowrap px-2 py-1.5 font-normal text-ink-500">Default</th>
          </tr>
        </thead>
        <tbody>
          {defs.map((def) => (
            <tr key={def.name} className="border-t border-ink-100">
              <td className="whitespace-nowrap px-2 py-1 font-mono text-ink-700">
                {def.label || def.name}
                {def.required && <span className="ml-1 text-red-500">*</span>}
              </td>
              <td className="whitespace-nowrap px-2 py-1">
                <span className="rounded bg-ink-100 px-1.5 py-0.5 font-mono text-[10px] uppercase text-ink-600">
                  {def.type || "string"}
                </span>
              </td>
              <td className="max-w-[300px] truncate whitespace-nowrap px-2 py-1 font-mono text-ink-700" title={def.value ?? ""}>
                {def.sensitive ? "••••••••" : truncateAddr(def.value ?? "", def.type)}
              </td>
              <td className="whitespace-nowrap px-2 py-1 font-mono text-[11px] text-ink-400">
                {def.default_value || "—"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function truncateAddr(val: string, type?: string): string {
  if (!val) return val;
  if (type === "address" && val.startsWith("0x") && val.length > 12) {
    return val.slice(0, 6) + "..." + val.slice(-4);
  }
  if (val.length > 60) return val.slice(0, 57) + "...";
  return val;
}

function RuleMatrixTable({ matrix }: { matrix: Record<string, any>[] }) {
  if (!matrix || matrix.length === 0) return null;
  const chainKey = "chain_id";
  const colSet = new Set<string>();
  for (const row of matrix) {
    for (const k of Object.keys(row)) colSet.add(k);
  }
  const cols = [chainKey, ...Array.from(colSet).filter((k) => k !== chainKey)];

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-xs" style={{ tableLayout: "auto" }}>
        <thead>
          <tr className="border-b border-ink-200">
            {cols.map((col) => (
              <th
                key={col}
                className="whitespace-nowrap px-2 py-1 font-mono font-normal text-ink-500"
              >
                {col}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {matrix.map((row, i) => (
            <tr key={i} className="border-t border-ink-100">
              {cols.map((col) => {
                const val = row[col];
                const display =
                  val === undefined || val === null
                    ? ""
                    : typeof val === "object"
                      ? JSON.stringify(val)
                      : String(val);
                return (
                  <td
                    key={col}
                    className="max-w-[200px] truncate whitespace-nowrap px-2 py-1 font-mono text-ink-700"
                    title={display}
                  >
                    {display}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
