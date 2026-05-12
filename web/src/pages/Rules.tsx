import { useState } from "react";
import {
  APIError,
  type CreateRuleRequest,
  type RuleMode,
  type RuleType,
} from "remote-signer-client";
import {
  Badge,
  Card,
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
  "signer_restriction",
  "sign_type_restriction",
  "message_pattern",
];

// Per-type starter config. The daemon validates the actual fields; this is
// just to save the operator from staring at an empty {} and looking up the
// schema in docs. Comments live in the UI, not in the emitted JSON.
const CONFIG_TEMPLATES: Record<RuleType, Record<string, unknown>> = {
  evm_address_list: { addresses: ["0x0000000000000000000000000000000000000000"] },
  evm_contract_method: {
    contract_address: "0x0000000000000000000000000000000000000000",
    method_signatures: ["transfer(address,uint256)"],
  },
  evm_value_limit: { max_value: "1000000000000000000" },
  evm_solidity_expression: { expression: "value < 1e18" },
  signer_restriction: {
    signer_addresses: ["0x0000000000000000000000000000000000000000"],
  },
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
          </>
        }
      />

      {mutationError && <ErrorBanner msg={mutationError} />}

      {showCreate && <CreateForm onSubmit={create} />}

      <Card>
        {loading && <Loading />}
        {error && <ErrorBanner msg={error} />}
        {data &&
          (data.rules.length === 0 ? (
            <Empty msg="No rules defined. Sign requests will be evaluated against the daemon's default policy (manual approval if configured)." />
          ) : (
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase text-ink-500">
                <tr>
                  <th className="py-1 pr-3 font-normal">Name</th>
                  <th className="py-1 pr-3 font-normal">Type</th>
                  <th className="py-1 pr-3 font-normal">Mode</th>
                  <th className="py-1 pr-3 font-normal">Source</th>
                  <th className="py-1 pr-3 font-normal">Status</th>
                  <th className="py-1 font-normal">Actions</th>
                </tr>
              </thead>
              <tbody>
                {data.rules.map((r) => (
                  <tr key={r.id} className="border-t border-ink-100">
                    <td className="py-1 pr-3">
                      <div className="text-ink-900">{r.name}</div>
                      <div className="font-mono text-[11px] text-ink-500">
                        {r.id}
                      </div>
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
                      <Badge tone={r.enabled ? "green" : "neutral"}>
                        {r.enabled ? "enabled" : "disabled"}
                      </Badge>
                    </td>
                    <td className="py-1">
                      <div className="flex gap-2">
                        <button
                          type="button"
                          disabled={busy === r.id}
                          onClick={() => toggle(r.id, r.enabled)}
                          className="rounded-md border border-ink-200 px-2 py-0.5 text-xs text-ink-700 hover:bg-ink-100 disabled:opacity-50"
                        >
                          {r.enabled ? "Disable" : "Enable"}
                        </button>
                        <button
                          type="button"
                          disabled={busy === r.id}
                          onClick={() => destroy(r.id, r.name)}
                          className="rounded-md border border-red-200 px-2 py-0.5 text-xs text-red-700 hover:bg-red-50 disabled:opacity-50"
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ))}
      </Card>
    </div>
  );
}

function CreateForm({
  onSubmit,
}: {
  onSubmit: (req: CreateRuleRequest) => void;
}) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [type, setType] = useState<RuleType>("evm_address_list");
  const [mode, setMode] = useState<RuleMode>("whitelist");
  const [chainType, setChainType] = useState("evm");
  const [chainId, setChainId] = useState("");
  const [apiKeyId, setApiKeyId] = useState("");
  const [signerAddress, setSignerAddress] = useState("");
  const [enabled, setEnabled] = useState(true);
  const [configJson, setConfigJson] = useState(() =>
    JSON.stringify(CONFIG_TEMPLATES.evm_address_list, null, 2),
  );
  const [parseError, setParseError] = useState<string | null>(null);

  // Switching rule type rewrites the config skeleton so the operator gets
  // a sensible starting point. We only overwrite if the textarea still
  // matches a known template (to avoid clobbering in-progress edits).
  function onTypeChange(next: RuleType) {
    setType(next);
    const isTemplate = Object.values(CONFIG_TEMPLATES).some(
      (tpl) => JSON.stringify(tpl, null, 2) === configJson,
    );
    if (isTemplate) {
      setConfigJson(JSON.stringify(CONFIG_TEMPLATES[next], null, 2));
    }
  }

  function submit(e: React.FormEvent) {
    e.preventDefault();
    setParseError(null);
    let config: Record<string, unknown>;
    try {
      config = JSON.parse(configJson);
    } catch (err) {
      setParseError(err instanceof Error ? err.message : "config: invalid JSON");
      return;
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
      config,
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
          <Field
            label="API key id (optional scope)"
            value={apiKeyId}
            onChange={setApiKeyId}
          />
          <Field
            label="Signer address (optional scope)"
            value={signerAddress}
            onChange={setSignerAddress}
          />
        </div>
        <div>
          <label className="mb-1 block text-[11px] uppercase tracking-wide text-ink-500">
            Config (JSON)
          </label>
          <textarea
            value={configJson}
            onChange={(e) => setConfigJson(e.target.value)}
            rows={Math.min(12, configJson.split("\n").length + 1)}
            spellCheck={false}
            className="block w-full rounded-md border border-ink-300 p-2 font-mono text-[11px]"
          />
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

function formatMutationError(e: unknown): string {
  if (e instanceof APIError) return `HTTP ${e.statusCode}: ${e.message}`;
  if (e instanceof Error) return e.message;
  return String(e);
}
