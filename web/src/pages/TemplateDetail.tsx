import { useState, type ReactNode } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  APIError,
  type Template,
  type TemplateVariable,
} from "remote-signer-client";
import {
  Badge,
  Card,
  ErrorBanner,
  Loading,
  PageHeader,
} from "../components/ui";
import { getClient } from "../lib/auth";
import { useApi } from "../lib/useApi";

/**
 * Per-template view: metadata + a typed form to fill the variables +
 * the daemon-side scope (chain + signer + applied_to) fields.
 * Submitting calls TemplateService.instantiate and lands the user on
 * /rules with a toast-style success card showing the new rule id.
 *
 * Variable types map to widgets (v0.3 typed; daemon revalidates):
 *   address / bytes / bytes4 → monospace text input
 *   address_list / bigint_list → textarea (comma-separated)
 *   bigint / duration / string → text input
 *   bool                     → checkbox toggle
 *   enum                     → select bound to options
 *   json                     → textarea (raw JSON)
 */
export function TemplateDetail() {
  const { id = "" } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { data, loading, error, reload } = useApi(
    (c) => c.templates.get(id),
    [id],
  );

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <Link
          to="/templates"
          className="text-xs text-accent-600 hover:text-accent-500"
        >
          ← all templates
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

      {data && <TemplateView tmpl={data} onApplied={(ruleID) => navigate(`/rules`, { state: { highlightRuleID: ruleID } })} />}
    </div>
  );
}

function TemplateView({
  tmpl,
  onApplied,
}: {
  tmpl: Template;
  onApplied: (ruleID: string) => void;
}) {
  return (
    <>
      <PageHeader
        title={tmpl.name}
        subtitle={tmpl.description ? <span>{tmpl.description}</span> : undefined}
        actions={
          <div className="flex gap-2">
            <Badge tone={tmpl.mode === "blocklist" ? "red" : "neutral"}>
              {tmpl.mode || "—"}
            </Badge>
            <Badge>{tmpl.source}</Badge>
          </div>
        }
      />

      <Card title="Metadata">
        <FieldGrid>
          <Field label="ID">
            <Mono>{tmpl.id}</Mono>
          </Field>
          <Field label="Type">
            <Mono>{tmpl.type}</Mono>
          </Field>
          {tmpl.budget_metering?.method && (
            <Field label="Budget metering">
              <Mono>
                {String(tmpl.budget_metering.method)}
                {tmpl.budget_metering.unit
                  ? ` · unit ${tmpl.budget_metering.unit}`
                  : ""}
              </Mono>
            </Field>
          )}
        </FieldGrid>
      </Card>

      <RulesCard tmpl={tmpl} />

      <InstantiateForm tmpl={tmpl} onApplied={onApplied} />
    </>
  );
}

// RulesCard surfaces the template's `config.rules[]` array so the
// operator can see exactly what sub-rules this template will expand
// into when applied. The Mode column on the list view shows an
// aggregate ("whitelist" / "blocklist" / "mixed"); this card explains
// the aggregate by listing each rule's name, type, and individual mode.
function RulesCard({ tmpl }: { tmpl: Template }) {
  const rules = extractRules(tmpl);
  if (rules.length === 0) {
    return null;
  }
  return (
    <Card title={`Rules (${rules.length})`}>
      <ul className="divide-y divide-ink-100 text-sm">
        {rules.map((r, i) => (
          <li key={r.id || r.name || i} className="py-2">
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0 flex-1">
                <div className="text-ink-900">{r.name || r.id || `rule ${i + 1}`}</div>
                {r.description && (
                  <div className="text-[11px] text-ink-500">{r.description}</div>
                )}
                {r.id && r.name && (
                  <div className="font-mono text-[10px] text-ink-500">{r.id}</div>
                )}
              </div>
              <div className="flex shrink-0 gap-1.5">
                {r.mode && (
                  <Badge tone={r.mode === "blocklist" ? "red" : "neutral"}>{r.mode}</Badge>
                )}
                {r.type && (
                  <span className="rounded bg-ink-100 px-1.5 py-0.5 font-mono text-[10px] text-ink-700">
                    {r.type}
                  </span>
                )}
              </div>
            </div>
          </li>
        ))}
      </ul>
    </Card>
  );
}

interface SubRule {
  id?: string;
  name?: string;
  type?: string;
  mode?: string;
  description?: string;
  enabled?: boolean;
}

// extractRules pulls the rules array out of the template's config blob.
// The server stores it as opaque JSON (Config is map<string,any>), so
// we navigate the shape defensively rather than relying on a typed
// SDK field.
function extractRules(tmpl: Template): SubRule[] {
  const cfg = tmpl.config as { rules?: unknown } | undefined;
  if (!cfg || !Array.isArray(cfg.rules)) return [];
  return cfg.rules.map((r) => {
    if (r && typeof r === "object") {
      const o = r as Record<string, unknown>;
      return {
        id: typeof o.id === "string" ? o.id : undefined,
        name: typeof o.name === "string" ? o.name : undefined,
        type: typeof o.type === "string" ? o.type : undefined,
        mode: typeof o.mode === "string" ? o.mode : undefined,
        description: typeof o.description === "string" ? o.description : undefined,
        enabled: typeof o.enabled === "boolean" ? o.enabled : undefined,
      };
    }
    return {};
  });
}

interface InstantiateState {
  ruleName: string;
  chainID: string;
  signerAddress: string;
  variables: Record<string, string>;
}

function InstantiateForm({
  tmpl,
  onApplied,
}: {
  tmpl: Template;
  onApplied: (ruleID: string) => void;
}) {
  const [state, setState] = useState<InstantiateState>(() => ({
    ruleName: tmpl.name + " instance",
    chainID: "1",
    signerAddress: "",
    variables: defaultVariables(tmpl.variables ?? []),
  }));
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<{ ruleID: string; ruleName: string } | null>(null);

  function setVar(name: string, value: string) {
    setState((s) => ({ ...s, variables: { ...s.variables, [name]: value } }));
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSuccess(null);
    const c = getClient();
    if (!c) return;
    setSubmitting(true);
    try {
      const resp = await c.templates.instantiate(tmpl.id, {
        name: state.ruleName.trim() || undefined,
        chain_type: "evm",
        chain_id: state.chainID.trim() || undefined,
        signer_address: state.signerAddress.trim() || undefined,
        variables: state.variables,
      });
      const rule = resp.rule as { id?: string; name?: string };
      setSuccess({
        ruleID: rule.id || "(unknown)",
        ruleName: rule.name || state.ruleName,
      });
      if (rule.id) onApplied(rule.id);
    } catch (ex) {
      setError(formatErr(ex));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Card title="Instantiate as rule">
      {success ? (
        <div className="space-y-3">
          <div className="rounded-md border border-green-200 bg-green-50 px-3 py-2 text-sm text-green-800">
            Rule <Mono>{success.ruleName}</Mono> created — ID{" "}
            <Mono>{success.ruleID}</Mono>.
          </div>
          <div className="flex gap-2">
            <Link
              to="/rules"
              className="rounded-md bg-accent-500 px-3 py-1.5 text-sm font-medium text-white hover:bg-accent-600"
            >
              View in Rules
            </Link>
            <button
              type="button"
              onClick={() => setSuccess(null)}
              className="rounded-md border border-ink-200 px-3 py-1.5 text-sm text-ink-700 hover:bg-ink-100"
            >
              Instantiate another
            </button>
          </div>
        </div>
      ) : (
        <form onSubmit={submit} className="space-y-4">
          {error && (
            <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-800">
              {error}
            </div>
          )}

          <FormRow label="Rule name" help="Defaults to the template name + ' instance'">
            <input
              type="text"
              value={state.ruleName}
              onChange={(e) =>
                setState((s) => ({ ...s, ruleName: e.target.value }))
              }
              className="w-full rounded-md border border-ink-300 px-2 py-1 text-sm"
              data-testid="template-form-rule-name"
            />
          </FormRow>
          <FormRow label="Chain ID" help='"1" = Ethereum mainnet'>
            <input
              type="text"
              value={state.chainID}
              onChange={(e) =>
                setState((s) => ({ ...s, chainID: e.target.value }))
              }
              className="w-full rounded-md border border-ink-300 px-2 py-1 font-mono text-sm"
              data-testid="template-form-chain-id"
            />
          </FormRow>
          <FormRow
            label="Signer address"
            help="Optional — scope the rule to a single signer; leave blank for all"
          >
            <input
              type="text"
              value={state.signerAddress}
              onChange={(e) =>
                setState((s) => ({ ...s, signerAddress: e.target.value }))
              }
              placeholder="0x…"
              className="w-full rounded-md border border-ink-300 px-2 py-1 font-mono text-sm"
              data-testid="template-form-signer-address"
            />
          </FormRow>

          {tmpl.variables && tmpl.variables.length > 0 && (
            <>
              <div className="border-t border-ink-100 pt-3 text-[11px] uppercase tracking-wider text-ink-500">
                Template variables
              </div>
              {tmpl.variables.map((v) => (
                <FormRow
                  key={v.name}
                  label={v.name}
                  required={v.required}
                  help={v.description}
                >
                  <VariableInput
                    variable={v}
                    value={state.variables[v.name] ?? ""}
                    onChange={(val) => setVar(v.name, val)}
                  />
                </FormRow>
              ))}
            </>
          )}

          <div className="flex gap-2 border-t border-ink-100 pt-3">
            <button
              type="submit"
              disabled={submitting}
              className="rounded-md bg-accent-500 px-3 py-1.5 text-sm font-medium text-white hover:bg-accent-600 disabled:opacity-50"
              data-testid="template-form-submit"
            >
              {submitting ? "Instantiating…" : "Instantiate"}
            </button>
          </div>
        </form>
      )}
    </Card>
  );
}

function defaultVariables(vars: TemplateVariable[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const v of vars) {
    // v.default is `unknown` in the v0.3 SDK (matches Go's any). Stringify
    // it for the form state; the widget below will reinterpret per type
    // when needed (e.g. bool checks "true"/"false").
    out[v.name] = stringifyDefault(v.default);
  }
  return out;
}

function stringifyDefault(v: unknown): string {
  if (v == null) return "";
  if (typeof v === "string") return v;
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") return String(v);
  // Arrays / objects (address_list defaults, json) round-trip through
  // JSON so the textarea keeps the structure visible.
  try {
    return JSON.stringify(v);
  } catch {
    return String(v);
  }
}

function VariableInput({
  variable,
  value,
  onChange,
}: {
  variable: TemplateVariable;
  value: string;
  onChange: (v: string) => void;
}) {
  const testid = `template-form-var-${variable.name}`;

  // bool → toggle.
  if (variable.type === "bool") {
    const checked = value === "true";
    return (
      <label className="inline-flex items-center gap-2 text-sm text-ink-700">
        <input
          type="checkbox"
          checked={checked}
          onChange={(e) => onChange(e.target.checked ? "true" : "false")}
          data-testid={testid}
        />
        <span>{checked ? "true" : "false"}</span>
      </label>
    );
  }

  // enum → select bound to Options.
  if (variable.type === "enum" && variable.options && variable.options.length > 0) {
    return (
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        required={variable.required}
        className="w-full rounded-md border border-ink-300 px-2 py-1 text-sm"
        data-testid={testid}
      >
        <option value="">— pick one —</option>
        {variable.options.map((opt) => (
          <option key={opt} value={opt}>
            {opt}
          </option>
        ))}
      </select>
    );
  }

  // *_list and json → textarea.
  if (
    variable.type === "address_list" ||
    variable.type === "bigint_list" ||
    variable.type === "json"
  ) {
    const placeholder =
      variable.placeholder ||
      (variable.type === "json"
        ? '{"key": "value"}'
        : variable.type === "bigint_list"
          ? "100, 200, 300"
          : "0xabc..., 0xdef..., 0x123...");
    return (
      <textarea
        value={value}
        onChange={(e) => onChange(e.target.value)}
        rows={variable.type === "json" ? 4 : 2}
        placeholder={placeholder}
        required={variable.required}
        className="w-full rounded-md border border-ink-300 px-2 py-1 font-mono text-xs"
        data-testid={testid}
      />
    );
  }

  const isMono =
    variable.type === "address" ||
    variable.type === "bigint" ||
    variable.type === "bytes" ||
    variable.type === "bytes4";
  return (
    <input
      type="text"
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={variable.placeholder || variable.type}
      required={variable.required}
      className={`w-full rounded-md border border-ink-300 px-2 py-1 text-sm ${
        isMono ? "font-mono" : ""
      }`}
      data-testid={testid}
    />
  );
}

// --- shared bits ---

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

function FormRow({
  label,
  required,
  help,
  children,
}: {
  label: string;
  required?: boolean;
  help?: string;
  children: ReactNode;
}) {
  return (
    <div className="grid grid-cols-[160px_1fr] gap-4">
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

function formatErr(e: unknown): string {
  if (e instanceof APIError) return `HTTP ${e.statusCode}: ${e.message}`;
  if (e instanceof Error) return e.message;
  return String(e);
}
