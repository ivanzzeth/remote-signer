import { useState, type ReactNode } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  APIError,
  type PresetDetail as PresetDetailDTO,
  type PresetVariableDetail,
} from "remote-signer-client";
import { AppliedToPicker } from "../components/AppliedToPicker";
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
 * Apply-a-preset form. The daemon's GET /api/v1/presets/{id} returns
 * each override hint already joined against the referenced template's
 * variable definition (type, description, default). Without that join
 * the form was just opaque text inputs — the v0.2 endpoint only
 * surfaced bare hint names — which is the friendliness gap Phase 2A
 * closes.
 *
 * Apply returns one or more rule.id values (a preset can fan out
 * across multiple templates). The success state lists them all and
 * offers a jump-to-rules action.
 */
export function PresetDetail() {
  const { id = "" } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { data, loading, error, reload } = useApi(
    (c) => c.presets.get(id),
    [id],
  );

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <Link
          to="/presets"
          className="text-xs text-accent-600 hover:text-accent-500"
        >
          ← all presets
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

      {data && (
        <>
          <PageHeader
            title={data.name || data.id}
            subtitle={
              <span className="font-mono text-xs text-ink-500">{data.id}</span>
            }
            actions={
              <div className="flex gap-2">
                {data.chain_type && (
                  <Badge>
                    {data.chain_type}
                    {data.chain_id ? `/${data.chain_id}` : ""}
                  </Badge>
                )}
                {data.template_ids.length > 0 && (
                  <Badge tone="neutral">
                    {data.template_ids.length} template
                    {data.template_ids.length === 1 ? "" : "s"}
                  </Badge>
                )}
              </div>
            }
          />

          {data.template_ids.length > 0 && (
            <Card title="Templates referenced">
              <ul className="space-y-1 text-sm">
                {data.template_ids.map((tid) => (
                  <li key={tid}>
                    <Link
                      to={`/templates/${encodeURIComponent(tid)}`}
                      className="font-mono text-xs text-accent-600 hover:text-accent-500"
                    >
                      {tid} →
                    </Link>
                  </li>
                ))}
              </ul>
            </Card>
          )}

          <ApplyForm
            preset={data}
            onApplied={() => navigate("/rules")}
          />
        </>
      )}
    </div>
  );
}

interface ApplyResult {
  ruleID: string;
  ruleName: string;
}

function ApplyForm({
  preset,
  onApplied,
}: {
  preset: PresetDetailDTO;
  onApplied: () => void;
}) {
  const [vars, setVars] = useState<Record<string, string>>(() => {
    const out: Record<string, string> = {};
    for (const v of preset.variables) {
      // Pre-fill with the preset's default so the operator sees
      // exactly what will be applied; clearing the field falls back
      // to the same default server-side.
      out[v.name] = v.default_value ?? "";
    }
    return out;
  });
  const [appliedTo, setAppliedTo] = useState<string[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<ApplyResult[] | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSuccess(null);
    const c = getClient();
    if (!c) return;
    setSubmitting(true);
    try {
      // Strip values that match the preset's default — let the server
      // use its own value rather than echoing it back. Empty strings
      // also fall through to the default.
      const cleanVars: Record<string, string> = {};
      for (const v of preset.variables) {
        const current = vars[v.name] ?? "";
        if (current !== "" && current !== (v.default_value ?? "")) {
          cleanVars[v.name] = current;
        }
      }
      const resp = await c.presets.apply(preset.id, {
        variables: cleanVars,
        applied_to: appliedTo.length > 0 ? appliedTo : undefined,
      });
      const items = resp.results.map((r) => ({
        ruleID: (r.rule as { id?: string }).id || "(unknown)",
        ruleName: (r.rule as { name?: string }).name || "(unnamed)",
      }));
      setSuccess(items);
    } catch (ex) {
      setError(formatErr(ex));
    } finally {
      setSubmitting(false);
    }
  }

  if (success) {
    return (
      <Card title="Applied">
        <div className="space-y-3">
          <div className="rounded-md border border-green-200 bg-green-50 px-3 py-2 text-sm text-green-800">
            Created {success.length} rule{success.length === 1 ? "" : "s"}:
          </div>
          <ul className="space-y-1">
            {success.map((r) => (
              <li key={r.ruleID} className="text-sm">
                <Mono>{r.ruleID}</Mono> — {r.ruleName}
              </li>
            ))}
          </ul>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={onApplied}
              className="rounded-md bg-accent-500 px-3 py-1.5 text-sm font-medium text-white hover:bg-accent-600"
            >
              View in Rules
            </button>
            <button
              type="button"
              onClick={() => setSuccess(null)}
              className="rounded-md border border-ink-200 px-3 py-1.5 text-sm text-ink-700 hover:bg-ink-100"
            >
              Apply again
            </button>
          </div>
        </div>
      </Card>
    );
  }

  return (
    <Card title="Apply preset">
      <form onSubmit={submit} className="space-y-4">
        {error && (
          <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-800">
            {error}
          </div>
        )}

        {preset.variables.length === 0 ? (
          <div className="rounded-md border border-ink-200 bg-ink-50 px-3 py-2 text-xs text-ink-700">
            This preset declares no override hints — apply with defaults.
          </div>
        ) : (
          preset.variables.map((v) => (
            <VariableRow
              key={v.name}
              variable={v}
              value={vars[v.name] ?? ""}
              onChange={(val) => setVars((s) => ({ ...s, [v.name]: val }))}
            />
          ))
        )}

        <FormRow
          label="Applied to"
          help="API keys the rule(s) will be scoped to. Pick from existing keys, or add the special values 'self' (current key) or '*' (all keys, admin only). Empty list = current key."
        >
          <AppliedToPicker value={appliedTo} onChange={setAppliedTo} />
        </FormRow>

        <div className="flex gap-2 border-t border-ink-100 pt-3">
          <button
            type="submit"
            disabled={submitting}
            className="rounded-md bg-accent-500 px-3 py-1.5 text-sm font-medium text-white hover:bg-accent-600 disabled:opacity-50"
            data-testid="preset-form-submit"
          >
            {submitting ? "Applying…" : "Apply preset"}
          </button>
        </div>
      </form>
    </Card>
  );
}

function VariableRow({
  variable,
  value,
  onChange,
}: {
  variable: PresetVariableDetail;
  value: string;
  onChange: (v: string) => void;
}) {
  const testid = `preset-form-var-${variable.name}`;

  // bool → render a toggle/checkbox so the operator picks true/false
  // instead of typing the literal string. Internal value remains a
  // string ("true" / "false") so the rest of the apply path stays
  // string-keyed; SubstituteTyped coerces on the server.
  if (variable.type === "bool") {
    const checked = value === "true";
    return (
      <FormRow
        label={variable.name}
        required={variable.required}
        type={variable.type}
        help={variable.description}
      >
        <label className="inline-flex items-center gap-2 text-sm text-ink-700">
          <input
            type="checkbox"
            checked={checked}
            onChange={(e) => onChange(e.target.checked ? "true" : "false")}
            data-testid={testid}
          />
          <span>{checked ? "true" : "false"}</span>
        </label>
        {variable.default_value && (
          <Hint>default: {variable.default_value}</Hint>
        )}
      </FormRow>
    );
  }

  // *_list and json → textarea (multi-line values, often pasted from
  // elsewhere). Comma-separated for lists, raw JSON for json.
  if (
    variable.type === "address_list" ||
    variable.type === "bigint_list" ||
    variable.type === "json"
  ) {
    const placeholder =
      variable.default_value ||
      (variable.type === "json"
        ? '{"key": "value"}'
        : variable.type === "bigint_list"
          ? "100, 200, 300"
          : "0xabc..., 0xdef...");
    return (
      <FormRow
        label={variable.name}
        required={variable.required}
        type={variable.type}
        help={variable.description}
      >
        <textarea
          value={value}
          onChange={(e) => onChange(e.target.value)}
          rows={variable.type === "json" ? 4 : 2}
          placeholder={placeholder}
          className="w-full rounded-md border border-ink-300 px-2 py-1 font-mono text-xs"
          data-testid={testid}
        />
        {variable.default_value && (
          <Hint>default: {variable.default_value}</Hint>
        )}
      </FormRow>
    );
  }

  // address / bigint / bytes / bytes4 → monospace; everything else
  // (string / enum / duration) gets the default proportional input.
  const isMono =
    variable.type === "address" ||
    variable.type === "bigint" ||
    variable.type === "bytes" ||
    variable.type === "bytes4";
  const placeholder =
    variable.default_value ||
    (variable.type === "duration"
      ? "24h"
      : variable.type === "bigint"
        ? "1000000000000000000"
        : variable.type === "address"
          ? "0x..."
          : variable.type || "");
  return (
    <FormRow
      label={variable.name}
      required={variable.required}
      type={variable.type}
      help={variable.description}
    >
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className={`w-full rounded-md border border-ink-300 px-2 py-1 text-sm ${
          isMono ? "font-mono" : ""
        }`}
        data-testid={testid}
      />
      {variable.default_value && (
        <Hint>default: {variable.default_value}</Hint>
      )}
    </FormRow>
  );
}

function FormRow({
  label,
  required,
  type,
  help,
  children,
}: {
  label: string;
  required?: boolean;
  type?: string;
  help?: string;
  children: ReactNode;
}) {
  return (
    <div className="grid grid-cols-[180px_1fr] gap-4">
      <div className="pt-1">
        <label className="text-sm text-ink-700">
          {label}
          {required && <span className="ml-1 text-red-500">*</span>}
        </label>
        {type && (
          <div className="text-[10px] font-mono uppercase tracking-wider text-ink-500">
            {type}
          </div>
        )}
      </div>
      <div>
        {children}
        {help && <div className="mt-1 text-[11px] text-ink-500">{help}</div>}
      </div>
    </div>
  );
}

function Hint({ children }: { children: ReactNode }) {
  return (
    <div className="mt-1 font-mono text-[10px] text-ink-500">{children}</div>
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
