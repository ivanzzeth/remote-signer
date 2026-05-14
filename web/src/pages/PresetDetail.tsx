import { useState, type ReactNode } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { APIError } from "remote-signer-client";
import {
  Card,
  ErrorBanner,
  Loading,
  PageHeader,
} from "../components/ui";
import { getClient } from "../lib/auth";
import { useApi } from "../lib/useApi";

/**
 * Apply-a-preset form. /api/v1/presets/{id}/vars returns just the
 * variable names (override_hints), no type metadata — the preset YAML
 * encodes its own defaults and the operator only needs to surface the
 * ones marked overridable. We render each as a free-text input;
 * the daemon validates downstream.
 *
 * Apply returns one or more rule.id values (preset can fan out across
 * multiple templates). Success state lists them all and offers a
 * jump-to-rules action.
 */
export function PresetDetail() {
  const { id = "" } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { data, loading, error, reload } = useApi(
    (c) => c.presets.vars(id),
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

      <PageHeader
        title={id}
        subtitle="Fill the override variables; everything else uses the preset's defaults."
      />

      {loading && <Loading />}
      {error && <ErrorBanner msg={error} />}

      {data && (
        <ApplyForm
          presetID={id}
          hints={data.override_hints}
          onApplied={() => navigate("/rules")}
        />
      )}
    </div>
  );
}

interface ApplyResult {
  ruleID: string;
  ruleName: string;
}

function ApplyForm({
  presetID,
  hints,
  onApplied,
}: {
  presetID: string;
  hints: string[];
  onApplied: () => void;
}) {
  const [vars, setVars] = useState<Record<string, string>>(() =>
    Object.fromEntries(hints.map((h) => [h, ""])),
  );
  const [appliedTo, setAppliedTo] = useState("");
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
      // Strip empty values so the daemon's preset.ParsePresetFile
      // falls back to the YAML defaults; sending "" overrides those.
      const cleanVars: Record<string, string> = {};
      for (const [k, v] of Object.entries(vars)) {
        if (v !== "") cleanVars[k] = v;
      }
      const cleanApplied = appliedTo
        .split(",")
        .map((s) => s.trim())
        .filter((s) => s !== "");
      const resp = await c.presets.apply(presetID, {
        variables: cleanVars,
        applied_to: cleanApplied.length > 0 ? cleanApplied : undefined,
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

        {hints.length === 0 && (
          <div className="rounded-md border border-ink-200 bg-ink-50 px-3 py-2 text-xs text-ink-700">
            This preset declares no override hints — apply with defaults.
          </div>
        )}

        {hints.map((name) => (
          <FormRow
            key={name}
            label={name}
            help="Empty → preset default applies"
          >
            <input
              type="text"
              value={vars[name] ?? ""}
              onChange={(e) =>
                setVars((s) => ({ ...s, [name]: e.target.value }))
              }
              className="w-full rounded-md border border-ink-300 px-2 py-1 font-mono text-sm"
              data-testid={`preset-form-var-${name}`}
            />
          </FormRow>
        ))}

        <FormRow
          label="Applied to"
          help="Comma-separated API key IDs to scope the rule(s) to; empty = current key"
        >
          <input
            type="text"
            value={appliedTo}
            onChange={(e) => setAppliedTo(e.target.value)}
            placeholder="self / *  / key-id"
            className="w-full rounded-md border border-ink-300 px-2 py-1 font-mono text-sm"
            data-testid="preset-form-applied-to"
          />
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

function FormRow({
  label,
  help,
  children,
}: {
  label: string;
  help?: string;
  children: ReactNode;
}) {
  return (
    <div className="grid grid-cols-[160px_1fr] gap-4">
      <label className="pt-1 text-sm text-ink-700">{label}</label>
      <div>
        {children}
        {help && <div className="mt-1 text-[11px] text-ink-500">{help}</div>}
      </div>
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
