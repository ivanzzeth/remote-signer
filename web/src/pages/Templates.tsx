import { useState } from "react";
import { Link } from "react-router-dom";
import {
  APIError,
  type Template,
} from "remote-signer-client";
import {
  Badge,
  Card,
  Empty,
  ErrorBanner,
  Loading,
  PageHeader,
} from "../components/ui";
import { useApi } from "../lib/useApi";

/**
 * Rule template catalogue. Templates are the parameterised shapes the
 * daemon ships built-in (one *.template.*.yaml per behavior — ERC20
 * limits, WETH ops, Polymarket flows, etc.). Operators don't write
 * these; they pick one, fill the variables, and instantiate a rule.
 *
 * This list is the entry point; click into a row for the form.
 */
export function Templates() {
  const { data, loading, error, reload } = useApi((c) => c.templates.list({}), []);
  const [filter, setFilter] = useState("");

  const all = data?.templates ?? [];
  const lc = (s: string | undefined) => (s ?? "").toLowerCase();
  const fl = filter.toLowerCase();
  // ID is now meaningful (file-stem, e.g. "evm/erc20"), so search hits
  // it too — operators searching for "evm/" want chain-scoped templates.
  const filtered = filter
    ? all.filter(
        (t) =>
          lc(t.id).includes(fl) ||
          lc(t.name).includes(fl) ||
          lc(t.description).includes(fl) ||
          lc(t.chain_type).includes(fl),
      )
    : all;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Templates"
        subtitle="Parameterised rule shapes shipped with the daemon — pick one, fill the variables, get a concrete rule."
        actions={
          <button
            type="button"
            onClick={reload}
            className="rounded-md border border-ink-200 px-3 py-1 text-xs text-ink-700 hover:bg-ink-100"
          >
            Refresh
          </button>
        }
      />

      {loading && <Loading />}
      {error && <ErrorBanner msg={error} />}

      {data && (
        <Card>
          <div className="mb-4 flex flex-wrap items-end gap-3">
            <div className="flex-1 min-w-[200px]">
              <label className="mb-1 block text-[11px] uppercase tracking-wide text-ink-500">
                Search
              </label>
              <input
                type="text"
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                placeholder="id, name, description, or chain"
                className="w-full rounded-md border border-ink-300 px-2 py-1 text-sm"
              />
            </div>
            <div className="text-xs text-ink-500">
              {filtered.length} of {all.length}
            </div>
          </div>

          {filtered.length === 0 ? (
            <Empty
              msg={
                all.length === 0
                  ? "No templates loaded. Check the daemon's templates_dir config and restart."
                  : "No templates match this filter."
              }
            />
          ) : (
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase text-ink-500">
                <tr>
                  <th className="py-1 pr-3 font-normal">Name</th>
                  <th className="py-1 pr-3 font-normal">Chain</th>
                  <th className="py-1 pr-3 font-normal">Mode</th>
                  <th className="py-1 pr-3 font-normal">Vars</th>
                  <th className="py-1 pr-3 font-normal">Source</th>
                  <th className="py-1 font-normal text-right">Action</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((t) => (
                  <TemplateRow key={t.id} tmpl={t} />
                ))}
              </tbody>
            </table>
          )}
        </Card>
      )}
    </div>
  );
}

function TemplateRow({ tmpl }: { tmpl: Template }) {
  const varCount = tmpl.variables?.length ?? 0;
  const requiredCount = tmpl.variables?.filter((v) => v.required).length ?? 0;
  return (
    <tr
      className="border-t border-ink-100 hover:bg-ink-50"
      data-testid={`template-row-${tmpl.id}`}
    >
      <td className="py-1 pr-3">
        <Link
          to={`/templates/${encodeURIComponent(tmpl.id)}`}
          className="text-ink-900 hover:text-accent-600"
        >
          {tmpl.name}
        </Link>
        {tmpl.description && (
          <div className="text-[11px] text-ink-500">{tmpl.description.slice(0, 120)}</div>
        )}
        <div className="font-mono text-[10px] text-ink-500">{tmpl.id}</div>
      </td>
      <td className="py-1 pr-3">
        {tmpl.chain_type ? (
          <Badge>{tmpl.chain_type}</Badge>
        ) : (
          <span className="text-[11px] text-ink-500">off-chain</span>
        )}
      </td>
      <td className="py-1 pr-3">
        <Badge tone={tmpl.mode === "blocklist" ? "red" : "neutral"}>
          {tmpl.mode || "—"}
        </Badge>
      </td>
      <td className="py-1 pr-3 font-mono text-xs text-ink-700">
        {requiredCount}/{varCount}
      </td>
      <td className="py-1 pr-3 text-xs text-ink-700">{tmpl.source || "—"}</td>
      <td className="py-1 text-right">
        <Link
          to={`/templates/${encodeURIComponent(tmpl.id)}`}
          className="text-[11px] text-accent-600 hover:text-accent-500"
        >
          instantiate →
        </Link>
      </td>
    </tr>
  );
}

// Kept for parity with other pages that re-export their err formatter.
export function formatErr(e: unknown): string {
  if (e instanceof APIError) return `HTTP ${e.statusCode}: ${e.message}`;
  if (e instanceof Error) return e.message;
  return String(e);
}
