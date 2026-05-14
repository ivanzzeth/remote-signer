import { useState } from "react";
import { Link } from "react-router-dom";
import { type PresetEntry } from "remote-signer-client";
import {
  Card,
  Empty,
  ErrorBanner,
  Loading,
  PageHeader,
} from "../components/ui";
import { useApi } from "../lib/useApi";

/**
 * Preset catalogue. Presets are pre-configured combinations of one or
 * more templates with sensible defaults baked in — apply a preset and
 * the daemon spins up the corresponding rule(s) + budgets + schedule
 * in one shot. Operators usually start here; they reach for raw
 * templates only when no preset fits.
 */
export function Presets() {
  const { data, loading, error, reload } = useApi(
    (c) => c.presets.list(),
    [],
  );
  const [filter, setFilter] = useState("");

  const all = data?.presets ?? [];
  const filtered = filter
    ? all.filter((p) =>
        p.id.toLowerCase().includes(filter.toLowerCase()) ||
        p.template_names.some((t) => t.toLowerCase().includes(filter.toLowerCase())),
      )
    : all;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Presets"
        subtitle="Pre-configured rule combinations — apply with a few variables and the daemon creates the rule(s), budgets, and schedule."
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
                placeholder="id or template name"
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
                  ? "No presets loaded. Check the daemon's presets.dir config and restart."
                  : "No presets match this filter."
              }
            />
          ) : (
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase text-ink-500">
                <tr>
                  <th className="py-1 pr-3 font-normal">ID</th>
                  <th className="py-1 pr-3 font-normal">Templates</th>
                  <th className="py-1 font-normal text-right">Action</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((p) => (
                  <PresetRow key={p.id} entry={p} />
                ))}
              </tbody>
            </table>
          )}
        </Card>
      )}
    </div>
  );
}

function PresetRow({ entry }: { entry: PresetEntry }) {
  return (
    <tr
      className="border-t border-ink-100 hover:bg-ink-50"
      data-testid={`preset-row-${entry.id}`}
    >
      <td className="py-1 pr-3 font-mono text-xs">
        <Link
          to={`/presets/${encodeURIComponent(entry.id)}`}
          className="text-ink-900 hover:text-accent-600"
        >
          {entry.id}
        </Link>
      </td>
      <td className="py-1 pr-3 text-xs text-ink-700">
        {entry.template_names.join(", ") || "—"}
      </td>
      <td className="py-1 text-right">
        <Link
          to={`/presets/${encodeURIComponent(entry.id)}`}
          className="text-[11px] text-accent-600 hover:text-accent-500"
        >
          apply →
        </Link>
      </td>
    </tr>
  );
}
