import { useMemo, useState } from "react";
import { useApi } from "../lib/useApi";

interface Option {
  value: string;
  label: string;
}

/**
 * Multi-entry picker for the `applied_to` scope. Backed by the live
 * /api/v1/api-keys roster so the operator picks from existing keys
 * instead of typing IDs (and typo'ing them). The two pseudo-values
 * the daemon understands are always offered:
 *
 *   self  — alias for the current API key (default semantics when the
 *           applied_to list is empty)
 *   *     — wildcard; admin only on the server side, but we leave the
 *           filtering to the daemon and just expose it here
 *
 * Already-selected entries are filtered out of the dropdown so the
 * operator can't add the same scope twice. Pills carry an ✕ to
 * remove; clearing the list reverts to "defaults to current key"
 * semantics.
 */
export function AppliedToPicker({
  value,
  onChange,
}: {
  value: string[];
  onChange: (next: string[]) => void;
}) {
  const apiKeys = useApi((c) => c.apiKeys.list({}), []);
  const [pending, setPending] = useState("");

  const available = useMemo(() => {
    const taken = new Set(value);
    const out: Option[] = [];
    if (!taken.has("self")) {
      out.push({ value: "self", label: "self · current API key" });
    }
    if (!taken.has("*")) {
      out.push({ value: "*", label: "* · all keys (admin only)" });
    }
    for (const k of apiKeys.data?.keys ?? []) {
      if (taken.has(k.id) || k.id === "self" || k.id === "*") continue;
      const label =
        k.name && k.name !== k.id ? `${k.id} · ${k.name}` : k.id;
      out.push({ value: k.id, label });
    }
    return out;
  }, [apiKeys.data, value]);

  function add() {
    const v = pending.trim();
    if (!v) return;
    if (value.includes(v)) return;
    onChange([...value, v]);
    setPending("");
  }

  function remove(v: string) {
    onChange(value.filter((x) => x !== v));
  }

  return (
    <div className="space-y-2" data-testid="applied-to-picker">
      <div className="flex flex-wrap gap-1">
        {value.length === 0 ? (
          <span className="text-xs text-ink-500">
            (empty — defaults to the current API key)
          </span>
        ) : (
          value.map((v) => (
            <span
              key={v}
              className="inline-flex items-center gap-1 rounded-full bg-ink-100 px-2 py-0.5 text-xs"
              data-testid={`applied-to-pill-${v}`}
            >
              <span className="font-mono">{v}</span>
              <button
                type="button"
                onClick={() => remove(v)}
                aria-label={`remove ${v}`}
                className="text-ink-500 hover:text-red-500"
              >
                ×
              </button>
            </span>
          ))
        )}
      </div>
      <div className="flex gap-2">
        <select
          value={pending}
          onChange={(e) => setPending(e.target.value)}
          className="flex-1 rounded-md border border-ink-300 px-2 py-1 text-xs"
          data-testid="applied-to-select"
          disabled={apiKeys.loading}
        >
          <option value="">
            {apiKeys.loading ? "Loading keys…" : "— select to add —"}
          </option>
          {available.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
        <button
          type="button"
          onClick={add}
          disabled={!pending}
          className="rounded-md bg-accent-500 px-3 py-1 text-xs font-medium text-white hover:bg-accent-600 disabled:opacity-50"
          data-testid="applied-to-add"
        >
          Add
        </button>
      </div>
    </div>
  );
}
