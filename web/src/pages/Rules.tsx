import { useState } from "react";
import { APIError } from "remote-signer-client";
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

/**
 * Lists every rule (whitelist/blocklist) registered on the daemon. This
 * is the operator's first stop when a sign request was unexpectedly
 * denied or auto-approved — the rule set is the source of truth.
 *
 * Mutations supported inline: toggle enabled, delete. Creating new rules
 * stays in the CLI for now — the rule shape varies enough by type that a
 * generic UI form would be more harm than help.
 */
export function Rules() {
  const { data, loading, error, reload } = useApi((c) => c.evm.rules.list());
  const [mutationError, setMutationError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

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
          <button
            type="button"
            onClick={reload}
            className="rounded-md border border-ink-200 px-3 py-1 text-xs text-ink-700 hover:bg-ink-100"
          >
            Refresh
          </button>
        }
      />

      {mutationError && <ErrorBanner msg={mutationError} />}

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

function formatMutationError(e: unknown): string {
  if (e instanceof APIError) return `HTTP ${e.statusCode}: ${e.message}`;
  if (e instanceof Error) return e.message;
  return String(e);
}
