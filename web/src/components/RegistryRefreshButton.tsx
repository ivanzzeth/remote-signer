import { useState } from "react";
import { APIError, type RegistryRefreshResponse } from "remote-signer-client";
import { useConfirm, useToast } from "./feedback";
import { ErrorBanner } from "./ui";
import { getClient } from "../lib/auth";
import { useCanRefreshRegistry } from "../lib/rbac";

/**
 * Re-sync templates + presets from on-disk YAML without restarting
 * the daemon. Admin/agent (apply_preset permission).
 */
export function RegistryRefreshButton({ onDone }: { onDone?: () => void }) {
  const canRefresh = useCanRefreshRegistry();
  const confirm = useConfirm();
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!canRefresh) return null;

  async function refresh() {
    const client = getClient();
    if (!client) return;
    const ok = await confirm({
      title: "Reload from disk",
      message:
        "Reload templates and presets from disk? Rows whose source files were removed may be pruned.",
      confirmLabel: "Reload",
    });
    if (!ok) return;

    setBusy(true);
    setError(null);
    try {
      const resp = await client.registry.refresh();
      toast({
        tone: "success",
        title: "Registry sync complete",
        description: formatRefreshSummary(resp),
      });
      onDone?.();
    } catch (e) {
      setError(formatErr(e));
      toast({
        tone: "error",
        title: "Registry sync failed",
        description: formatErr(e),
      });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-2">
      <button
        type="button"
        onClick={refresh}
        disabled={busy}
        data-testid="registry-refresh"
        className="rounded-md border border-ink-200 px-3 py-1 text-xs text-ink-700 hover:bg-ink-100 disabled:opacity-50"
      >
        {busy ? "Reloading…" : "Reload from disk"}
      </button>
      {error && <ErrorBanner msg={error} />}
    </div>
  );
}

function formatRefreshSummary(resp: RegistryRefreshResponse): string {
  const lines = [
    `templates: ${resp.templates.changed} changed, ${resp.templates.skipped} skipped, ${resp.templates.deleted} deleted`,
    `presets: ${resp.presets.changed} changed, ${resp.presets.skipped} skipped, ${resp.presets.deleted} deleted`,
  ];
  const templateErrors = resp.templates.errors?.length ?? 0;
  const presetErrors = resp.presets.errors?.length ?? 0;
  if (templateErrors > 0) {
    lines.push(`${templateErrors} template parse error(s) — check daemon logs.`);
  }
  if (presetErrors > 0) {
    lines.push(`${presetErrors} preset parse error(s).`);
  }
  return lines.join("\n");
}

function formatErr(e: unknown): string {
  if (e instanceof APIError) return `HTTP ${e.statusCode}: ${e.message}`;
  if (e instanceof Error) return e.message;
  return String(e);
}
