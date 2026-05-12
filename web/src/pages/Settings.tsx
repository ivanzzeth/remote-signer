import { useEffect, useState } from "react";
import {
  APIError,
  SETTINGS_GROUPS,
  type SettingsSnapshot,
} from "remote-signer-client";
import {
  Card,
  Empty,
  ErrorBanner,
  Loading,
  PageHeader,
  Row,
} from "../components/ui";
import { getClient } from "../lib/auth";

type GroupState =
  | { status: "loading" }
  | { status: "ok"; data: SettingsSnapshot }
  | { status: "error"; msg: string };

/**
 * Read-only view over every runtime-mutable settings group the daemon
 * exposes. Each group renders as a card with one row per top-level key;
 * nested objects fall back to a JSON dump because the shape varies (and
 * the v0 viewer doesn't pretend to be a schema-aware editor — 8c will).
 */
export function Settings() {
  const [groups, setGroups] = useState<Record<string, GroupState>>(() =>
    Object.fromEntries(SETTINGS_GROUPS.map((g) => [g, { status: "loading" }])),
  );

  useEffect(() => {
    const client = getClient();
    if (!client) return;
    let mounted = true;
    // Fan out to all 9 groups in parallel — they're independent and
    // small. settle, not all, so one failed group doesn't blank the page.
    Promise.allSettled(
      SETTINGS_GROUPS.map((g) =>
        client.settings.get(g).then(
          (data) => ({ g, data }) as const,
          (err) => ({ g, err }) as const,
        ),
      ),
    ).then((results) => {
      if (!mounted) return;
      const next: Record<string, GroupState> = {};
      for (const r of results) {
        if (r.status !== "fulfilled") continue;
        const v = r.value;
        if ("err" in v) {
          const msg =
            v.err instanceof APIError
              ? `HTTP ${v.err.statusCode}: ${v.err.message}`
              : v.err instanceof Error
                ? v.err.message
                : String(v.err);
          next[v.g] = { status: "error", msg };
        } else {
          next[v.g] = { status: "ok", data: v.data };
        }
      }
      setGroups(next);
    });
    return () => {
      mounted = false;
    };
  }, []);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Settings"
        subtitle="Runtime-mutable configuration groups (read-only — edit via CLI for now)."
      />

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        {SETTINGS_GROUPS.map((g) => (
          <Card key={g} title={g}>
            <GroupCard state={groups[g]} />
          </Card>
        ))}
      </div>
    </div>
  );
}

function GroupCard({ state }: { state: GroupState }) {
  if (!state || state.status === "loading") return <Loading />;
  if (state.status === "error") return <ErrorBanner msg={state.msg} />;
  const entries = Object.entries(state.data);
  if (entries.length === 0) return <Empty msg="empty group" />;
  return (
    <dl className="space-y-1 text-sm">
      {entries.map(([k, v]) => (
        <Row key={k} k={k} v={formatValue(v)} mono={isSimpleValue(v)} />
      ))}
    </dl>
  );
}

function isSimpleValue(v: unknown): boolean {
  return (
    v === null ||
    typeof v === "string" ||
    typeof v === "number" ||
    typeof v === "boolean"
  );
}

function formatValue(v: unknown): string {
  if (v === null || v === undefined) return "—";
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  // Objects/arrays — show JSON; small enough since these are config snapshots.
  return JSON.stringify(v);
}
