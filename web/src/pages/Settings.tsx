import { useEffect, useState } from "react";
import {
  APIError,
  SETTINGS_GROUPS,
  type SettingsGroup,
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
 * Per-group settings viewer + raw JSON editor. The editor PUTs the full
 * snapshot back; the daemon validates the shape. We deliberately don't
 * try to be schema-aware — settings shapes vary too much group-to-group
 * (durations as strings, nested objects for IPWhitelist/ApprovalGuard,
 * arrays of strings, etc.) and a typed form per group would be 9× the
 * code without proportional value for an admin who already understands
 * the YAML config shape.
 */
export function Settings() {
  const [groups, setGroups] = useState<Record<string, GroupState>>(() =>
    Object.fromEntries(SETTINGS_GROUPS.map((g) => [g, { status: "loading" }])),
  );

  function fetchOne(g: SettingsGroup) {
    const client = getClient();
    if (!client) return;
    setGroups((prev) => ({ ...prev, [g]: { status: "loading" } }));
    client.settings.get(g).then(
      (data) => setGroups((prev) => ({ ...prev, [g]: { status: "ok", data } })),
      (err) => {
        const msg =
          err instanceof APIError
            ? `HTTP ${err.statusCode}: ${err.message}`
            : err instanceof Error
              ? err.message
              : String(err);
        setGroups((prev) => ({ ...prev, [g]: { status: "error", msg } }));
      },
    );
  }

  useEffect(() => {
    const client = getClient();
    if (!client) return;
    let mounted = true;
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
        subtitle="Runtime-mutable configuration groups. Edits PUT the whole group; daemon validates the JSON shape."
      />

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        {SETTINGS_GROUPS.map((g) => (
          <GroupCard
            key={g}
            group={g}
            state={groups[g]}
            onSaved={() => fetchOne(g)}
          />
        ))}
      </div>
    </div>
  );
}

function GroupCard({
  group,
  state,
  onSaved,
}: {
  group: SettingsGroup;
  state: GroupState;
  onSaved: () => void;
}) {
  const [editing, setEditing] = useState(false);
  return (
    <Card
      title={group}
      actions={
        state?.status === "ok" && !editing ? (
          <button
            type="button"
            onClick={() => setEditing(true)}
            className="rounded-md border border-ink-200 px-2 py-0.5 text-xs text-ink-700 hover:bg-ink-100"
          >
            Edit
          </button>
        ) : null
      }
    >
      {!state || state.status === "loading" ? (
        <Loading />
      ) : state.status === "error" ? (
        <ErrorBanner msg={state.msg} />
      ) : editing ? (
        <GroupEditor
          group={group}
          initial={state.data}
          onCancel={() => setEditing(false)}
          onSaved={() => {
            setEditing(false);
            onSaved();
          }}
        />
      ) : (
        <GroupViewer data={state.data} />
      )}
    </Card>
  );
}

function GroupViewer({ data }: { data: SettingsSnapshot }) {
  const entries = Object.entries(data);
  if (entries.length === 0) return <Empty msg="empty group" />;
  return (
    <dl className="space-y-1 text-sm">
      {entries.map(([k, v]) => (
        <Row key={k} k={k} v={formatValue(v)} mono={isSimpleValue(v)} />
      ))}
    </dl>
  );
}

function GroupEditor({
  group,
  initial,
  onCancel,
  onSaved,
}: {
  group: SettingsGroup;
  initial: SettingsSnapshot;
  onCancel: () => void;
  onSaved: () => void;
}) {
  const [json, setJson] = useState(() => JSON.stringify(initial, null, 2));
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  async function save() {
    setError(null);
    let parsed: SettingsSnapshot;
    try {
      parsed = JSON.parse(json);
    } catch (e) {
      setError(e instanceof Error ? e.message : "JSON parse error");
      return;
    }
    const client = getClient();
    if (!client) return;
    setSaving(true);
    try {
      await client.settings.put(group, parsed);
      onSaved();
    } catch (e) {
      if (e instanceof APIError) {
        setError(`HTTP ${e.statusCode}: ${e.message}`);
      } else {
        setError(e instanceof Error ? e.message : String(e));
      }
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="space-y-2">
      <textarea
        value={json}
        onChange={(e) => setJson(e.target.value)}
        rows={Math.min(20, json.split("\n").length + 1)}
        spellCheck={false}
        className="block w-full rounded-md border border-ink-300 p-2 font-mono text-[11px]"
      />
      {error && <ErrorBanner msg={error} />}
      <div className="flex justify-end gap-2">
        <button
          type="button"
          onClick={onCancel}
          disabled={saving}
          className="rounded-md border border-ink-200 px-2 py-0.5 text-xs text-ink-700 hover:bg-ink-100 disabled:opacity-50"
        >
          Cancel
        </button>
        <button
          type="button"
          onClick={save}
          disabled={saving}
          className="rounded-md bg-accent-500 px-2 py-0.5 text-xs font-medium text-white hover:bg-accent-600 disabled:opacity-50"
        >
          {saving ? "Saving…" : "Save"}
        </button>
      </div>
    </div>
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
  return JSON.stringify(v);
}
