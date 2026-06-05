import { useEffect, useState } from "react";
import {
  APIError,
  SETTINGS_GROUPS,
  type SettingsGroup,
  type SettingsSnapshot,
} from "remote-signer-client";
import { PageHeader, Card, Empty, ErrorBanner, Loading } from "../components/ui";
import { AdminSecurityPanel } from "../components/AdminSecurityPanel";
import { getClient } from "../lib/auth";
import {
  formatDuration,
  isDurationField,
  parseDuration,
} from "../lib/settingsDuration";

type GroupState =
  | { status: "loading" }
  | { status: "ok"; data: SettingsSnapshot }
  | { status: "error"; msg: string };

/**
 * Runtime settings editor. Each of the daemon's nine groups gets a
 * typed form rendered from the JSON snapshot: booleans become
 * checkboxes, numbers in duration-flavoured fields render as "30s"
 * strings, string arrays render as one-per-line textareas, nested
 * objects recurse. Advanced operators still get a raw-JSON fallback
 * for fields the type-sniffer doesn't model.
 *
 * Left rail switches groups; saves are per-group via settings.put().
 */
export function Settings() {
  const [groups, setGroups] = useState<Record<string, GroupState>>(() =>
    Object.fromEntries(SETTINGS_GROUPS.map((g) => [g, { status: "loading" }])),
  );
  const [selected, setSelected] = useState<SettingsGroup>(SETTINGS_GROUPS[0]);

  function fetchOne(g: SettingsGroup) {
    const client = getClient();
    if (!client) return;
    setGroups((prev) => ({ ...prev, [g]: { status: "loading" } }));
    client.settings.get(g).then(
      (data) =>
        setGroups((prev) => ({ ...prev, [g]: { status: "ok", data } })),
      (err) => {
        setGroups((prev) => ({
          ...prev,
          [g]: { status: "error", msg: formatErr(err) },
        }));
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
        next[v.g] =
          "err" in v
            ? { status: "error", msg: formatErr(v.err) }
            : { status: "ok", data: v.data };
      }
      setGroups(next);
    });
    return () => {
      mounted = false;
    };
  }, []);

  const selectedState = groups[selected];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Settings"
        subtitle="Runtime-mutable configuration. Saved per group; the daemon validates each PUT."
      />

      <AdminSecurityPanel />

      <div className="grid grid-cols-1 gap-4 md:grid-cols-[14rem_1fr]">
        <nav className="rounded-lg border border-ink-200 bg-white p-2">
          {SETTINGS_GROUPS.map((g) => {
            const state = groups[g];
            const dot =
              state?.status === "error"
                ? "bg-red-400"
                : state?.status === "loading"
                  ? "bg-ink-300 animate-pulse"
                  : "bg-green-400";
            return (
              <button
                key={g}
                type="button"
                onClick={() => setSelected(g)}
                className={`flex w-full items-center justify-between rounded px-3 py-1.5 text-left text-sm transition ${
                  selected === g
                    ? "bg-accent-500 text-white"
                    : "text-ink-700 hover:bg-ink-100"
                }`}
              >
                <span className="truncate font-mono text-xs">{g}</span>
                <span
                  className={`h-1.5 w-1.5 rounded-full ${dot}`}
                  aria-hidden
                />
              </button>
            );
          })}
        </nav>

        <Card title={selected}>
          {selectedState?.status === "loading" || !selectedState ? (
            <Loading />
          ) : selectedState.status === "error" ? (
            <ErrorBanner msg={selectedState.msg} />
          ) : (
            <GroupEditor
              key={selected}
              group={selected}
              initial={selectedState.data}
              onSaved={() => fetchOne(selected)}
            />
          )}
        </Card>
      </div>
    </div>
  );
}

// --- Editor -----------------------------------------------------------------

function GroupEditor({
  group,
  initial,
  onSaved,
}: {
  group: SettingsGroup;
  initial: SettingsSnapshot;
  onSaved: () => void;
}) {
  const [value, setValue] = useState<SettingsSnapshot>(() =>
    structuredClone(initial),
  );
  const [advanced, setAdvanced] = useState(false);
  const [rawJson, setRawJson] = useState(() =>
    JSON.stringify(initial, null, 2),
  );
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const dirty = JSON.stringify(value) !== JSON.stringify(initial);

  function setField(path: string[], v: unknown) {
    setValue((prev) => {
      const next = structuredClone(prev) as Record<string, unknown>;
      let cur: Record<string, unknown> = next;
      for (let i = 0; i < path.length - 1; i++) {
        cur = cur[path[i]] as Record<string, unknown>;
      }
      cur[path[path.length - 1]] = v;
      return next as SettingsSnapshot;
    });
  }

  async function save() {
    setError(null);
    let payload = value;
    if (advanced) {
      try {
        payload = JSON.parse(rawJson);
      } catch (e) {
        setError(e instanceof Error ? e.message : "invalid JSON");
        return;
      }
    }
    const client = getClient();
    if (!client) return;
    setSaving(true);
    try {
      await client.settings.put(group, payload);
      onSaved();
    } catch (e) {
      setError(formatErr(e));
    } finally {
      setSaving(false);
    }
  }

  const entries = Object.entries(value);

  return (
    <div className="space-y-4">
      {advanced ? (
        <textarea
          value={rawJson}
          onChange={(e) => setRawJson(e.target.value)}
          rows={Math.min(24, rawJson.split("\n").length + 1)}
          spellCheck={false}
          className="block w-full rounded-md border border-ink-300 p-2 font-mono text-[11px]"
        />
      ) : group === "notify" ? (
        <NotifyEditor
          value={value}
          onChange={(next) => setValue(next)}
        />
      ) : entries.length === 0 ? (
        <Empty msg="empty group" />
      ) : (
        <dl className="space-y-2 text-sm">
          {entries.map(([k, v]) => (
            <FieldRow
              key={k}
              path={[k]}
              fieldKey={k}
              value={v}
              onChange={setField}
            />
          ))}
        </dl>
      )}

      {error && <ErrorBanner msg={error} />}

      <div className="flex items-center justify-between border-t border-ink-200 pt-3">
        <label className="flex items-center gap-2 text-xs text-ink-500">
          <input
            type="checkbox"
            checked={advanced}
            onChange={(e) => {
              const next = e.target.checked;
              if (next) {
                setRawJson(JSON.stringify(value, null, 2));
              } else {
                try {
                  setValue(JSON.parse(rawJson));
                } catch {
                  // ignore — let the user fix invalid JSON before flipping back
                }
              }
              setAdvanced(next);
            }}
          />
          Advanced (raw JSON)
        </label>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={() => {
              setValue(structuredClone(initial));
              setRawJson(JSON.stringify(initial, null, 2));
              setError(null);
            }}
            disabled={!dirty && rawJson === JSON.stringify(initial, null, 2)}
            className="rounded-md border border-ink-200 px-3 py-1 text-xs text-ink-700 hover:bg-ink-100 disabled:opacity-50"
          >
            Reset
          </button>
          <button
            type="button"
            onClick={save}
            disabled={saving}
            className="rounded-md bg-accent-500 px-3 py-1 text-xs font-medium text-white hover:bg-accent-600 disabled:opacity-50"
          >
            {saving ? "Saving…" : "Save"}
          </button>
        </div>
      </div>
    </div>
  );
}

// --- Field rendering --------------------------------------------------------

function FieldRow({
  path,
  fieldKey,
  value,
  onChange,
}: {
  path: string[];
  fieldKey: string;
  value: unknown;
  onChange: (path: string[], v: unknown) => void;
}) {
  // Nested object → indent + recurse. Skip arrays here (handled below).
  if (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value)
  ) {
    const obj = value as Record<string, unknown>;
    const entries = Object.entries(obj);
    return (
      <div className="rounded-md border border-ink-200 p-3">
        <div className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-ink-500">
          {fieldKey}
        </div>
        {entries.length === 0 ? (
          <p className="text-xs text-ink-500">empty</p>
        ) : (
          <dl className="space-y-2">
            {entries.map(([k, v]) => (
              <FieldRow
                key={k}
                path={[...path, k]}
                fieldKey={k}
                value={v}
                onChange={onChange}
              />
            ))}
          </dl>
        )}
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 items-center gap-1 md:grid-cols-[16rem_1fr]">
      <dt className="font-mono text-xs text-ink-500">{fieldKey}</dt>
      <dd>
        <FieldInput
          fieldKey={fieldKey}
          value={value}
          onChange={(v) => onChange(path, v)}
        />
      </dd>
    </div>
  );
}

function FieldInput({
  fieldKey,
  value,
  onChange,
}: {
  fieldKey: string;
  value: unknown;
  onChange: (v: unknown) => void;
}) {
  // Boolean → toggle.
  if (typeof value === "boolean") {
    return (
      <label className="inline-flex items-center gap-2 text-sm">
        <input
          type="checkbox"
          checked={value}
          onChange={(e) => onChange(e.target.checked)}
          className="h-4 w-4"
        />
        <span className="text-ink-700">{value ? "true" : "false"}</span>
      </label>
    );
  }

  // Duration-like number → "30s" input with parsing.
  if (isDurationField(fieldKey, value)) {
    return <DurationInput value={value as number} onChange={onChange} />;
  }

  // Plain number.
  if (typeof value === "number") {
    return (
      <input
        type="number"
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
        className="w-48 rounded-md border border-ink-300 px-2 py-1 text-sm"
      />
    );
  }

  // String[] → newline-separated textarea.
  if (Array.isArray(value)) {
    const joined = value.map((v) => String(v)).join("\n");
    return (
      <textarea
        value={joined}
        onChange={(e) => {
          const next = e.target.value
            .split("\n")
            .map((s) => s.trim())
            .filter(Boolean);
          onChange(next);
        }}
        rows={Math.max(2, value.length + 1)}
        spellCheck={false}
        className="block w-full rounded-md border border-ink-300 p-2 font-mono text-xs"
        placeholder="one entry per line"
      />
    );
  }

  // null → empty text input that materialises into a string on type.
  if (value === null) {
    return (
      <input
        type="text"
        value=""
        onChange={(e) => onChange(e.target.value)}
        className="w-full rounded-md border border-ink-300 px-2 py-1 text-sm"
        placeholder="null"
      />
    );
  }

  // String fallback.
  return (
    <input
      type="text"
      value={String(value)}
      onChange={(e) => onChange(e.target.value)}
      className="w-full rounded-md border border-ink-300 px-2 py-1 text-sm font-mono"
    />
  );
}

function DurationInput({
  value,
  onChange,
}: {
  value: number;
  onChange: (v: number) => void;
}) {
  const [text, setText] = useState(() => formatDuration(value));
  const [bad, setBad] = useState(false);

  useEffect(() => {
    setText(formatDuration(value));
    setBad(false);
  }, [value]);

  return (
    <div className="flex items-center gap-2">
      <input
        type="text"
        value={text}
        onChange={(e) => {
          const t = e.target.value;
          setText(t);
          const parsed = parseDuration(t);
          if (parsed === null) {
            setBad(true);
          } else {
            setBad(false);
            onChange(parsed);
          }
        }}
        className={`w-32 rounded-md border px-2 py-1 text-sm font-mono ${
          bad ? "border-red-400" : "border-ink-300"
        }`}
        placeholder="30s"
      />
      <span className="text-[11px] text-ink-500">
        {bad ? "use e.g. 30s, 5m, 1h" : "ns under the hood"}
      </span>
    </div>
  );
}

// --- Notify-specific editor -------------------------------------------------
//
// notify's wire shape is `{providers: {slack?, pushover?, webhook?, telegram?},
// channels: {slack?, pushover?, webhook?, telegram?}}` — every leaf is
// optional and the snapshot is `{providers:{}, channels:{}}` until the
// operator configures something. The generic field-shape sniffer can't
// suggest provider keys out of thin air, so notify gets a typed form
// keyed off the daemon's NotifySnapshot struct.

type NotifyProviderKind = "slack" | "pushover" | "webhook" | "telegram";
const PROVIDER_KINDS: NotifyProviderKind[] = [
  "slack",
  "pushover",
  "webhook",
  "telegram",
];

type NotifyProviders = Partial<Record<NotifyProviderKind, Record<string, unknown>>>;
type NotifyChannels = Partial<Record<NotifyProviderKind, string[]>>;

function NotifyEditor({
  value,
  onChange,
}: {
  value: SettingsSnapshot;
  onChange: (next: SettingsSnapshot) => void;
}) {
  const providers = (value.providers ?? {}) as NotifyProviders;
  const channels = (value.channels ?? {}) as NotifyChannels;

  function setProvider(kind: NotifyProviderKind, patch: Record<string, unknown> | null) {
    const nextProviders = { ...providers };
    if (patch === null) {
      delete nextProviders[kind];
    } else {
      nextProviders[kind] = patch;
    }
    onChange({ ...value, providers: nextProviders });
  }

  function setChannel(kind: NotifyProviderKind, recipients: string[]) {
    const nextChannels = { ...channels };
    if (recipients.length === 0) {
      delete nextChannels[kind];
    } else {
      nextChannels[kind] = recipients;
    }
    onChange({ ...value, channels: nextChannels });
  }

  return (
    <div className="space-y-6">
      <section>
        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-ink-500">
          Providers
        </h3>
        <div className="space-y-3">
          {PROVIDER_KINDS.map((kind) => (
            <ProviderCard
              key={kind}
              kind={kind}
              config={providers[kind] ?? null}
              onChange={(patch) => setProvider(kind, patch)}
            />
          ))}
        </div>
      </section>

      <section>
        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-ink-500">
          Channels (recipients per provider)
        </h3>
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          {PROVIDER_KINDS.map((kind) => (
            <ChannelInput
              key={kind}
              kind={kind}
              recipients={channels[kind] ?? []}
              onChange={(next) => setChannel(kind, next)}
            />
          ))}
        </div>
      </section>
    </div>
  );
}

const PROVIDER_DEFAULTS: Record<NotifyProviderKind, Record<string, unknown>> = {
  slack: { enabled: true, bot_token: "" },
  pushover: {
    enabled: true,
    app_token: "",
    retry: 60,
    expire: 3600,
    max_retries: 3,
    retry_delay: 5,
  },
  webhook: { enabled: true, headers: {}, timeout: 5_000_000_000 },
  telegram: { enabled: true, bot_token: "" },
};

const PROVIDER_LABELS: Record<NotifyProviderKind, string> = {
  slack: "Slack",
  pushover: "Pushover",
  webhook: "Webhook",
  telegram: "Telegram",
};

function ProviderCard({
  kind,
  config,
  onChange,
}: {
  kind: NotifyProviderKind;
  config: Record<string, unknown> | null;
  onChange: (next: Record<string, unknown> | null) => void;
}) {
  const present = config !== null;
  return (
    <div
      className={`rounded-md border p-3 ${
        present ? "border-ink-300 bg-white" : "border-ink-200 bg-ink-50"
      }`}
    >
      <label className="flex items-center justify-between gap-3">
        <span className="text-sm font-medium text-ink-900">
          {PROVIDER_LABELS[kind]}
        </span>
        <span className="inline-flex items-center gap-2 text-xs text-ink-500">
          <input
            type="checkbox"
            checked={present}
            onChange={(e) =>
              onChange(e.target.checked ? PROVIDER_DEFAULTS[kind] : null)
            }
            className="h-4 w-4"
          />
          {present ? "configured" : "not configured"}
        </span>
      </label>

      {present && (
        <div className="mt-3 space-y-2">
          {Object.entries(config).map(([k, v]) => (
            <ProviderField
              key={k}
              fieldKey={k}
              value={v}
              onChange={(next) => onChange({ ...config, [k]: next })}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function ProviderField({
  fieldKey,
  value,
  onChange,
}: {
  fieldKey: string;
  value: unknown;
  onChange: (v: unknown) => void;
}) {
  // Webhook headers is a string→string map; render as a small KV editor.
  if (
    fieldKey === "headers" &&
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value)
  ) {
    return (
      <HeadersEditor
        value={value as Record<string, string>}
        onChange={onChange}
      />
    );
  }
  return (
    <div className="grid grid-cols-1 items-center gap-1 md:grid-cols-[12rem_1fr]">
      <span className="font-mono text-[11px] text-ink-500">{fieldKey}</span>
      <FieldInput
        fieldKey={fieldKey}
        value={value}
        onChange={onChange}
      />
    </div>
  );
}

function HeadersEditor({
  value,
  onChange,
}: {
  value: Record<string, string>;
  onChange: (v: Record<string, string>) => void;
}) {
  const entries = Object.entries(value);
  const [newKey, setNewKey] = useState("");
  const [newVal, setNewVal] = useState("");
  return (
    <div className="grid grid-cols-1 gap-1 md:grid-cols-[12rem_1fr]">
      <span className="font-mono text-[11px] text-ink-500">headers</span>
      <div className="space-y-1">
        {entries.length === 0 && (
          <div className="text-[11px] text-ink-500">no headers</div>
        )}
        {entries.map(([k, v]) => (
          <div key={k} className="flex items-center gap-2">
            <input
              type="text"
              value={k}
              readOnly
              className="w-40 rounded-md border border-ink-200 bg-ink-50 px-2 py-1 font-mono text-xs"
            />
            <input
              type="text"
              value={v}
              onChange={(e) => onChange({ ...value, [k]: e.target.value })}
              className="flex-1 rounded-md border border-ink-300 px-2 py-1 text-xs"
            />
            <button
              type="button"
              onClick={() => {
                const next = { ...value };
                delete next[k];
                onChange(next);
              }}
              className="rounded-md border border-red-200 px-2 py-0.5 text-xs text-red-700 hover:bg-red-50"
            >
              ×
            </button>
          </div>
        ))}
        <div className="flex items-center gap-2 border-t border-ink-100 pt-1">
          <input
            type="text"
            value={newKey}
            onChange={(e) => setNewKey(e.target.value)}
            placeholder="X-Header"
            className="w-40 rounded-md border border-ink-300 px-2 py-1 font-mono text-xs"
          />
          <input
            type="text"
            value={newVal}
            onChange={(e) => setNewVal(e.target.value)}
            placeholder="value"
            className="flex-1 rounded-md border border-ink-300 px-2 py-1 text-xs"
          />
          <button
            type="button"
            disabled={!newKey.trim()}
            onClick={() => {
              onChange({ ...value, [newKey.trim()]: newVal });
              setNewKey("");
              setNewVal("");
            }}
            className="rounded-md bg-accent-500 px-2 py-0.5 text-xs font-medium text-white hover:bg-accent-600 disabled:opacity-50"
          >
            Add
          </button>
        </div>
      </div>
    </div>
  );
}

function ChannelInput({
  kind,
  recipients,
  onChange,
}: {
  kind: NotifyProviderKind;
  recipients: string[];
  onChange: (next: string[]) => void;
}) {
  return (
    <div>
      <label className="mb-1 block text-[11px] uppercase tracking-wide text-ink-500">
        {PROVIDER_LABELS[kind]}
      </label>
      <textarea
        value={recipients.join("\n")}
        onChange={(e) =>
          onChange(
            e.target.value
              .split("\n")
              .map((s) => s.trim())
              .filter(Boolean),
          )
        }
        rows={3}
        spellCheck={false}
        placeholder={recipientPlaceholder(kind)}
        className="block w-full rounded-md border border-ink-300 p-2 font-mono text-[11px]"
      />
    </div>
  );
}

function recipientPlaceholder(kind: NotifyProviderKind): string {
  switch (kind) {
    case "slack":
      return "#alerts\nU0123ABC";
    case "telegram":
      return "@channel_id\n123456789";
    case "pushover":
      return "user-key-1";
    case "webhook":
      return "https://hooks.example.com/abc";
  }
}

function formatErr(e: unknown): string {
  if (e instanceof APIError) return `HTTP ${e.statusCode}: ${e.message}`;
  if (e instanceof Error) return e.message;
  return String(e);
}
