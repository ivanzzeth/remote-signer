import { Fragment, useState } from "react";
import {
  APIError,
  type APIKey,
  bytesToHex,
  derivePublicKey,
} from "remote-signer-client";
import {
  Badge,
  Card,
  Empty,
  ErrorBanner,
  Loading,
  PageHeader,
  shorten,
} from "../components/ui";
import { useConfirm } from "../components/feedback";
import { getClient } from "../lib/auth";
import { useCanManageAPIKeys } from "../lib/rbac";
import { useApi } from "../lib/useApi";

const ROLES = ["admin", "dev", "agent", "strategy"] as const;
type Role = (typeof ROLES)[number];

// PKCS#8 DER header for an Ed25519 private key: 16 bytes, followed by the
// 32-byte seed. Hand-coded so we don't need a crypto library to assemble
// the PEM the operator pastes back into the CLI / Login page.
const PKCS8_ED25519_HEADER = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
  0x04, 0x22, 0x04, 0x20,
]);

interface NewKeyState {
  apiKey: import("remote-signer-client").APIKey;
  seedPem: string;
  seedHex: string;
}

/**
 * Manage API keys (Ed25519). Create generates a fresh keypair in the
 * browser so the daemon only ever sees the public half; the private seed
 * is displayed once in a one-time panel and never persisted.
 */
export function ApiKeys() {
  const canManage = useCanManageAPIKeys();
  const confirm = useConfirm();
  const { data, loading, error, reload } = useApi((c) => c.apiKeys.list());
  const [mutationError, setMutationError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [newKey, setNewKey] = useState<NewKeyState | null>(null);
  const [editing, setEditing] = useState<string | null>(null);

  async function saveEdit(
    id: string,
    patch: { name?: string; role?: string; rate_limit?: number },
  ) {
    const client = getClient();
    if (!client) return;
    setBusy(id);
    setMutationError(null);
    try {
      await client.apiKeys.update(id, patch);
      setEditing(null);
      reload();
    } catch (e) {
      setMutationError(formatMutationError(e));
    } finally {
      setBusy(null);
    }
  }

  // --- mutations -----------------------------------------------------------

  async function toggle(id: string, currentEnabled: boolean) {
    const client = getClient();
    if (!client) return;
    setBusy(id);
    setMutationError(null);
    try {
      await client.apiKeys.update(id, { enabled: !currentEnabled });
      reload();
    } catch (e) {
      setMutationError(formatMutationError(e));
    } finally {
      setBusy(null);
    }
  }

  async function destroy(id: string) {
    const ok = await confirm({
      title: "Delete API key",
      message: `Delete API key "${id}"? This cannot be undone.`,
      confirmLabel: "Delete",
      tone: "danger",
    });
    if (!ok) return;
    const client = getClient();
    if (!client) return;
    setBusy(id);
    setMutationError(null);
    try {
      await client.apiKeys.delete(id);
      reload();
    } catch (e) {
      setMutationError(formatMutationError(e));
    } finally {
      setBusy(null);
    }
  }

  async function create(input: {
    id: string;
    name: string;
    role: Role;
    rateLimit?: number;
  }) {
    const client = getClient();
    if (!client) return;
    setMutationError(null);
    try {
      // Generate the seed in-browser; only the pubkey hits the wire.
      const seed = new Uint8Array(32);
      crypto.getRandomValues(seed);
      const pub = await derivePublicKey(seed);

      const apiKey = await client.apiKeys.create({
        id: input.id,
        name: input.name,
        public_key: bytesToHex(pub),
        role: input.role,
        ...(input.rateLimit !== undefined
          ? { rate_limit: input.rateLimit }
          : {}),
      });

      setNewKey({
        apiKey,
        seedPem: seedToPem(seed),
        seedHex: bytesToHex(seed),
      });
      setShowCreate(false);
      reload();
    } catch (e) {
      setMutationError(formatMutationError(e));
    }
  }

  // --- render --------------------------------------------------------------

  return (
    <div className="space-y-6">
      <PageHeader
        title="API Keys"
        subtitle="Ed25519 keys authorised to sign API requests."
        actions={
          <>
            <button
              type="button"
              onClick={() => setShowCreate((s) => !s)}
              disabled={!canManage}
              className="rounded-md bg-accent-500 px-3 py-1 text-xs font-medium text-white hover:bg-accent-600 disabled:opacity-50"
            >
              {showCreate ? "Cancel" : "New API key"}
            </button>
            <button
              type="button"
              onClick={reload}
              className="rounded-md border border-ink-200 px-3 py-1 text-xs text-ink-700 hover:bg-ink-100"
            >
              Refresh
            </button>
          </>
        }
      />

      {mutationError && <ErrorBanner msg={mutationError} />}

      {newKey && <NewKeyPanel state={newKey} onDismiss={() => setNewKey(null)} />}

      {showCreate && <CreateForm onSubmit={create} />}

      <Card>
        {loading && <Loading />}
        {error && <ErrorBanner msg={error} />}
        {data &&
          (data.keys.length === 0 ? (
            <Empty msg="No API keys registered." />
          ) : (
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase text-ink-500">
                <tr>
                  <th className="py-1 pr-3 font-normal">ID / Name</th>
                  <th className="py-1 pr-3 font-normal">Role</th>
                  <th className="py-1 pr-3 font-normal">Rate limit</th>
                  <th className="py-1 pr-3 font-normal">Source</th>
                  <th className="py-1 pr-3 font-normal">Last used</th>
                  <th className="py-1 pr-3 font-normal">Status</th>
                  <th className="py-1 font-normal">Actions</th>
                </tr>
              </thead>
              <tbody>
                {data.keys.map((k) => (
                  <Fragment key={k.id}>
                  <tr className="border-t border-ink-100">
                    <td className="py-1 pr-3">
                      <div className="font-mono text-xs text-ink-900">
                        {k.id}
                      </div>
                      {k.name && k.name !== k.id && (
                        <div className="text-[11px] text-ink-500">
                          {k.name}
                        </div>
                      )}
                    </td>
                    <td className="py-1 pr-3">
                      <Badge tone={k.role === "admin" ? "red" : "neutral"}>
                        {k.role}
                      </Badge>
                    </td>
                    <td className="py-1 pr-3 font-mono text-xs text-ink-700">
                      {k.rate_limit != null && k.rate_limit > 0
                        ? `${k.rate_limit}/min`
                        : "—"}
                    </td>
                    <td className="py-1 pr-3 text-xs text-ink-500">
                      {k.source}
                    </td>
                    <td className="py-1 pr-3 font-mono text-[11px] text-ink-700">
                      {k.last_used_at ? shorten(k.last_used_at, 19, 0) : "—"}
                    </td>
                    <td className="py-1 pr-3">
                      <Badge tone={k.enabled ? "green" : "neutral"}>
                        {k.enabled ? "enabled" : "disabled"}
                      </Badge>
                    </td>
                    <td className="py-1">
                      <div className="flex gap-2">
                        <button
                          type="button"
                          disabled={busy === k.id || !canManage}
                          onClick={() => toggle(k.id, k.enabled)}
                          className="rounded-md border border-ink-200 px-2 py-0.5 text-xs text-ink-700 hover:bg-ink-100 disabled:opacity-50"
                        >
                          {k.enabled ? "Disable" : "Enable"}
                        </button>
                        <button
                          type="button"
                          disabled={
                            busy === k.id || k.source !== "api" || !canManage
                          }
                          onClick={() =>
                            setEditing((id) => (id === k.id ? null : k.id))
                          }
                          title={
                            k.source !== "api"
                              ? "config-sourced keys can only be edited in config.yaml"
                              : ""
                          }
                          className="rounded-md border border-ink-200 px-2 py-0.5 text-xs text-ink-700 hover:bg-ink-100 disabled:opacity-50"
                        >
                          {editing === k.id ? "Cancel" : "Edit"}
                        </button>
                        <button
                          type="button"
                          disabled={
                            busy === k.id || k.id === "admin" || !canManage
                          }
                          onClick={() => destroy(k.id)}
                          title={
                            k.id === "admin"
                              ? "admin key cannot be deleted via UI"
                              : ""
                          }
                          className="rounded-md border border-red-200 px-2 py-0.5 text-xs text-red-700 hover:bg-red-50 disabled:opacity-50"
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                  {editing === k.id && (
                    <tr className="border-t border-ink-100 bg-ink-50">
                      <td colSpan={7} className="px-4 py-3">
                        <EditForm
                          apiKey={k}
                          busy={busy === k.id}
                          onCancel={() => setEditing(null)}
                          onSave={(patch) => saveEdit(k.id, patch)}
                        />
                      </td>
                    </tr>
                  )}
                  </Fragment>
                ))}
              </tbody>
            </table>
          ))}
      </Card>
    </div>
  );
}

function CreateForm({
  onSubmit,
}: {
  onSubmit: (v: { id: string; name: string; role: Role; rateLimit?: number }) => void;
}) {
  const [id, setId] = useState("");
  const [name, setName] = useState("");
  const [role, setRole] = useState<Role>("dev");
  const [rateLimit, setRateLimit] = useState("");

  return (
    <Card title="New API key">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          onSubmit({
            id: id.trim(),
            name: name.trim() || id.trim(),
            role,
            rateLimit: rateLimit ? Number(rateLimit) : undefined,
          });
        }}
        className="grid grid-cols-1 gap-3 md:grid-cols-4"
      >
        <Field label="ID" value={id} onChange={setId} required />
        <Field label="Name (optional)" value={name} onChange={setName} />
        <div>
          <label className="mb-1 block text-[11px] uppercase tracking-wide text-ink-500">
            Role
          </label>
          <select
            value={role}
            onChange={(e) => setRole(e.target.value as Role)}
            className="w-full rounded-md border border-ink-300 px-2 py-1 text-sm"
          >
            {ROLES.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
        </div>
        <Field
          label="Rate limit (req/min, optional)"
          value={rateLimit}
          onChange={setRateLimit}
          type="number"
        />
        <div className="md:col-span-4">
          <button
            type="submit"
            disabled={!id.trim()}
            className="rounded-md bg-accent-500 px-3 py-1.5 text-sm font-medium text-white hover:bg-accent-600 disabled:cursor-not-allowed disabled:bg-ink-300"
          >
            Generate keypair & create
          </button>
          <p className="mt-2 text-xs text-ink-500">
            The private key is generated in this browser tab and shown once
            below — save it before reloading.
          </p>
        </div>
      </form>
    </Card>
  );
}

function NewKeyPanel({
  state,
  onDismiss,
}: {
  state: NewKeyState;
  onDismiss: () => void;
}) {
  return (
    <section className="rounded-lg border-2 border-yellow-300 bg-yellow-50 p-5">
      <div className="mb-3 flex items-center justify-between">
        <h2 className="text-sm font-semibold text-yellow-900">
          Save the private key for &ldquo;{state.apiKey.id}&rdquo; now
        </h2>
        <button
          type="button"
          onClick={onDismiss}
          className="text-xs text-yellow-800 hover:text-yellow-950"
        >
          Dismiss
        </button>
      </div>
      <p className="mb-3 text-xs text-yellow-900">
        This is the only time the private key is shown. The daemon stores
        only the public half — losing this PEM means the key is unusable.
      </p>
      <details open className="mb-3">
        <summary className="cursor-pointer text-xs font-medium text-yellow-900">
          PKCS#8 PEM (paste into Login)
        </summary>
        <pre className="mt-2 max-w-full overflow-x-auto rounded border border-yellow-300 bg-white p-2 font-mono text-[11px] text-ink-900">
          {state.seedPem}
        </pre>
      </details>
      <details>
        <summary className="cursor-pointer text-xs font-medium text-yellow-900">
          Hex seed (32 bytes)
        </summary>
        <pre className="mt-2 break-all rounded border border-yellow-300 bg-white p-2 font-mono text-[11px] text-ink-900">
          {state.seedHex}
        </pre>
      </details>
    </section>
  );
}

function Field({
  label,
  value,
  onChange,
  required,
  type = "text",
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  required?: boolean;
  type?: string;
}) {
  return (
    <div>
      <label className="mb-1 block text-[11px] uppercase tracking-wide text-ink-500">
        {label}
      </label>
      <input
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        required={required}
        className="w-full rounded-md border border-ink-300 px-2 py-1 text-sm"
      />
    </div>
  );
}

function seedToPem(seed: Uint8Array): string {
  const der = new Uint8Array(PKCS8_ED25519_HEADER.length + 32);
  der.set(PKCS8_ED25519_HEADER, 0);
  der.set(seed, PKCS8_ED25519_HEADER.length);
  let bin = "";
  for (const b of der) bin += String.fromCharCode(b);
  const b64 = btoa(bin);
  // PEM wraps base64 at 64 chars per line; Ed25519 PKCS#8 is 48 bytes →
  // 64 base64 chars, so one line suffices but we keep the loop for clarity.
  const lines = b64.match(/.{1,64}/g) ?? [b64];
  return [
    "-----BEGIN PRIVATE KEY-----",
    ...lines,
    "-----END PRIVATE KEY-----",
  ].join("\n");
}

function EditForm({
  apiKey,
  busy,
  onCancel,
  onSave,
}: {
  apiKey: APIKey;
  busy: boolean;
  onCancel: () => void;
  onSave: (patch: { name?: string; role?: string; rate_limit?: number }) => void;
}) {
  const [name, setName] = useState(apiKey.name);
  const [role, setRole] = useState(apiKey.role);
  const [rateLimit, setRateLimit] = useState(String(apiKey.rate_limit ?? ""));

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        onSave({
          name: name.trim() || undefined,
          role,
          rate_limit: rateLimit ? Number(rateLimit) : undefined,
        });
      }}
      className="space-y-3"
    >
      <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
        <Field label="Name" value={name} onChange={setName} />
        <div>
          <label className="mb-1 block text-[11px] uppercase tracking-wide text-ink-500">
            Role
          </label>
          <select
            value={role}
            onChange={(e) => setRole(e.target.value)}
            className="w-full rounded-md border border-ink-300 px-2 py-1 text-sm"
          >
            {ROLES.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
        </div>
        <Field
          label="Rate limit (req/min)"
          value={rateLimit}
          onChange={setRateLimit}
          type="number"
        />
      </div>
      <div className="flex justify-end gap-2">
        <button
          type="button"
          onClick={onCancel}
          disabled={busy}
          className="rounded-md border border-ink-200 px-2 py-0.5 text-xs text-ink-700 hover:bg-ink-100 disabled:opacity-50"
        >
          Cancel
        </button>
        <button
          type="submit"
          disabled={busy}
          className="rounded-md bg-accent-500 px-2 py-0.5 text-xs font-medium text-white hover:bg-accent-600 disabled:opacity-50"
        >
          {busy ? "Saving…" : "Save"}
        </button>
      </div>
    </form>
  );
}

function formatMutationError(e: unknown): string {
  if (e instanceof APIError) return `HTTP ${e.statusCode}: ${e.message}`;
  if (e instanceof Error) return e.message;
  return String(e);
}
