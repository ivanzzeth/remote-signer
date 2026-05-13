import { Fragment, useState } from "react";
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
 * EVM signers: list + create + unlock/lock + approve + delete. Mirrors the
 * `remote-signer signer …` CLI surface so an operator can do the same
 * daily work without dropping into a terminal.
 *
 * Passwords are typed inline (unlock dialog) rather than being kept in
 * memory across actions; the SDK transports them server-side over the
 * signed HTTPS body.
 */
export function Signers() {
  const { data, loading, error, reload } = useApi((c) => c.evm.signers.list());
  const [mutationError, setMutationError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [unlockTarget, setUnlockTarget] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);

  async function create(input: {
    password: string;
    displayName: string;
    tags: string[];
    privateKeyHex?: string;
  }) {
    const client = getClient();
    if (!client) return;
    setMutationError(null);
    try {
      await client.evm.signers.create({
        type: "keystore",
        keystore: {
          password: input.password,
          ...(input.privateKeyHex
            ? { private_key_hex: input.privateKeyHex }
            : {}),
        },
        ...(input.displayName ? { display_name: input.displayName } : {}),
        ...(input.tags.length ? { tags: input.tags } : {}),
      });
      setShowCreate(false);
      reload();
    } catch (e) {
      setMutationError(formatErr(e));
    }
  }

  async function unlock(address: string, password: string) {
    const client = getClient();
    if (!client) return;
    setBusy(address);
    setMutationError(null);
    try {
      await client.evm.signers.unlock(address, { password });
      setUnlockTarget(null);
      reload();
    } catch (e) {
      setMutationError(formatErr(e));
    } finally {
      setBusy(null);
    }
  }

  async function lock(address: string) {
    const client = getClient();
    if (!client) return;
    setBusy(address);
    setMutationError(null);
    try {
      await client.evm.signers.lock(address);
      reload();
    } catch (e) {
      setMutationError(formatErr(e));
    } finally {
      setBusy(null);
    }
  }

  async function approveSigner(address: string) {
    const client = getClient();
    if (!client) return;
    setBusy(address);
    setMutationError(null);
    try {
      await client.evm.signers.approveSigner(address);
      reload();
    } catch (e) {
      setMutationError(formatErr(e));
    } finally {
      setBusy(null);
    }
  }

  async function destroy(address: string) {
    if (
      !confirm(
        `Delete signer ${address}? Ownership and access records are removed; the keystore on disk is untouched.`,
      )
    )
      return;
    const client = getClient();
    if (!client) return;
    setBusy(address);
    setMutationError(null);
    try {
      await client.evm.signers.deleteSigner(address);
      reload();
    } catch (e) {
      setMutationError(formatErr(e));
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Signers"
        subtitle="EVM signing keys this daemon can use to sign transactions and messages."
        actions={
          <>
            <button
              type="button"
              onClick={() => setShowCreate((s) => !s)}
              className="rounded-md bg-accent-500 px-3 py-1 text-xs font-medium text-white hover:bg-accent-600"
            >
              {showCreate ? "Cancel" : "New signer"}
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

      {showCreate && <CreateForm onSubmit={create} />}

      <Card>
        {loading && <Loading />}
        {error && <ErrorBanner msg={error} />}
        {data &&
          (data.signers.length === 0 ? (
            <Empty msg="No signers configured. Click New signer to generate a fresh keystore-backed key." />
          ) : (
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase text-ink-500">
                <tr>
                  <th className="py-1 pr-3 font-normal">Address</th>
                  <th className="py-1 pr-3 font-normal">Type</th>
                  <th className="py-1 pr-3 font-normal">Enabled</th>
                  <th className="py-1 pr-3 font-normal">Locked</th>
                  <th className="py-1 pr-3 font-normal">Ownership</th>
                  <th className="py-1 font-normal">Actions</th>
                </tr>
              </thead>
              <tbody>
                {data.signers.map((s) => (
                  <Fragment key={s.address}>
                  <tr
                    className="cursor-pointer border-t border-ink-100 hover:bg-ink-50"
                    onClick={() =>
                      setExpanded((id) => (id === s.address ? null : s.address))
                    }
                  >
                    <td className="py-1 pr-3">
                      <div className="font-mono text-xs text-ink-900">
                        {s.address}
                      </div>
                      {s.display_name && (
                        <div className="text-[11px] text-ink-500">
                          {s.display_name}
                        </div>
                      )}
                    </td>
                    <td className="py-1 pr-3 text-ink-700">{s.type}</td>
                    <td className="py-1 pr-3">
                      <Badge tone={s.enabled ? "green" : "neutral"}>
                        {s.enabled ? "enabled" : "disabled"}
                      </Badge>
                    </td>
                    <td className="py-1 pr-3">
                      <Badge tone={s.locked ? "red" : "green"}>
                        {s.locked ? "locked" : "unlocked"}
                      </Badge>
                    </td>
                    <td className="py-1 pr-3 text-xs text-ink-700">
                      {s.status === "pending_approval" ? (
                        <Badge tone="yellow">pending_approval</Badge>
                      ) : (
                        s.status || "active"
                      )}
                    </td>
                    <td className="py-1">
                      <div
                        className="flex flex-wrap gap-2"
                        onClick={(e) => e.stopPropagation()}
                      >
                        {s.locked ? (
                          <button
                            type="button"
                            disabled={busy === s.address}
                            onClick={() => setUnlockTarget(s.address)}
                            className="rounded-md border border-ink-200 px-2 py-0.5 text-xs text-ink-700 hover:bg-ink-100 disabled:opacity-50"
                          >
                            Unlock
                          </button>
                        ) : (
                          <button
                            type="button"
                            disabled={busy === s.address}
                            onClick={() => lock(s.address)}
                            className="rounded-md border border-ink-200 px-2 py-0.5 text-xs text-ink-700 hover:bg-ink-100 disabled:opacity-50"
                          >
                            Lock
                          </button>
                        )}
                        {s.status === "pending_approval" && (
                          <button
                            type="button"
                            disabled={busy === s.address}
                            onClick={() => approveSigner(s.address)}
                            className="rounded-md bg-accent-500 px-2 py-0.5 text-xs font-medium text-white hover:bg-accent-600 disabled:opacity-50"
                          >
                            Approve
                          </button>
                        )}
                        <button
                          type="button"
                          disabled={busy === s.address}
                          onClick={() => destroy(s.address)}
                          className="rounded-md border border-red-200 px-2 py-0.5 text-xs text-red-700 hover:bg-red-50 disabled:opacity-50"
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                  {expanded === s.address && (
                    <tr className="border-t border-ink-100 bg-ink-50">
                      <td colSpan={6} className="px-4 py-3">
                        <AccessPanel address={s.address} />
                      </td>
                    </tr>
                  )}
                  </Fragment>
                ))}
              </tbody>
            </table>
          ))}
      </Card>

      {unlockTarget && (
        <UnlockDialog
          address={unlockTarget}
          busy={busy === unlockTarget}
          onCancel={() => setUnlockTarget(null)}
          onSubmit={(password) => unlock(unlockTarget, password)}
        />
      )}
    </div>
  );
}

function CreateForm({
  onSubmit,
}: {
  onSubmit: (v: {
    password: string;
    displayName: string;
    tags: string[];
    privateKeyHex?: string;
  }) => void;
}) {
  const [mode, setMode] = useState<"generate" | "import">("generate");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [privateKeyHex, setPrivateKeyHex] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [tagsCsv, setTagsCsv] = useState("");
  const [error, setError] = useState<string | null>(null);

  function submit(e: React.FormEvent) {
    e.preventDefault();
    if (password !== confirmPassword) {
      setError("passwords do not match");
      return;
    }
    if (password.length < 8) {
      setError("password must be at least 8 characters");
      return;
    }
    let hex: string | undefined;
    if (mode === "import") {
      hex = privateKeyHex.trim().replace(/^0x/i, "");
      if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
        setError("private key must be 64 hex chars (with or without 0x)");
        return;
      }
    }
    setError(null);
    const tags = tagsCsv
      .split(",")
      .map((t) => t.trim())
      .filter(Boolean);
    onSubmit({
      password,
      displayName: displayName.trim(),
      tags,
      privateKeyHex: hex,
    });
  }

  return (
    <Card title="New signer">
      <form onSubmit={submit} className="space-y-3">
        <div className="flex gap-2 rounded-md border border-ink-200 bg-ink-50 p-1">
          {(["generate", "import"] as const).map((m) => (
            <button
              key={m}
              type="button"
              onClick={() => setMode(m)}
              className={`flex-1 rounded px-3 py-1 text-xs font-medium transition ${
                mode === m
                  ? "bg-white text-ink-900 shadow-sm"
                  : "text-ink-500 hover:text-ink-900"
              }`}
            >
              {m === "generate" ? "Generate fresh keypair" : "Import private key"}
            </button>
          ))}
        </div>

        {mode === "import" && (
          <div>
            <label className="mb-1 block text-[11px] uppercase tracking-wide text-ink-500">
              Private key (hex, with or without 0x)
            </label>
            <input
              type="password"
              value={privateKeyHex}
              onChange={(e) => setPrivateKeyHex(e.target.value)}
              required
              autoComplete="off"
              spellCheck={false}
              placeholder="0x…"
              className="w-full rounded-md border border-ink-300 px-2 py-1 font-mono text-xs"
            />
            <p className="mt-1 text-[11px] text-ink-500">
              Treated as sensitive — the input is masked. The hex bytes leave
              the browser exactly once over the signed HTTPS body; the daemon
              encrypts them into a v3 keystore on disk.
            </p>
          </div>
        )}

        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          <Field
            label="Keystore password"
            type="password"
            value={password}
            onChange={setPassword}
            required
            autoComplete="new-password"
          />
          <Field
            label="Confirm password"
            type="password"
            value={confirmPassword}
            onChange={setConfirmPassword}
            required
            autoComplete="new-password"
          />
          <Field
            label="Display name (optional)"
            value={displayName}
            onChange={setDisplayName}
          />
          <Field
            label="Tags (comma-separated, optional)"
            value={tagsCsv}
            onChange={setTagsCsv}
          />
        </div>
        {error && <ErrorBanner msg={error} />}
        <p className="text-xs text-ink-500">
          {mode === "generate" ? (
            <>
              Daemon generates a fresh secp256k1 keypair and writes the
              encrypted keystore under <code>~/.remote-signer/keystores/</code>.
              Save the password — it's the only way to unlock later.
            </>
          ) : (
            <>
              Daemon encrypts the supplied private key into a new v3 keystore
              under <code>~/.remote-signer/keystores/</code>. The original
              hex is not retained server-side.
            </>
          )}
        </p>
        <div className="flex justify-end">
          <button
            type="submit"
            disabled={!password || !confirmPassword}
            className="rounded-md bg-accent-500 px-3 py-1.5 text-sm font-medium text-white hover:bg-accent-600 disabled:cursor-not-allowed disabled:bg-ink-300"
          >
            {mode === "import" ? "Import signer" : "Create signer"}
          </button>
        </div>
      </form>
    </Card>
  );
}

function UnlockDialog({
  address,
  busy,
  onCancel,
  onSubmit,
}: {
  address: string;
  busy: boolean;
  onCancel: () => void;
  onSubmit: (password: string) => void;
}) {
  const [password, setPassword] = useState("");
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/30"
      onClick={onCancel}
    >
      <div
        className="w-full max-w-sm rounded-lg border border-ink-200 bg-white p-5 shadow-lg"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className="mb-1 text-sm font-semibold text-ink-900">
          Unlock signer
        </h2>
        <p className="mb-4 font-mono text-[11px] text-ink-500">{address}</p>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            onSubmit(password);
          }}
          className="space-y-3"
        >
          <Field
            label="Keystore password"
            type="password"
            value={password}
            onChange={setPassword}
            required
            autoFocus
            autoComplete="current-password"
          />
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={onCancel}
              disabled={busy}
              className="rounded-md border border-ink-200 px-3 py-1 text-xs text-ink-700 hover:bg-ink-100 disabled:opacity-50"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={busy || !password}
              className="rounded-md bg-accent-500 px-3 py-1 text-xs font-medium text-white hover:bg-accent-600 disabled:opacity-50"
            >
              Unlock
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

function Field({
  label,
  value,
  onChange,
  required,
  type = "text",
  autoComplete,
  autoFocus,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  required?: boolean;
  type?: string;
  autoComplete?: string;
  autoFocus?: boolean;
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
        autoComplete={autoComplete}
        autoFocus={autoFocus}
        className="w-full rounded-md border border-ink-300 px-2 py-1 text-sm"
      />
    </div>
  );
}

function AccessPanel({ address }: { address: string }) {
  const access = useApi((c) => c.evm.signers.listAccess(address), [address]);
  const [grantKey, setGrantKey] = useState("");
  const [transferTo, setTransferTo] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [panelError, setPanelError] = useState<string | null>(null);

  async function grant() {
    if (!grantKey.trim()) return;
    const client = getClient();
    if (!client) return;
    setBusy("grant");
    setPanelError(null);
    try {
      await client.evm.signers.grantAccess(address, {
        api_key_id: grantKey.trim(),
      });
      setGrantKey("");
      access.reload();
    } catch (e) {
      setPanelError(formatErr(e));
    } finally {
      setBusy(null);
    }
  }

  async function revoke(apiKeyID: string) {
    if (!confirm(`Revoke ${apiKeyID}'s access to this signer?`)) return;
    const client = getClient();
    if (!client) return;
    setBusy(apiKeyID);
    setPanelError(null);
    try {
      await client.evm.signers.revokeAccess(address, apiKeyID);
      access.reload();
    } catch (e) {
      setPanelError(formatErr(e));
    } finally {
      setBusy(null);
    }
  }

  async function transfer() {
    if (!transferTo.trim()) return;
    if (
      !confirm(
        `Transfer ownership to ${transferTo}? The old owner loses ALL access. This cannot be undone from the UI.`,
      )
    )
      return;
    const client = getClient();
    if (!client) return;
    setBusy("transfer");
    setPanelError(null);
    try {
      await client.evm.signers.transferOwnership(address, {
        new_owner_id: transferTo.trim(),
      });
      setTransferTo("");
      access.reload();
    } catch (e) {
      setPanelError(formatErr(e));
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="space-y-4" onClick={(e) => e.stopPropagation()}>
      {panelError && <ErrorBanner msg={panelError} />}

      <div>
        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-ink-500">
          Access grants
        </h3>
        {access.loading && <Loading />}
        {access.error && <ErrorBanner msg={access.error} />}
        {access.data &&
          (access.data.length === 0 ? (
            <Empty msg="Owner only — no grants yet." />
          ) : (
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase text-ink-500">
                <tr>
                  <th className="py-1 pr-3 font-normal">API key</th>
                  <th className="py-1 pr-3 font-normal">Granted by</th>
                  <th className="py-1 pr-3 font-normal">When</th>
                  <th className="py-1 font-normal"></th>
                </tr>
              </thead>
              <tbody>
                {access.data.map((g) => (
                  <tr key={g.api_key_id} className="border-t border-ink-100">
                    <td className="py-1 pr-3 font-mono text-xs text-ink-900">
                      {g.api_key_id}
                    </td>
                    <td className="py-1 pr-3 font-mono text-xs text-ink-700">
                      {g.granted_by}
                    </td>
                    <td className="py-1 pr-3 font-mono text-[11px] text-ink-500">
                      {g.created_at}
                    </td>
                    <td className="py-1">
                      <button
                        type="button"
                        disabled={busy === g.api_key_id}
                        onClick={() => revoke(g.api_key_id)}
                        className="rounded-md border border-red-200 px-2 py-0.5 text-xs text-red-700 hover:bg-red-50 disabled:opacity-50"
                      >
                        Revoke
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ))}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            grant();
          }}
          className="mt-2 flex flex-wrap items-end gap-3"
        >
          <div className="flex-1 min-w-[200px]">
            <label className="mb-1 block text-[11px] uppercase tracking-wide text-ink-500">
              Grant access to (api key id)
            </label>
            <input
              type="text"
              value={grantKey}
              onChange={(e) => setGrantKey(e.target.value)}
              className="w-full rounded-md border border-ink-300 px-2 py-1 text-sm"
            />
          </div>
          <button
            type="submit"
            disabled={busy === "grant" || !grantKey.trim()}
            className="rounded-md bg-accent-500 px-3 py-1 text-xs font-medium text-white hover:bg-accent-600 disabled:opacity-50"
          >
            Grant
          </button>
        </form>
      </div>

      <div className="border-t border-ink-200 pt-3">
        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-ink-500">
          Transfer ownership
        </h3>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            transfer();
          }}
          className="flex flex-wrap items-end gap-3"
        >
          <div className="flex-1 min-w-[200px]">
            <label className="mb-1 block text-[11px] uppercase tracking-wide text-ink-500">
              New owner (api key id)
            </label>
            <input
              type="text"
              value={transferTo}
              onChange={(e) => setTransferTo(e.target.value)}
              className="w-full rounded-md border border-ink-300 px-2 py-1 text-sm"
            />
          </div>
          <button
            type="submit"
            disabled={busy === "transfer" || !transferTo.trim()}
            className="rounded-md border border-red-200 px-3 py-1 text-xs text-red-700 hover:bg-red-50 disabled:opacity-50"
          >
            Transfer
          </button>
        </form>
        <p className="mt-2 text-[11px] text-ink-500">
          Transferring ownership clears the entire access list — the old
          owner loses ALL access. Irreversible from the UI.
        </p>
      </div>
    </div>
  );
}

function formatErr(e: unknown): string {
  if (e instanceof APIError) return `HTTP ${e.statusCode}: ${e.message}`;
  if (e instanceof Error) return e.message;
  return String(e);
}
