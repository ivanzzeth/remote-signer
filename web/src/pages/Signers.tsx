import { Fragment, useEffect, useState } from "react";
import { APIError } from "remote-signer-client";
import type { ListSignersFilter } from "remote-signer-client";
import {
  Badge,
  Card,
  Empty,
  ErrorBanner,
  Loading,
  PageHeader,
} from "../components/ui";
import { getClient, getCredentials } from "../lib/auth";
import { useApi } from "../lib/useApi";

// Tri-state encoding for select inputs: empty string = no filter,
// "true"/"false" map to the boolean parameter on the SDK side. Keeping
// it as a string in state lets the <select> control round-trip the
// "all" option without us having to model a 3-valued boolean in React.
type TriBool = "" | "true" | "false";
const tri = (v: TriBool): boolean | undefined => (v === "" ? undefined : v === "true");

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
  // Filter state. Each control round-trips through useApi's deps so a
  // change re-fetches the daemon — server-side filtering is the whole
  // point (no client-side over-listing of an admin's full set).
  const [filterType, setFilterType] = useState<string>("");
  const [filterAPIKeyID, setFilterAPIKeyID] = useState<string>("");
  const [filterLocked, setFilterLocked] = useState<TriBool>("");
  const [filterEnabled, setFilterEnabled] = useState<TriBool>("");

  const filter: ListSignersFilter = {
    ...(filterType ? { type: filterType } : {}),
    ...(filterAPIKeyID ? { api_key_id: filterAPIKeyID } : {}),
    ...(tri(filterLocked) !== undefined ? { locked: tri(filterLocked) } : {}),
    ...(tri(filterEnabled) !== undefined ? { enabled: tri(filterEnabled) } : {}),
  };
  const { data, loading, error, reload } = useApi(
    (c) => c.evm.signers.list(filter),
    [filterType, filterAPIKeyID, filterLocked, filterEnabled],
  );

  // Names directory feeds two things: the api-key filter dropdown
  // options AND the admin-detection that decides whether to show the
  // dropdown at all. Non-admin operators can't filter by another key
  // (daemon 403s), so hiding the control beats showing a control that
  // can only error.
  const namesApi = useApi((c) => c.apiKeys.names());
  const currentApiKeyID = getCredentials()?.apiKeyID ?? "";
  const currentRole =
    namesApi.data?.keys.find((k) => k.id === currentApiKeyID)?.role ?? "";
  const isAdmin = currentRole === "admin";

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
    keystoreJson?: string;
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
          ...(input.keystoreJson
            ? { keystore_json: input.keystoreJson }
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

      <FilterBar
        type={filterType}
        onType={setFilterType}
        apiKeyID={filterAPIKeyID}
        onAPIKeyID={setFilterAPIKeyID}
        locked={filterLocked}
        onLocked={setFilterLocked}
        enabled={filterEnabled}
        onEnabled={setFilterEnabled}
        apiKeyOptions={namesApi.data?.keys ?? []}
        showAPIKeyFilter={isAdmin}
      />

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

// Inline filter bar above the signer table. All four controls are
// independent — clearing one leaves the others in place — and a
// "—" option encodes "no filter" so the operator can drop a
// constraint without retyping the others.
function FilterBar({
  type,
  onType,
  apiKeyID,
  onAPIKeyID,
  locked,
  onLocked,
  enabled,
  onEnabled,
  apiKeyOptions,
  showAPIKeyFilter,
}: {
  type: string;
  onType: (v: string) => void;
  apiKeyID: string;
  onAPIKeyID: (v: string) => void;
  locked: TriBool;
  onLocked: (v: TriBool) => void;
  enabled: TriBool;
  onEnabled: (v: TriBool) => void;
  apiKeyOptions: Array<{ id: string; name: string; role: string }>;
  showAPIKeyFilter: boolean;
}) {
  const selectCls =
    "rounded-md border border-ink-300 bg-white px-2 py-1 text-xs text-ink-900";
  return (
    <div
      data-testid="signers-filter-bar"
      className="flex flex-wrap items-end gap-3 rounded-md border border-ink-200 bg-ink-50 p-3"
    >
      <FilterField label="Type">
        <select
          data-testid="filter-type"
          className={selectCls}
          value={type}
          onChange={(e) => onType(e.target.value)}
        >
          <option value="">All</option>
          <option value="keystore">keystore</option>
          <option value="hd_wallet">hd_wallet</option>
          <option value="private_key">private_key</option>
        </select>
      </FilterField>

      <FilterField label="Locked">
        <select
          data-testid="filter-locked"
          className={selectCls}
          value={locked}
          onChange={(e) => onLocked(e.target.value as TriBool)}
        >
          <option value="">All</option>
          <option value="true">locked</option>
          <option value="false">unlocked</option>
        </select>
      </FilterField>

      <FilterField label="Enabled">
        <select
          data-testid="filter-enabled"
          className={selectCls}
          value={enabled}
          onChange={(e) => onEnabled(e.target.value as TriBool)}
        >
          <option value="">All</option>
          <option value="true">enabled</option>
          <option value="false">disabled</option>
        </select>
      </FilterField>

      {showAPIKeyFilter && (
        <FilterField label="API key">
          <select
            data-testid="filter-apikey"
            className={selectCls}
            value={apiKeyID}
            onChange={(e) => onAPIKeyID(e.target.value)}
          >
            <option value="">All</option>
            {apiKeyOptions.map((k) => (
              <option key={k.id} value={k.id}>
                {k.id} {k.name && `· ${k.name}`}
              </option>
            ))}
          </select>
        </FilterField>
      )}
    </div>
  );
}

function FilterField({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex flex-col gap-1">
      <label className="text-[10px] uppercase tracking-wide text-ink-500">
        {label}
      </label>
      {children}
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
    keystoreJson?: string;
  }) => void;
}) {
  type Mode = "generate" | "import-hex" | "import-json";
  const [mode, setMode] = useState<Mode>("generate");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [privateKeyHex, setPrivateKeyHex] = useState("");
  const [keystoreJson, setKeystoreJson] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [tagsCsv, setTagsCsv] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function onFilePicked(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    setError(null);
    try {
      setKeystoreJson(await file.text());
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      e.target.value = "";
    }
  }

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
    let json: string | undefined;
    if (mode === "import-hex") {
      hex = privateKeyHex.trim().replace(/^0x/i, "");
      if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
        setError("private key must be 64 hex chars (with or without 0x)");
        return;
      }
    }
    if (mode === "import-json") {
      const trimmed = keystoreJson.trim();
      if (!trimmed) {
        setError("paste or upload a v3 keystore JSON");
        return;
      }
      try {
        const parsed = JSON.parse(trimmed);
        if (!parsed.crypto && !parsed.Crypto) {
          setError("not a v3 keystore JSON (missing crypto field)");
          return;
        }
      } catch {
        setError("keystore JSON is not valid JSON");
        return;
      }
      json = trimmed;
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
      keystoreJson: json,
    });
  }

  return (
    <Card title="New signer">
      <form onSubmit={submit} className="space-y-3">
        <div className="flex gap-2 rounded-md border border-ink-200 bg-ink-50 p-1">
          {([
            ["generate", "Generate fresh keypair"],
            ["import-hex", "Import private key"],
            ["import-json", "Import keystore JSON"],
          ] as const).map(([m, label]) => (
            <button
              key={m}
              type="button"
              onClick={() => setMode(m as Mode)}
              className={`flex-1 rounded px-3 py-1 text-xs font-medium transition ${
                mode === m
                  ? "bg-white text-ink-900 shadow-sm"
                  : "text-ink-500 hover:text-ink-900"
              }`}
            >
              {label}
            </button>
          ))}
        </div>

        {mode === "import-hex" && (
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

        {mode === "import-json" && (
          <div>
            <label className="mb-1 flex items-center justify-between text-[11px] uppercase tracking-wide text-ink-500">
              <span>v3 Keystore JSON</span>
              <label className="cursor-pointer text-accent-600 hover:text-accent-500">
                <input
                  type="file"
                  className="hidden"
                  accept=".json,.txt,application/json"
                  onChange={onFilePicked}
                />
                Load from file…
              </label>
            </label>
            <textarea
              value={keystoreJson}
              onChange={(e) => setKeystoreJson(e.target.value)}
              rows={6}
              spellCheck={false}
              placeholder='{"version":3,"id":"…","address":"…","crypto":{…}}'
              className="block w-full rounded-md border border-ink-300 p-2 font-mono text-[11px]"
            />
            <p className="mt-1 text-[11px] text-ink-500">
              Paste a v3 keystore JSON (or upload via Load from file). The
              password below must unlock it; the daemon decrypts locally,
              then re-encrypts under <code>~/.remote-signer/keystores/</code>.
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
          {mode === "generate" && (
            <>
              Daemon generates a fresh secp256k1 keypair and writes the
              encrypted keystore under <code>~/.remote-signer/keystores/</code>.
              Save the password — it's the only way to unlock later.
            </>
          )}
          {mode === "import-hex" && (
            <>
              Daemon encrypts the supplied private key into a new v3 keystore.
              The original hex is not retained server-side.
            </>
          )}
          {mode === "import-json" && (
            <>
              Daemon verifies the keystore JSON unlocks with the password
              you provided, then re-encrypts it under its own keystore dir.
              The source file is not retained.
            </>
          )}
        </p>
        <div className="flex justify-end">
          <button
            type="submit"
            disabled={!password || !confirmPassword}
            className="rounded-md bg-accent-500 px-3 py-1.5 text-sm font-medium text-white hover:bg-accent-600 disabled:cursor-not-allowed disabled:bg-ink-300"
          >
            {mode === "generate" ? "Create signer" : "Import signer"}
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
  // Names directory drives the grant-to picker. We show every enabled
  // key but tag the ones that can't be grant targets — the owner (this
  // caller) and anyone who already has access. Hiding them instead
  // makes the dropdown go blank in the common "agent already granted"
  // case, which reads as "the UI is broken" rather than "there's just
  // nothing more to do". "agent" is the default when it's still a
  // valid grantee, otherwise the first eligible key wins.
  const namesApi = useApi((c) => c.apiKeys.names());
  const callerKeyID = getCredentials()?.apiKeyID ?? "";
  const alreadyGranted = new Set((access.data ?? []).map((g) => g.api_key_id));
  type GrantOption = {
    id: string;
    name: string;
    role: string;
    /** Empty string means selectable; otherwise the reason it's not. */
    disabledReason: string;
  };
  const grantOptions: GrantOption[] = (namesApi.data?.keys ?? []).map((k) => ({
    id: k.id,
    name: k.name,
    role: k.role,
    disabledReason:
      k.id === callerKeyID
        ? "owner"
        : alreadyGranted.has(k.id)
        ? "already granted"
        : "",
  }));
  const eligible = grantOptions.filter((k) => k.disabledReason === "");
  const defaultGrantKey =
    eligible.find((k) => k.id === "agent")?.id ?? eligible[0]?.id ?? "";
  const [grantKey, setGrantKey] = useState("");
  // Auto-select once the directory loads (or after the eligible set
  // shifts — e.g. a revoke re-opens a slot). Only fires when grantKey
  // is empty OR no longer eligible, so a manual choice sticks until
  // it becomes invalid.
  useEffect(() => {
    const stillEligible = eligible.some((k) => k.id === grantKey);
    if (!stillEligible && defaultGrantKey !== "") {
      setGrantKey(defaultGrantKey);
    } else if (!stillEligible && defaultGrantKey === "") {
      setGrantKey("");
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [defaultGrantKey, eligible.length]);

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
            <label
              htmlFor="grant-apikey-select"
              className="mb-1 block text-[11px] uppercase tracking-wide text-ink-500"
            >
              Grant access to (api key)
            </label>
            <select
              id="grant-apikey-select"
              data-testid="grant-apikey"
              value={grantKey}
              onChange={(e) => setGrantKey(e.target.value)}
              disabled={namesApi.loading || grantOptions.length === 0}
              className="w-full rounded-md border border-ink-300 bg-white px-2 py-1 text-sm disabled:opacity-50"
            >
              {grantOptions.length === 0 ? (
                <option value="">
                  {namesApi.loading ? "Loading…" : "No api keys exist"}
                </option>
              ) : (
                grantOptions.map((k) => (
                  <option
                    key={k.id}
                    value={k.id}
                    disabled={k.disabledReason !== ""}
                  >
                    {k.id}
                    {k.name && ` · ${k.name}`}
                    {k.disabledReason && ` (${k.disabledReason})`}
                  </option>
                ))
              )}
            </select>
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
