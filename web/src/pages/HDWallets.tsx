import { useState } from "react";
import { APIError, type HDWalletResponse, type SignerInfo } from "remote-signer-client";
import {
  Badge,
  Card,
  Empty,
  ErrorBanner,
  Loading,
  PageHeader,
  shorten,
} from "../components/ui";

import { getClient } from "../lib/auth";
import { useApi } from "../lib/useApi";

/**
 * HD wallet management: create from random entropy, import from mnemonic,
 * derive single addresses or ranges, browse existing derived children.
 *
 * Mnemonic and password are kept inside the form's local state and never
 * leave this component except through the SDK call; we don't write either
 * to localStorage.
 */
export function HDWallets() {
  const { data, loading, error, reload } = useApi((c) =>
    c.evm.hdWallets.list(),
  );
  const [mutationError, setMutationError] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [showImport, setShowImport] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [unlockTarget, setUnlockTarget] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  async function unlock(address: string, password: string) {
    const client = getClient();
    if (!client) return;
    setBusy(address);
    setMutationError(null);
    try {
      // HD wallets surface as signers (type=hd_wallet) and reuse the
      // signer unlock endpoint — the manager dispatches to the HD wallet
      // provider's UnlockSigner based on the signer's recorded type.
      await client.evm.signers.unlock(address, { password });
      setUnlockTarget(null);
      reload();
    } catch (e) {
      setMutationError(formatErr(e));
    } finally {
      setBusy(null);
    }
  }

  async function create(input: { password: string; entropyBits: number }) {
    const client = getClient();
    if (!client) return;
    setMutationError(null);
    try {
      await client.evm.hdWallets.create({
        password: input.password,
        entropy_bits: input.entropyBits,
      });
      setShowCreate(false);
      reload();
    } catch (e) {
      setMutationError(formatErr(e));
    }
  }

  async function importWallet(input: {
    password: string;
    mnemonic?: string;
    walletJson?: string;
  }) {
    const client = getClient();
    if (!client) return;
    setMutationError(null);
    try {
      await client.evm.hdWallets.import({
        password: input.password,
        ...(input.mnemonic ? { mnemonic: input.mnemonic } : {}),
        ...(input.walletJson ? { wallet_json: input.walletJson } : {}),
      });
      setShowImport(false);
      reload();
    } catch (e) {
      setMutationError(formatErr(e));
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="HD Wallets"
        subtitle="Hierarchical-deterministic wallets — one parent address, many derived children."
        actions={
          <>
            <button
              type="button"
              onClick={() => {
                setShowCreate((s) => !s);
                setShowImport(false);
              }}
              className="rounded-md bg-accent-500 px-3 py-1 text-xs font-medium text-white hover:bg-accent-600"
            >
              {showCreate ? "Cancel" : "New wallet"}
            </button>
            <button
              type="button"
              onClick={() => {
                setShowImport((s) => !s);
                setShowCreate(false);
              }}
              className="rounded-md border border-ink-200 px-3 py-1 text-xs text-ink-700 hover:bg-ink-100"
            >
              {showImport ? "Cancel" : "Import"}
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
      {showImport && <ImportForm onSubmit={importWallet} />}

      <Card>
        {loading && <Loading />}
        {error && <ErrorBanner msg={error} />}
        {data &&
          (data.wallets.length === 0 ? (
            <Empty msg="No HD wallets. Create or import one above." />
          ) : (
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase text-ink-500">
                <tr>
                  <th className="py-1 pr-3 font-normal">Primary address</th>
                  <th className="py-1 pr-3 font-normal">Base path</th>
                  <th className="py-1 pr-3 font-normal">State</th>
                  <th className="py-1 pr-3 font-normal">Derived</th>
                  <th className="py-1 font-normal">Actions</th>
                </tr>
              </thead>
              <tbody>
                {data.wallets.map((w) => (
                  <HDWalletRow
                    key={w.primary_address}
                    wallet={w}
                    expanded={expanded === w.primary_address}
                    onToggle={() =>
                      setExpanded((id) =>
                        id === w.primary_address ? null : w.primary_address,
                      )
                    }
                    onUnlockClick={() => setUnlockTarget(w.primary_address)}
                    busy={busy === w.primary_address}
                  />
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

function HDWalletRow({
  wallet,
  expanded,
  onToggle,
  onUnlockClick,
  busy,
}: {
  wallet: HDWalletResponse;
  expanded: boolean;
  onToggle: () => void;
  onUnlockClick: () => void;
  busy: boolean;
}) {
  return (
    <>
      <tr
        className="cursor-pointer border-t border-ink-100 hover:bg-ink-50"
        onClick={onToggle}
      >
        <td className="py-1 pr-3 font-mono text-xs text-ink-900">
          {wallet.primary_address}
        </td>
        <td className="py-1 pr-3 font-mono text-xs text-ink-700">
          {wallet.base_path}
        </td>
        <td className="py-1 pr-3">
          <Badge tone={wallet.locked ? "red" : "green"}>
            {wallet.locked ? "locked" : "unlocked"}
          </Badge>
        </td>
        <td className="py-1 pr-3 text-ink-700">{wallet.derived_count}</td>
        <td className="py-1">
          <div
            className="flex gap-2"
            onClick={(e) => e.stopPropagation()}
          >
            {wallet.locked && (
              <button
                type="button"
                disabled={busy}
                onClick={onUnlockClick}
                className="rounded-md border border-ink-200 px-2 py-0.5 text-xs text-ink-700 hover:bg-ink-100 disabled:opacity-50"
              >
                Unlock
              </button>
            )}
          </div>
        </td>
      </tr>
      {expanded && (
        <tr className="border-t border-ink-100 bg-ink-50">
          <td colSpan={5} className="px-4 py-3">
            {wallet.locked ? (
              <Empty msg="This wallet is locked — derived addresses are unavailable until you unlock it." />
            ) : (
              <ExpandedPanel address={wallet.primary_address} />
            )}
          </td>
        </tr>
      )}
    </>
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
          Unlock HD wallet
        </h2>
        <p className="mb-4 font-mono text-[11px] text-ink-500">{address}</p>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            onSubmit(password);
          }}
          className="space-y-3"
        >
          <div>
            <label className="mb-1 block text-[11px] uppercase tracking-wide text-ink-500">
              Wallet password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              autoFocus
              autoComplete="current-password"
              className="w-full rounded-md border border-ink-300 px-2 py-1 text-sm"
            />
          </div>
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

function ExpandedPanel({ address }: { address: string }) {
  const derived = useApi((c) => c.evm.hdWallets.listDerived(address), [address]);
  const [deriveError, setDeriveError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function derive(input: {
    mode: "index" | "range";
    index: number;
    start: number;
    count: number;
  }) {
    const client = getClient();
    if (!client) return;
    setBusy(true);
    setDeriveError(null);
    try {
      if (input.mode === "index") {
        await client.evm.hdWallets.deriveAddress(address, { index: input.index });
      } else {
        await client.evm.hdWallets.deriveAddress(address, {
          start: input.start,
          count: input.count,
        });
      }
      derived.reload();
    } catch (e) {
      setDeriveError(formatErr(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-3">
      <DeriveForm onSubmit={derive} busy={busy} />
      {deriveError && <ErrorBanner msg={deriveError} />}

      <div>
        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-ink-500">
          Derived addresses
        </h3>
        {derived.loading && <Loading />}
        {derived.error && <ErrorBanner msg={derived.error} />}
        {derived.data &&
          (derived.data.derived.length === 0 ? (
            <Empty msg="No derived addresses yet. Use Derive above to mint them." />
          ) : (
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase text-ink-500">
                <tr>
                  <th className="py-1 pr-3 font-normal">Address</th>
                  <th className="py-1 pr-3 font-normal">Index</th>
                  <th className="py-1 pr-3 font-normal">Enabled</th>
                  <th className="py-1 font-normal">Locked</th>
                </tr>
              </thead>
              <tbody>
                {derived.data.derived.map((d: SignerInfo) => (
                  <tr key={d.address} className="border-t border-ink-100">
                    <td className="py-1 pr-3 font-mono text-xs text-ink-900">
                      {shorten(d.address, 10, 8)}
                    </td>
                    <td className="py-1 pr-3 font-mono text-xs text-ink-700">
                      {d.hd_derivation_index ?? "—"}
                    </td>
                    <td className="py-1 pr-3">
                      <Badge tone={d.enabled ? "green" : "neutral"}>
                        {d.enabled ? "enabled" : "disabled"}
                      </Badge>
                    </td>
                    <td className="py-1">
                      <Badge tone={d.locked ? "red" : "green"}>
                        {d.locked ? "locked" : "unlocked"}
                      </Badge>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ))}
      </div>
    </div>
  );
}

function DeriveForm({
  onSubmit,
  busy,
}: {
  onSubmit: (v: {
    mode: "index" | "range";
    index: number;
    start: number;
    count: number;
  }) => void;
  busy: boolean;
}) {
  const [mode, setMode] = useState<"index" | "range">("index");
  const [index, setIndex] = useState("0");
  const [start, setStart] = useState("0");
  const [count, setCount] = useState("5");

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        onSubmit({
          mode,
          index: Number(index) || 0,
          start: Number(start) || 0,
          count: Number(count) || 1,
        });
      }}
      className="flex flex-wrap items-end gap-3 rounded-md border border-ink-200 p-3"
    >
      <div>
        <label className="mb-1 block text-[11px] uppercase tracking-wide text-ink-500">
          Mode
        </label>
        <select
          value={mode}
          onChange={(e) => setMode(e.target.value as "index" | "range")}
          className="rounded-md border border-ink-300 px-2 py-1 text-sm"
        >
          <option value="index">Single index</option>
          <option value="range">Range</option>
        </select>
      </div>
      {mode === "index" ? (
        <Field label="Index" value={index} onChange={setIndex} type="number" />
      ) : (
        <>
          <Field label="Start" value={start} onChange={setStart} type="number" />
          <Field label="Count" value={count} onChange={setCount} type="number" />
        </>
      )}
      <button
        type="submit"
        disabled={busy}
        className="rounded-md bg-accent-500 px-3 py-1 text-xs font-medium text-white hover:bg-accent-600 disabled:opacity-50"
      >
        {busy ? "Deriving…" : "Derive"}
      </button>
    </form>
  );
}

function CreateForm({
  onSubmit,
}: {
  onSubmit: (v: { password: string; entropyBits: number }) => void;
}) {
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [entropyBits, setEntropyBits] = useState<"128" | "256">("256");
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
    setError(null);
    onSubmit({ password, entropyBits: Number(entropyBits) });
  }

  return (
    <Card title="New HD wallet">
      <form onSubmit={submit} className="space-y-3">
        <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
          <Field
            label="Password"
            type="password"
            value={password}
            onChange={setPassword}
            required
            autoComplete="new-password"
          />
          <Field
            label="Confirm"
            type="password"
            value={confirmPassword}
            onChange={setConfirmPassword}
            required
            autoComplete="new-password"
          />
          <div>
            <label className="mb-1 block text-[11px] uppercase tracking-wide text-ink-500">
              Entropy
            </label>
            <select
              value={entropyBits}
              onChange={(e) => setEntropyBits(e.target.value as "128" | "256")}
              className="w-full rounded-md border border-ink-300 px-2 py-1 text-sm"
            >
              <option value="128">128 bits (12 words)</option>
              <option value="256">256 bits (24 words)</option>
            </select>
          </div>
        </div>
        {error && <ErrorBanner msg={error} />}
        <p className="text-xs text-ink-500">
          The daemon generates the mnemonic server-side and encrypts the
          wallet under the password. The mnemonic is shown once in the
          response — keep a backup; lost passwords are unrecoverable.
        </p>
        <div className="flex justify-end">
          <button
            type="submit"
            disabled={!password}
            className="rounded-md bg-accent-500 px-3 py-1.5 text-sm font-medium text-white hover:bg-accent-600 disabled:cursor-not-allowed disabled:bg-ink-300"
          >
            Generate HD wallet
          </button>
        </div>
      </form>
    </Card>
  );
}

function ImportForm({
  onSubmit,
}: {
  onSubmit: (v: {
    password: string;
    mnemonic?: string;
    walletJson?: string;
  }) => void;
}) {
  type Mode = "mnemonic" | "wallet-json";
  const [mode, setMode] = useState<Mode>("mnemonic");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [mnemonic, setMnemonic] = useState("");
  const [walletJson, setWalletJson] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function onFilePicked(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    setError(null);
    try {
      setWalletJson(await file.text());
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
    if (mode === "mnemonic") {
      const words = mnemonic.trim().split(/\s+/).length;
      if (![12, 15, 18, 21, 24].includes(words)) {
        setError(`mnemonic must be 12/15/18/21/24 words (got ${words})`);
        return;
      }
      setError(null);
      onSubmit({ password, mnemonic: mnemonic.trim() });
      return;
    }
    // wallet-json mode
    const trimmed = walletJson.trim();
    if (!trimmed) {
      setError("paste or upload a wallet JSON");
      return;
    }
    try {
      const parsed = JSON.parse(trimmed);
      if (!parsed.mnemonic || typeof parsed.mnemonic !== "object") {
        setError("not an HD wallet JSON (missing encrypted mnemonic)");
        return;
      }
    } catch {
      setError("wallet JSON is not valid JSON");
      return;
    }
    setError(null);
    onSubmit({ password, walletJson: trimmed });
  }

  return (
    <Card title="Import HD wallet">
      <form onSubmit={submit} className="space-y-3">
        <div className="flex gap-2 rounded-md border border-ink-200 bg-ink-50 p-1">
          {([
            ["mnemonic", "From mnemonic"],
            ["wallet-json", "From wallet JSON"],
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

        {mode === "mnemonic" ? (
          <div>
            <label className="mb-1 block text-[11px] uppercase tracking-wide text-ink-500">
              BIP-39 mnemonic
            </label>
            <textarea
              value={mnemonic}
              onChange={(e) => setMnemonic(e.target.value)}
              rows={3}
              spellCheck={false}
              placeholder="abandon abandon abandon …"
              className="block w-full rounded-md border border-ink-300 p-2 font-mono text-[11px]"
            />
          </div>
        ) : (
          <div>
            <label className="mb-1 flex items-center justify-between text-[11px] uppercase tracking-wide text-ink-500">
              <span>HDWalletFile JSON</span>
              <label className="cursor-pointer text-accent-600 hover:text-accent-500">
                <input
                  type="file"
                  className="hidden"
                  accept=".json,application/json"
                  onChange={onFilePicked}
                />
                Load from file…
              </label>
            </label>
            <textarea
              value={walletJson}
              onChange={(e) => setWalletJson(e.target.value)}
              rows={5}
              spellCheck={false}
              placeholder='{"version":1,"primary_address":"…","mnemonic":{…},"hd_config":{…}}'
              className="block w-full rounded-md border border-ink-300 p-2 font-mono text-[11px]"
            />
          </div>
        )}
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          <Field
            label="Password"
            type="password"
            value={password}
            onChange={setPassword}
            required
            autoComplete="new-password"
          />
          <Field
            label="Confirm"
            type="password"
            value={confirmPassword}
            onChange={setConfirmPassword}
            required
            autoComplete="new-password"
          />
        </div>
        {error && <ErrorBanner msg={error} />}
        <p className="text-xs text-ink-500">
          {mode === "mnemonic"
            ? "Daemon stores the mnemonic encrypted under the password. It never reaches localStorage."
            : "Daemon decrypts the embedded mnemonic with the password and re-imports it under its wallet dir."}
        </p>
        <div className="flex justify-end">
          <button
            type="submit"
            disabled={
              !password ||
              (mode === "mnemonic" ? !mnemonic : !walletJson)
            }
            className="rounded-md bg-accent-500 px-3 py-1.5 text-sm font-medium text-white hover:bg-accent-600 disabled:cursor-not-allowed disabled:bg-ink-300"
          >
            Import wallet
          </button>
        </div>
      </form>
    </Card>
  );
}

function Field({
  label,
  value,
  onChange,
  required,
  type = "text",
  autoComplete,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  required?: boolean;
  type?: string;
  autoComplete?: string;
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
        className="w-full rounded-md border border-ink-300 px-2 py-1 text-sm"
      />
    </div>
  );
}

function formatErr(e: unknown): string {
  if (e instanceof APIError) return `HTTP ${e.statusCode}: ${e.message}`;
  if (e instanceof Error) return e.message;
  return String(e);
}
