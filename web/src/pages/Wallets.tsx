import { useState } from "react";
import { APIError, type Wallet } from "remote-signer-client";
import {
  Card,
  Empty,
  ErrorBanner,
  Loading,
  PageHeader,
} from "../components/ui";
import { getClient } from "../lib/auth";
import { useApi } from "../lib/useApi";

/**
 * Wallet collections: named groups of signer addresses. Mirrors
 * `remote-signer evm wallet …`. NOT a multi-sig contract — just an
 * organisational tag so an operator can bundle related signers
 * (per-strategy / per-environment / per-chain) and reason about them
 * together.
 */
export function Wallets() {
  const { data, loading, error, reload } = useApi((c) => c.wallets.list());
  const [mutationError, setMutationError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);

  async function create(input: { name: string; description: string }) {
    const client = getClient();
    if (!client) return;
    setMutationError(null);
    try {
      await client.wallets.create({
        name: input.name,
        ...(input.description ? { description: input.description } : {}),
      });
      setShowCreate(false);
      reload();
    } catch (e) {
      setMutationError(formatErr(e));
    }
  }

  async function destroy(id: string, name: string) {
    if (!confirm(`Delete wallet "${name}"? Members are unaffected.`)) return;
    const client = getClient();
    if (!client) return;
    setBusy(id);
    setMutationError(null);
    try {
      await client.wallets.delete(id);
      if (expanded === id) setExpanded(null);
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
        title="Wallets"
        subtitle="Named collections of signer addresses (organisational grouping; not multi-sig)."
        actions={
          <>
            <button
              type="button"
              onClick={() => setShowCreate((s) => !s)}
              className="rounded-md bg-accent-500 px-3 py-1 text-xs font-medium text-white hover:bg-accent-600"
            >
              {showCreate ? "Cancel" : "New wallet"}
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
          (data.wallets.length === 0 ? (
            <Empty msg="No wallet collections. Create one above and add signer members." />
          ) : (
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase text-ink-500">
                <tr>
                  <th className="py-1 pr-3 font-normal">Name</th>
                  <th className="py-1 pr-3 font-normal">Description</th>
                  <th className="py-1 pr-3 font-normal">Owner</th>
                  <th className="py-1 pr-3 font-normal">Members</th>
                  <th className="py-1 font-normal">Actions</th>
                </tr>
              </thead>
              <tbody>
                {data.wallets.map((w) => (
                  <WalletRow
                    key={w.id}
                    wallet={w}
                    expanded={expanded === w.id}
                    onToggle={() =>
                      setExpanded((id) => (id === w.id ? null : w.id))
                    }
                    onDelete={() => destroy(w.id, w.name)}
                    busy={busy === w.id}
                  />
                ))}
              </tbody>
            </table>
          ))}
      </Card>
    </div>
  );
}

function WalletRow({
  wallet,
  expanded,
  onToggle,
  onDelete,
  busy,
}: {
  wallet: Wallet;
  expanded: boolean;
  onToggle: () => void;
  onDelete: () => void;
  busy: boolean;
}) {
  return (
    <>
      <tr
        className="cursor-pointer border-t border-ink-100 hover:bg-ink-50"
        onClick={onToggle}
      >
        <td className="py-1 pr-3">
          <div className="text-ink-900">{wallet.name}</div>
          <div className="font-mono text-[11px] text-ink-500">{wallet.id}</div>
        </td>
        <td className="py-1 pr-3 text-ink-700">{wallet.description || "—"}</td>
        <td className="py-1 pr-3 font-mono text-xs text-ink-700">
          {wallet.owner_id || "—"}
        </td>
        <td className="py-1 pr-3 text-ink-700">{wallet.member_count ?? 0}</td>
        <td className="py-1">
          <button
            type="button"
            disabled={busy}
            onClick={(e) => {
              e.stopPropagation();
              onDelete();
            }}
            className="rounded-md border border-red-200 px-2 py-0.5 text-xs text-red-700 hover:bg-red-50 disabled:opacity-50"
          >
            Delete
          </button>
        </td>
      </tr>
      {expanded && (
        <tr className="border-t border-ink-100 bg-ink-50">
          <td colSpan={5} className="px-4 py-3">
            <MembersPanel walletID={wallet.id} />
          </td>
        </tr>
      )}
    </>
  );
}

function MembersPanel({ walletID }: { walletID: string }) {
  const members = useApi(
    (c) => c.wallets.listMembers(walletID),
    [walletID],
  );
  const [addError, setAddError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [newSigner, setNewSigner] = useState("");

  async function add() {
    if (!newSigner.trim()) return;
    const client = getClient();
    if (!client) return;
    setBusy("add");
    setAddError(null);
    try {
      await client.wallets.addMember(walletID, {
        signer_address: newSigner.trim(),
      });
      setNewSigner("");
      members.reload();
    } catch (e) {
      setAddError(formatErr(e));
    } finally {
      setBusy(null);
    }
  }

  async function remove(signerAddress: string) {
    if (!confirm(`Remove ${signerAddress} from this wallet?`)) return;
    const client = getClient();
    if (!client) return;
    setBusy(signerAddress);
    setAddError(null);
    try {
      await client.wallets.removeMember(walletID, signerAddress);
      members.reload();
    } catch (e) {
      setAddError(formatErr(e));
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="space-y-3">
      <form
        onClick={(e) => e.stopPropagation()}
        onSubmit={(e) => {
          e.preventDefault();
          add();
        }}
        className="flex flex-wrap items-end gap-3 rounded-md border border-ink-200 p-3"
      >
        <div className="flex-1 min-w-[280px]">
          <label className="mb-1 block text-[11px] uppercase tracking-wide text-ink-500">
            Add signer (0x-prefixed address)
          </label>
          <input
            type="text"
            value={newSigner}
            onChange={(e) => setNewSigner(e.target.value)}
            placeholder="0x…"
            className="w-full rounded-md border border-ink-300 px-2 py-1 font-mono text-xs"
          />
        </div>
        <button
          type="submit"
          disabled={busy === "add" || !newSigner.trim()}
          className="rounded-md bg-accent-500 px-3 py-1 text-xs font-medium text-white hover:bg-accent-600 disabled:opacity-50"
        >
          Add member
        </button>
      </form>
      {addError && <ErrorBanner msg={addError} />}

      <div>
        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-ink-500">
          Members
        </h3>
        {members.loading && <Loading />}
        {members.error && <ErrorBanner msg={members.error} />}
        {members.data &&
          (members.data.members.length === 0 ? (
            <Empty msg="No members yet." />
          ) : (
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase text-ink-500">
                <tr>
                  <th className="py-1 pr-3 font-normal">Signer</th>
                  <th className="py-1 pr-3 font-normal">Type</th>
                  <th className="py-1 pr-3 font-normal">Added</th>
                  <th className="py-1 font-normal"></th>
                </tr>
              </thead>
              <tbody>
                {members.data.members.map((m) => (
                  <tr
                    key={m.signer_address}
                    className="border-t border-ink-100"
                  >
                    <td className="py-1 pr-3 font-mono text-xs text-ink-900">
                      {m.signer_address}
                    </td>
                    <td className="py-1 pr-3 text-xs text-ink-700">
                      {m.wallet_type || "—"}
                    </td>
                    <td className="py-1 pr-3 font-mono text-[11px] text-ink-500">
                      {m.added_at}
                    </td>
                    <td className="py-1">
                      <button
                        type="button"
                        disabled={busy === m.signer_address}
                        onClick={(e) => {
                          e.stopPropagation();
                          remove(m.signer_address);
                        }}
                        className="rounded-md border border-red-200 px-2 py-0.5 text-xs text-red-700 hover:bg-red-50 disabled:opacity-50"
                      >
                        Remove
                      </button>
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

function CreateForm({
  onSubmit,
}: {
  onSubmit: (v: { name: string; description: string }) => void;
}) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");

  return (
    <Card title="New wallet collection">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          onSubmit({ name: name.trim(), description: description.trim() });
        }}
        className="space-y-3"
      >
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          <div>
            <label className="mb-1 block text-[11px] uppercase tracking-wide text-ink-500">
              Name
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
              className="w-full rounded-md border border-ink-300 px-2 py-1 text-sm"
            />
          </div>
          <div>
            <label className="mb-1 block text-[11px] uppercase tracking-wide text-ink-500">
              Description (optional)
            </label>
            <input
              type="text"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className="w-full rounded-md border border-ink-300 px-2 py-1 text-sm"
            />
          </div>
        </div>
        <div className="flex justify-end">
          <button
            type="submit"
            disabled={!name.trim()}
            className="rounded-md bg-accent-500 px-3 py-1.5 text-sm font-medium text-white hover:bg-accent-600 disabled:cursor-not-allowed disabled:bg-ink-300"
          >
            Create wallet
          </button>
        </div>
      </form>
    </Card>
  );
}

function formatErr(e: unknown): string {
  if (e instanceof APIError) return `HTTP ${e.statusCode}: ${e.message}`;
  if (e instanceof Error) return e.message;
  return String(e);
}
