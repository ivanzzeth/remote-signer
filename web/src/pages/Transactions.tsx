import { useState } from "react";
import { Link } from "react-router-dom";
import type {
  OnChainTransaction,
  OnChainTransactionStatus,
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
import { getCredentials } from "../lib/auth";
import { useApi } from "../lib/useApi";

const STATUSES: OnChainTransactionStatus[] = [
  "broadcasted",
  "mined",
  "dropped",
  "failed",
];

const SIGN_TYPES = [
  "personal",
  "typed_data",
  "transaction",
  "hash",
  "raw_message",
  "eip191",
] as const;

const ROLES = ["admin", "dev", "agent", "strategy"] as const;

/**
 * On-chain transactions surface: every eth_sendRawTransaction the
 * daemon's wallet RPC proxy observes lands here, with the background
 * poller filling in block / receipt fields as upstream mines the tx.
 *
 * The list is the operator's answer to "what happened to my signed
 * payload" — pre-tracking, the only way to know was to grep the
 * daemon log + paste hashes into a block explorer.
 */
export function Transactions() {
  const [status, setStatus] = useState<OnChainTransactionStatus | "">("");
  const [chainID, setChainID] = useState("");
  const [fromAddress, setFromAddress] = useState("");
  const [signType, setSignType] = useState("");
  const [apiKeyID, setAPIKeyID] = useState("");
  const [role, setRole] = useState("");
  const [signRequestID, setSignRequestID] = useState("");

  const namesApi = useApi((c) => c.apiKeys.names());
  const currentApiKeyID = getCredentials()?.apiKeyID ?? "";
  const currentRole =
    namesApi.data?.keys.find((k) => k.id === currentApiKeyID)?.role ?? "";
  const showAdminFilters = currentRole === "admin" || currentRole === "dev";

  const filter = {
    limit: 50,
    ...(status ? { status } : {}),
    ...(chainID ? { chain_id: chainID } : {}),
    ...(fromAddress ? { from: fromAddress } : {}),
    ...(signType ? { sign_type: signType } : {}),
    ...(showAdminFilters && apiKeyID ? { api_key_id: apiKeyID } : {}),
    ...(showAdminFilters && role ? { role } : {}),
    ...(signRequestID ? { sign_request_id: signRequestID } : {}),
  };
  const { data, loading, error, reload } = useApi(
    (c) => c.evm.transactions.list(filter),
    [status, chainID, fromAddress, signType, apiKeyID, role, signRequestID],
  );

  const selectCls =
    "rounded-md border border-ink-300 bg-white px-2 py-1 text-sm text-ink-900";
  const inputCls =
    "rounded-md border border-ink-300 bg-white px-2 py-1 text-sm text-ink-900";

  return (
    <div className="space-y-6">
      <PageHeader
        title="Transactions"
        subtitle="On-chain transactions the daemon broadcast on this signer's behalf."
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

      <Card>
        <div
          data-testid="transactions-filter-bar"
          className="mb-4 flex flex-wrap items-end gap-3 rounded-md border border-ink-200 bg-ink-50 p-3"
        >
          <FilterField label="Status">
            <select
              value={status}
              onChange={(e) =>
                setStatus(e.target.value as OnChainTransactionStatus | "")
              }
              className={selectCls}
            >
              <option value="">All</option>
              {STATUSES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </FilterField>

          <FilterField label="From">
            <input
              type="text"
              value={fromAddress}
              onChange={(e) => setFromAddress(e.target.value.trim())}
              placeholder="0x…"
              className={`${inputCls} w-44 font-mono text-xs`}
            />
          </FilterField>

          <FilterField label="Chain ID">
            <input
              type="text"
              inputMode="numeric"
              value={chainID}
              onChange={(e) => setChainID(e.target.value.trim())}
              placeholder="e.g. 1"
              className={`${inputCls} w-24`}
            />
          </FilterField>

          <FilterField label="Sign type">
            <select
              value={signType}
              onChange={(e) => setSignType(e.target.value)}
              className={selectCls}
            >
              <option value="">All</option>
              {SIGN_TYPES.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
          </FilterField>

          <FilterField label="Sign request">
            <input
              type="text"
              value={signRequestID}
              onChange={(e) => setSignRequestID(e.target.value.trim())}
              placeholder="uuid"
              data-testid="transactions-filter-sign-request"
              className={`${inputCls} w-36 font-mono text-xs`}
            />
          </FilterField>

          {showAdminFilters && (
            <>
              <FilterField label="API key">
                <select
                  value={apiKeyID}
                  onChange={(e) => setAPIKeyID(e.target.value)}
                  className={selectCls}
                >
                  <option value="">All</option>
                  {(namesApi.data?.keys ?? []).map((k) => (
                    <option key={k.id} value={k.id}>
                      {k.id} {k.name && `· ${k.name}`}
                    </option>
                  ))}
                </select>
              </FilterField>

              <FilterField label="Role">
                <select
                  value={role}
                  onChange={(e) => setRole(e.target.value)}
                  className={selectCls}
                >
                  <option value="">All</option>
                  {ROLES.map((r) => (
                    <option key={r} value={r}>
                      {r}
                    </option>
                  ))}
                </select>
              </FilterField>
            </>
          )}
        </div>

        {loading && <Loading />}
        {error && <ErrorBanner msg={error} />}
        {data &&
          (data.transactions.length === 0 ? (
            <Empty msg="No transactions yet — broadcast something through the daemon to populate this view." />
          ) : (
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase text-ink-500">
                <tr>
                  <th className="py-1 pr-3 font-normal">When</th>
                  <th className="py-1 pr-3 font-normal">Hash</th>
                  <th className="py-1 pr-3 font-normal">From</th>
                  <th className="py-1 pr-3 font-normal">Chain</th>
                  <th className="py-1 pr-3 font-normal">Block</th>
                  <th className="py-1 pr-3 font-normal">Status</th>
                  <th className="py-1 font-normal text-right">Sign req</th>
                </tr>
              </thead>
              <tbody>
                {data.transactions.map((tx) => (
                  <TxRow key={tx.id} tx={tx} />
                ))}
              </tbody>
            </table>
          ))}
      </Card>
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

function TxRow({ tx }: { tx: OnChainTransaction }) {
  return (
    <tr className="border-t border-ink-100">
      <td className="py-1 pr-3 font-mono text-xs text-ink-700">
        {tx.broadcasted_at}
      </td>
      <td className="py-1 pr-3 font-mono text-xs text-ink-900">
        <Link to={`/transactions/${tx.id}`} className="hover:text-accent-600">
          {shorten(tx.tx_hash, 10, 8)}
        </Link>
      </td>
      <td className="py-1 pr-3 font-mono text-xs text-ink-700">
        {shorten(tx.from_address)}
      </td>
      <td className="py-1 pr-3 font-mono text-xs">{tx.chain_id}</td>
      <td className="py-1 pr-3 font-mono text-xs text-ink-700">
        {tx.block_number ?? "—"}
      </td>
      <td className="py-1 pr-3">
        <Badge tone={statusTone(tx)}>{statusLabel(tx)}</Badge>
      </td>
      <td className="py-1 text-right text-[11px]">
        {tx.sign_request_id ? (
          <Link
            to={`/requests/${tx.sign_request_id}`}
            className="text-accent-600 hover:text-accent-500"
          >
            details →
          </Link>
        ) : (
          <span className="text-ink-400">—</span>
        )}
      </td>
    </tr>
  );
}

function statusLabel(tx: OnChainTransaction): string {
  if (tx.status === "mined") {
    if (tx.receipt_status === 0) return "reverted";
    return "mined";
  }
  return tx.status;
}

function statusTone(
  tx: OnChainTransaction,
): "green" | "yellow" | "red" | "neutral" {
  switch (tx.status) {
    case "mined":
      return tx.receipt_status === 0 ? "red" : "green";
    case "broadcasted":
      return "yellow";
    case "dropped":
    case "failed":
      return "red";
    default:
      return "neutral";
  }
}
