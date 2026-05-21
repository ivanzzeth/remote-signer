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
import { useApi } from "../lib/useApi";

const STATUSES: OnChainTransactionStatus[] = [
  "broadcasted",
  "mined",
  "dropped",
  "failed",
];

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

  const filter = {
    limit: 50,
    ...(status ? { status } : {}),
    ...(chainID ? { chain_id: chainID } : {}),
  };
  const { data, loading, error, reload } = useApi(
    (c) => c.evm.transactions.list(filter),
    [status, chainID],
  );

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
        <div className="mb-4 flex flex-wrap items-end gap-3">
          <div>
            <label className="mb-1 block text-[11px] uppercase tracking-wide text-ink-500">
              Status
            </label>
            <select
              value={status}
              onChange={(e) =>
                setStatus(e.target.value as OnChainTransactionStatus | "")
              }
              className="rounded-md border border-ink-300 px-2 py-1 text-sm"
            >
              <option value="">all</option>
              {STATUSES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="mb-1 block text-[11px] uppercase tracking-wide text-ink-500">
              Chain ID
            </label>
            <input
              type="text"
              inputMode="numeric"
              value={chainID}
              onChange={(e) => setChainID(e.target.value.trim())}
              placeholder="e.g. 1"
              className="w-24 rounded-md border border-ink-300 px-2 py-1 text-sm"
            />
          </div>
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

// statusLabel and statusTone collapse the (status, receipt_status)
// pair into a single human-readable label + tone. A mined tx with
// receipt_status=0 is on-chain BUT reverted — distinct from a
// dropped tx that never made it, distinct from a failed broadcast
// that the upstream rejected outright. Keeping the distinction in
// the badge text avoids "mined" giving the operator a false-success
// impression.
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
