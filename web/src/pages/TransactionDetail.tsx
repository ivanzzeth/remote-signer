import { Link, useParams } from "react-router-dom";
import type { ReactNode } from "react";
import type { OnChainTransaction } from "remote-signer-client";
import {
  Badge,
  Card,
  ErrorBanner,
  Loading,
  PageHeader,
} from "../components/ui";
import { useApi } from "../lib/useApi";

// Local helper — the shared `ui` module doesn't export Mono yet and
// every page that needs it inlines its own. Keeping the same one-
// liner shape so future consolidation is mechanical.
function Mono({ children }: { children: ReactNode }) {
  return <span className="font-mono text-xs text-ink-900">{children}</span>;
}

/**
 * Per-tx detail view. Renders every column the tracker holds plus a
 * link back to the originating sign request, so an operator
 * investigating "did this approve actually settle?" has the full
 * audit trail in one place.
 */
export function TransactionDetail() {
  const { id = "" } = useParams<{ id: string }>();
  const { data, loading, error } = useApi(
    (c) => c.evm.transactions.get(id),
    [id],
  );

  return (
    <div className="space-y-6">
      <PageHeader
        title="Transaction"
        subtitle={id}
        actions={
          <Link
            to="/transactions"
            className="rounded-md border border-ink-200 px-3 py-1 text-xs text-ink-700 hover:bg-ink-100"
          >
            ← All transactions
          </Link>
        }
      />

      {loading && <Loading />}
      {error && <ErrorBanner msg={error} />}
      {data && <TxDetail tx={data} />}
    </div>
  );
}

function TxDetail({ tx }: { tx: OnChainTransaction }) {
  return (
    <div className="space-y-4">
      <Card>
        <dl className="grid grid-cols-1 gap-3 text-sm sm:grid-cols-2">
          <Field label="Status">
            <Badge tone={statusTone(tx)}>{statusLabel(tx)}</Badge>
          </Field>
          <Field label="Chain ID">
            <Mono>{tx.chain_id}</Mono>
          </Field>
          <Field label="Tx hash" full>
            <Mono>{tx.tx_hash}</Mono>
          </Field>
          <Field label="From" full>
            <Mono>{tx.from_address || "—"}</Mono>
          </Field>
          <Field label="Block">
            <Mono>{tx.block_number ?? "—"}</Mono>
          </Field>
          <Field label="Block hash" full>
            <Mono>{tx.block_hash || "—"}</Mono>
          </Field>
          <Field label="Tx index">
            <Mono>{tx.tx_index ?? "—"}</Mono>
          </Field>
          <Field label="Gas used">
            <Mono>{tx.gas_used ?? "—"}</Mono>
          </Field>
          <Field label="Receipt status">
            <Mono>
              {tx.receipt_status === undefined
                ? "—"
                : tx.receipt_status === 1
                ? "success (1)"
                : "revert (0)"}
            </Mono>
          </Field>
          {tx.error_message && (
            <Field label="Error" full>
              <span className="text-red-700">{tx.error_message}</span>
            </Field>
          )}
        </dl>
      </Card>

      <Card>
        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-ink-500">
          Timeline
        </h3>
        <ul className="space-y-1 text-xs text-ink-700">
          <li>
            <span className="text-ink-500">Broadcasted at:</span>{" "}
            <Mono>{tx.broadcasted_at}</Mono>
          </li>
          {tx.last_checked_at && (
            <li>
              <span className="text-ink-500">Last polled:</span>{" "}
              <Mono>{tx.last_checked_at}</Mono>
            </li>
          )}
          {tx.mined_at && (
            <li>
              <span className="text-ink-500">Mined at:</span>{" "}
              <Mono>{tx.mined_at}</Mono>
            </li>
          )}
          <li>
            <span className="text-ink-500">Created:</span>{" "}
            <Mono>{tx.created_at}</Mono>
          </li>
          <li>
            <span className="text-ink-500">Updated:</span>{" "}
            <Mono>{tx.updated_at}</Mono>
          </li>
        </ul>
      </Card>

      {tx.sign_request_id && (
        <Card>
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-ink-500">
            Originating sign request
          </h3>
          <Link
            to={`/requests/${tx.sign_request_id}`}
            className="text-sm text-accent-600 hover:text-accent-500"
          >
            <Mono>{tx.sign_request_id}</Mono> →
          </Link>
        </Card>
      )}
    </div>
  );
}

function Field({
  label,
  full,
  children,
}: {
  label: string;
  full?: boolean;
  children: React.ReactNode;
}) {
  return (
    <div className={full ? "sm:col-span-2" : undefined}>
      <dt className="mb-0.5 text-[11px] uppercase tracking-wide text-ink-500">
        {label}
      </dt>
      <dd>{children}</dd>
    </div>
  );
}

function statusLabel(tx: OnChainTransaction): string {
  if (tx.status === "mined" && tx.receipt_status === 0) return "reverted";
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
