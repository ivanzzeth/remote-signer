import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  APIError,
  type ListRequestsFilter,
  type RequestStatus,
  type RequestStatusResponse,
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
import { getClient, getCredentials } from "../lib/auth";
import { useApi } from "../lib/useApi";

const STATUSES: RequestStatus[] = [
  "pending",
  "authorizing",
  "signing",
  "completed",
  "rejected",
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

const TX_STATUSES = ["none", "broadcasted", "mined", "dropped", "failed"] as const;

const ROLES = ["admin", "dev", "agent", "strategy"] as const;

/**
 * Sign-request queue overview. Rows link out to /requests/:id for the
 * full payload + action view; the only inline actions are Approve and
 * Reject for rows whose status still admits them, which is the most
 * common operator gesture.
 */
export function Requests() {
  const [status, setStatus] = useState<RequestStatus | "">("");
  const [signerAddress, setSignerAddress] = useState("");
  const [chainID, setChainID] = useState("");
  const [signType, setSignType] = useState("");
  const [transactionStatus, setTransactionStatus] = useState<
    (typeof TX_STATUSES)[number] | ""
  >("");
  const [apiKeyID, setAPIKeyID] = useState("");
  const [role, setRole] = useState("");
  const [mutationError, setMutationError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const namesApi = useApi((c) => c.apiKeys.names());
  const currentApiKeyID = getCredentials()?.apiKeyID ?? "";
  const currentRole =
    namesApi.data?.keys.find((k) => k.id === currentApiKeyID)?.role ?? "";
  const showAdminFilters = currentRole === "admin" || currentRole === "dev";

  const filter: ListRequestsFilter = {
    limit: 50,
    ...(status ? { status } : {}),
    ...(signerAddress ? { signer_address: signerAddress } : {}),
    ...(chainID ? { chain_id: chainID } : {}),
    ...(signType ? { sign_type: signType } : {}),
    ...(transactionStatus ? { transaction_status: transactionStatus } : {}),
    ...(showAdminFilters && apiKeyID ? { api_key_id: apiKeyID } : {}),
    ...(showAdminFilters && role ? { role } : {}),
  };
  const { data, loading, error, reload } = useApi(
    (c) => c.evm.requests.list(filter),
    [status, signerAddress, chainID, signType, transactionStatus, apiKeyID, role],
  );

  async function approve(id: string) {
    const client = getClient();
    if (!client) return;
    setBusy(id);
    setMutationError(null);
    try {
      await client.evm.requests.approve(id, { approved: true });
      reload();
    } catch (e) {
      setMutationError(formatErr(e));
    } finally {
      setBusy(null);
    }
  }

  async function reject(id: string) {
    if (!confirm("Reject this request? It cannot be re-approved later.")) return;
    const client = getClient();
    if (!client) return;
    setBusy(id);
    setMutationError(null);
    try {
      await client.evm.requests.approve(id, { approved: false });
      reload();
    } catch (e) {
      setMutationError(formatErr(e));
    } finally {
      setBusy(null);
    }
  }

  const selectCls =
    "rounded-md border border-ink-300 bg-white px-2 py-1 text-sm text-ink-900";
  const inputCls =
    "rounded-md border border-ink-300 bg-white px-2 py-1 text-sm text-ink-900";

  return (
    <div className="space-y-6">
      <PageHeader
        title="Sign requests"
        subtitle="Approve or reject pending requests; click a row for full details."
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

      {mutationError && <ErrorBanner msg={mutationError} />}

      <Card>
        <div
          data-testid="requests-filter-bar"
          className="mb-4 flex flex-wrap items-end gap-3 rounded-md border border-ink-200 bg-ink-50 p-3"
        >
          <FilterField label="Status">
            <select
              value={status}
              onChange={(e) => setStatus(e.target.value as RequestStatus | "")}
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

          <FilterField label="Signer">
            <input
              type="text"
              value={signerAddress}
              onChange={(e) => setSignerAddress(e.target.value.trim())}
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

          <FilterField label="On-chain">
            <select
              value={transactionStatus}
              onChange={(e) =>
                setTransactionStatus(e.target.value as (typeof TX_STATUSES)[number] | "")
              }
              className={selectCls}
            >
              <option value="">All</option>
              {TX_STATUSES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
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
          (data.requests.length === 0 ? (
            <Empty msg="No matching requests." />
          ) : (
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase text-ink-500">
                <tr>
                  <th className="py-1 pr-3 font-normal">When</th>
                  <th className="py-1 pr-3 font-normal">Signer</th>
                  <th className="py-1 pr-3 font-normal">Chain</th>
                  <th className="py-1 pr-3 font-normal">Type</th>
                  <th className="py-1 pr-3 font-normal">By</th>
                  <th className="py-1 pr-3 font-normal">Status</th>
                  <th className="py-1 pr-3 font-normal">On-chain</th>
                  <th className="py-1 font-normal text-right">Action</th>
                </tr>
              </thead>
              <tbody>
                {data.requests.map((r) => (
                  <RequestRow
                    key={r.id}
                    req={r}
                    busy={busy === r.id}
                    onApprove={() => approve(r.id)}
                    onReject={() => reject(r.id)}
                  />
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

function RequestRow({
  req,
  busy,
  onApprove,
  onReject,
}: {
  req: RequestStatusResponse;
  busy: boolean;
  onApprove: () => void;
  onReject: () => void;
}) {
  const navigate = useNavigate();
  const actionable = req.status === "pending" || req.status === "authorizing";

  return (
    <tr
      className="cursor-pointer border-t border-ink-100 hover:bg-ink-50"
      onClick={() => navigate(`/requests/${req.id}`)}
    >
      <td className="py-1 pr-3 font-mono text-xs text-ink-700">
        {req.created_at}
      </td>
      <td className="py-1 pr-3 font-mono text-xs text-ink-900">
        {shorten(req.signer_address)}
      </td>
      <td className="py-1 pr-3 font-mono text-xs text-ink-700">
        {req.chain_type}/{req.chain_id}
      </td>
      <td className="py-1 pr-3 text-xs">{req.sign_type}</td>
      <td className="py-1 pr-3 font-mono text-xs text-ink-700">
        {req.api_key_id}
      </td>
      <td className="py-1 pr-3">
        <Badge tone={statusTone(req.status)}>{req.status}</Badge>
      </td>
      <td
        className="py-1 pr-3 text-xs"
        onClick={(e) => e.stopPropagation()}
      >
        {req.transaction_id ? (
          <Link
            to={`/transactions/${req.transaction_id}`}
            className="text-accent-600 hover:text-accent-500"
          >
            view →
          </Link>
        ) : (
          <span className="text-ink-400">—</span>
        )}
      </td>
      <td
        className="py-1 text-right"
        onClick={(e) => e.stopPropagation()}
      >
        {actionable ? (
          <div className="inline-flex gap-1">
            <button
              type="button"
              onClick={onApprove}
              disabled={busy}
              className="rounded-md bg-accent-500 px-2 py-0.5 text-[11px] font-medium text-white hover:bg-accent-600 disabled:opacity-50"
            >
              Approve
            </button>
            <button
              type="button"
              onClick={onReject}
              disabled={busy}
              className="rounded-md border border-red-200 px-2 py-0.5 text-[11px] text-red-700 hover:bg-red-50 disabled:opacity-50"
            >
              Reject
            </button>
          </div>
        ) : (
          <Link
            to={`/requests/${req.id}`}
            className="text-[11px] text-accent-600 hover:text-accent-500"
          >
            details →
          </Link>
        )}
      </td>
    </tr>
  );
}

function statusTone(s: RequestStatus): "neutral" | "green" | "red" | "yellow" {
  switch (s) {
    case "completed":
      return "green";
    case "rejected":
    case "failed":
      return "red";
    case "pending":
    case "authorizing":
      return "yellow";
    default:
      return "neutral";
  }
}

function formatErr(e: unknown): string {
  if (e instanceof APIError) return `HTTP ${e.statusCode}: ${e.message}`;
  if (e instanceof Error) return e.message;
  return String(e);
}
