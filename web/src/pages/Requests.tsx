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
import { getClient } from "../lib/auth";
import { useApi } from "../lib/useApi";

const STATUSES: RequestStatus[] = [
  "pending",
  "authorizing",
  "signing",
  "completed",
  "rejected",
  "failed",
];

/**
 * Sign-request queue overview. Rows link out to /requests/:id for the
 * full payload + action view; the only inline actions are Approve and
 * Reject for rows whose status still admits them, which is the most
 * common operator gesture.
 */
export function Requests() {
  // Default to "all" so freshly-landed operators see history + active
  // queue together; filtering by `authorizing` is one click away and
  // restoring it as the default hid completed/rejected from view.
  const [status, setStatus] = useState<RequestStatus | "">("");
  const [mutationError, setMutationError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const filter: ListRequestsFilter = {
    limit: 50,
    ...(status ? { status } : {}),
  };
  const { data, loading, error, reload } = useApi(
    (c) => c.evm.requests.list(filter),
    [status],
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
        <div className="mb-4 flex flex-wrap items-end gap-3">
          <div>
            <label className="mb-1 block text-[11px] uppercase tracking-wide text-ink-500">
              Status
            </label>
            <select
              value={status}
              onChange={(e) => setStatus(e.target.value as RequestStatus | "")}
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
