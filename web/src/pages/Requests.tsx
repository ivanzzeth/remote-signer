import { useState } from "react";
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
  Row,
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
 * Sign-request approval queue. Lists every request the daemon has on file;
 * an admin can drill into a row to approve or reject. The status filter
 * defaults to `pending` because that's the only state with pending work
 * for a human — completed/rejected are history.
 */
export function Requests() {
  const [status, setStatus] = useState<RequestStatus | "">("pending");
  const [selectedId, setSelectedId] = useState<string | null>(null);
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
      setSelectedId(null);
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
      setSelectedId(null);
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
        subtitle="Approve or reject pending requests; review history of completed ones."
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
              onChange={(e) => {
                setStatus(e.target.value as RequestStatus | "");
                setSelectedId(null);
              }}
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
                  <th className="py-1 font-normal">Status</th>
                </tr>
              </thead>
              <tbody>
                {data.requests.map((r) => (
                  <RequestRow
                    key={r.id}
                    req={r}
                    expanded={selectedId === r.id}
                    onToggle={() =>
                      setSelectedId((id) => (id === r.id ? null : r.id))
                    }
                    onApprove={() => approve(r.id)}
                    onReject={() => reject(r.id)}
                    busy={busy === r.id}
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
  expanded,
  onToggle,
  onApprove,
  onReject,
  busy,
}: {
  req: RequestStatusResponse;
  expanded: boolean;
  onToggle: () => void;
  onApprove: () => void;
  onReject: () => void;
  busy: boolean;
}) {
  const pending = req.status === "pending" || req.status === "authorizing";

  return (
    <>
      <tr
        className="cursor-pointer border-t border-ink-100 hover:bg-ink-50"
        onClick={onToggle}
      >
        <td className="py-1 pr-3 font-mono text-xs text-ink-700">
          {req.created_at}
        </td>
        <td className="py-1 pr-3 font-mono text-xs text-ink-900">
          {req.signer_address}
        </td>
        <td className="py-1 pr-3 font-mono text-xs text-ink-700">
          {req.chain_type}/{req.chain_id}
        </td>
        <td className="py-1 pr-3 text-xs">{req.sign_type}</td>
        <td className="py-1 pr-3 font-mono text-xs text-ink-700">
          {req.api_key_id}
        </td>
        <td className="py-1">
          <Badge tone={statusTone(req.status)}>{req.status}</Badge>
        </td>
      </tr>
      {expanded && (
        <tr className="border-t border-ink-100 bg-ink-50">
          <td colSpan={6} className="px-4 py-3">
            <dl className="grid grid-cols-1 gap-1 text-sm md:grid-cols-2">
              <Row k="ID" v={req.id} mono />
              <Row k="Updated" v={req.updated_at} mono />
              {req.completed_at && (
                <Row k="Completed" v={req.completed_at} mono />
              )}
              {req.rule_matched_id && (
                <Row k="Matched rule" v={req.rule_matched_id} mono />
              )}
              {req.approved_by && (
                <Row k="Approved by" v={req.approved_by} mono />
              )}
              {req.error_message && (
                <Row k="Error" v={req.error_message} />
              )}
              {req.signature && (
                <Row k="Signature" v={req.signature.slice(0, 32) + "…"} mono />
              )}
            </dl>

            {pending && (
              <div className="mt-4 flex gap-3 border-t border-ink-200 pt-3">
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    onApprove();
                  }}
                  disabled={busy}
                  className="rounded-md bg-accent-500 px-3 py-1 text-xs font-medium text-white hover:bg-accent-600 disabled:opacity-50"
                >
                  Approve
                </button>
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    onReject();
                  }}
                  disabled={busy}
                  className="rounded-md border border-red-200 px-3 py-1 text-xs text-red-700 hover:bg-red-50 disabled:opacity-50"
                >
                  Reject
                </button>
              </div>
            )}
          </td>
        </tr>
      )}
    </>
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
