import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  APIError,
  type ListRequestsFilter,
  type RequestStatus,
  type RequestStatusResponse,
} from "remote-signer-client";
import { LockedSignersQueueBanner } from "../components/RequestBlockerBanner";
import { useConfirm, useToast } from "../components/feedback";
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
import {
  getRequestBlocker,
  isActionableRequestStatus,
  REQUEST_LIST_PAGE_SIZE,
  summarizeLockedSignersInRequests,
} from "../lib/requestQueue";
import { useCanApproveRequest } from "../lib/rbac";
import { useApi } from "../lib/useApi";
import { useLockedSignerAddresses } from "../lib/useLockedSigners";

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
 * full payload + action view; inline Approve/Reject plus bulk selection
 * for pending/authorizing rows when the operator has approval permission.
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
  const [bulkBusy, setBulkBusy] = useState(false);
  const [selected, setSelected] = useState<Set<string>>(() => new Set());
  const [listCursor, setListCursor] = useState<{ c: string; id: string } | null>(
    null,
  );
  const [cursorHistory, setCursorHistory] = useState<
    Array<{ c: string; id: string } | null>
  >([]);
  const [selectAllBusy, setSelectAllBusy] = useState(false);

  const namesApi = useApi((c) => c.apiKeys.names());
  const currentApiKeyID = getCredentials()?.apiKeyID ?? "";
  const currentRole =
    namesApi.data?.keys.find((k) => k.id === currentApiKeyID)?.role ?? "";
  const showAdminFilters = currentRole === "admin" || currentRole === "dev";
  const canApprove = useCanApproveRequest();
  const confirm = useConfirm();
  const toast = useToast();
  const lockedSigners = useLockedSignerAddresses();
  const selectAllRef = useRef<HTMLInputElement>(null);

  const baseFilter = useMemo((): ListRequestsFilter => {
    return {
      limit: REQUEST_LIST_PAGE_SIZE,
      ...(status ? { status } : {}),
      ...(signerAddress ? { signer_address: signerAddress } : {}),
      ...(chainID ? { chain_id: chainID } : {}),
      ...(signType ? { sign_type: signType } : {}),
      ...(transactionStatus ? { transaction_status: transactionStatus } : {}),
      ...(showAdminFilters && apiKeyID ? { api_key_id: apiKeyID } : {}),
      ...(showAdminFilters && role ? { role } : {}),
    };
  }, [
    status,
    signerAddress,
    chainID,
    signType,
    transactionStatus,
    apiKeyID,
    role,
    showAdminFilters,
  ]);

  const filter: ListRequestsFilter = {
    ...baseFilter,
    ...(listCursor ? { cursor: listCursor.c, cursor_id: listCursor.id } : {}),
  };
  const { data, loading, error, reload } = useApi(
    (c) => c.evm.requests.list(filter),
    [
      status,
      signerAddress,
      chainID,
      signType,
      transactionStatus,
      apiKeyID,
      role,
      listCursor?.c,
      listCursor?.id,
    ],
  );

  const requests = data?.requests ?? [];

  const actionableOnPage = useMemo(
    () => requests.filter((r) => isActionableRequestStatus(r.status)),
    [requests],
  );

  const actionableIds = useMemo(
    () => actionableOnPage.map((r) => r.id),
    [actionableOnPage],
  );

  const allActionableSelected =
    actionableIds.length > 0 && actionableIds.every((id) => selected.has(id));
  const someSelected = selected.size > 0;

  const lockedInQueue = useMemo(
    () => summarizeLockedSignersInRequests(requests, lockedSigners),
    [requests, lockedSigners],
  );

  useEffect(() => {
    setSelected(new Set());
    setListCursor(null);
    setCursorHistory([]);
  }, [status, signerAddress, chainID, signType, transactionStatus, apiKeyID, role]);

  function goNextPage() {
    if (!data?.next_cursor || !data?.next_cursor_id) return;
    setCursorHistory((h) => [...h, listCursor]);
    setListCursor({ c: data.next_cursor, id: data.next_cursor_id });
  }

  function goPrevPage() {
    setCursorHistory((h) => {
      const copy = [...h];
      const prev = copy.pop() ?? null;
      setListCursor(prev);
      return copy;
    });
  }

  async function selectAllMatching() {
    const client = getClient();
    if (!client) return;
    setSelectAllBusy(true);
    setMutationError(null);
    try {
      const resp = await client.evm.requests.list({ ...baseFilter, limit: 200 });
      const ids = resp.requests
        .filter((r) => isActionableRequestStatus(r.status))
        .map((r) => r.id);
      setSelected(new Set(ids));
      if (resp.has_more) {
        toast({
          title: `Selected ${ids.length} actionable requests (first 200 matches). Narrow filters to select more.`,
          tone: "info",
        });
      }
    } catch (e) {
      setMutationError(formatErr(e));
    } finally {
      setSelectAllBusy(false);
    }
  }

  const pageNumber = cursorHistory.length + 1;

  useEffect(() => {
    const el = selectAllRef.current;
    if (el) {
      el.indeterminate = someSelected && !allActionableSelected;
    }
  }, [someSelected, allActionableSelected]);

  function toggleOne(id: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function toggleSelectAll() {
    if (allActionableSelected) {
      setSelected(new Set());
      return;
    }
    setSelected(new Set(actionableIds));
  }

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
    const ok = await confirm({
      title: "Reject request",
      message: "Reject this request? It cannot be re-approved later.",
      confirmLabel: "Reject",
      tone: "danger",
    });
    if (!ok) return;
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

  async function bulkDecide(approved: boolean) {
    const ids = [...selected];
    if (ids.length === 0) return;

    if (!approved) {
      const ok = await confirm({
        title: `Reject ${ids.length} request(s)?`,
        message: "Rejected requests cannot be re-approved later.",
        confirmLabel: `Reject ${ids.length}`,
        tone: "danger",
      });
      if (!ok) return;
    }

    const client = getClient();
    if (!client) return;

    setBulkBusy(true);
    setMutationError(null);

    try {
      const batch = await client.evm.requests.batchApprove({
        request_ids: ids,
        approved,
      });

      setSelected(new Set());
      reload();

      const { succeeded, failed, idempotent } = batch.summary;
      const failures = batch.results
        .filter((r) => r.error)
        .map((r) => `${shorten(r.request_id, 8, 4)}: ${r.error}`);

      if (failed === 0) {
        const idemNote =
          idempotent > 0 ? ` (${idempotent} already in target state)` : "";
        toast({
          title: approved
            ? `Approved ${succeeded} request(s).${idemNote}`
            : `Rejected ${succeeded} request(s).${idemNote}`,
          tone: "success",
        });
      } else {
        const msg = `${succeeded} succeeded, ${failed} failed. ${failures.slice(0, 3).join("; ")}`;
        setMutationError(msg);
        if (succeeded > 0) {
          toast({
            title: `${succeeded} request(s) updated; ${failed} failed.`,
            tone: "info",
          });
        }
      }
    } catch (e) {
      setMutationError(formatErr(e));
    } finally {
      setBulkBusy(false);
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
        subtitle="Approve or reject pending requests; select rows for bulk actions."
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

      {!loading && lockedInQueue.length > 0 && (
        <LockedSignersQueueBanner addresses={lockedInQueue} />
      )}

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

        {canApprove && someSelected && (
          <div
            data-testid="requests-bulk-toolbar"
            className="mb-3 flex flex-wrap items-center gap-2 rounded-md border border-accent-200 bg-accent-50 px-3 py-2 text-sm"
          >
            <span className="text-ink-700">{selected.size} selected</span>
            <button
              type="button"
              disabled={bulkBusy}
              onClick={() => bulkDecide(true)}
              className="rounded-md bg-accent-500 px-3 py-1 text-xs font-medium text-white hover:bg-accent-600 disabled:opacity-50"
            >
              Approve selected
            </button>
            <button
              type="button"
              disabled={bulkBusy}
              onClick={() => bulkDecide(false)}
              className="rounded-md border border-red-200 px-3 py-1 text-xs text-red-700 hover:bg-red-50 disabled:opacity-50"
            >
              Reject selected
            </button>
            <button
              type="button"
              disabled={bulkBusy}
              onClick={() => setSelected(new Set())}
              className="rounded-md border border-ink-200 px-3 py-1 text-xs text-ink-600 hover:bg-white disabled:opacity-50"
            >
              Clear
            </button>
          </div>
        )}

        {canApprove && data && data.total > 0 && (
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <button
              type="button"
              data-testid="requests-select-all-matching"
              disabled={selectAllBusy || bulkBusy}
              onClick={() => void selectAllMatching()}
              className="rounded-md border border-ink-200 px-2 py-1 text-xs text-ink-700 hover:bg-ink-100 disabled:opacity-50"
            >
              Select all matching (≤200)
            </button>
          </div>
        )}

        {data && (data.requests.length > 0 || data.total > 0) && (
          <div
            data-testid="requests-pagination"
            className="mb-3 flex flex-wrap items-center justify-between gap-2 text-xs text-ink-600"
          >
            <span>
              Showing {requests.length}
              {typeof data.total === "number" ? ` of ${data.total}` : ""}
              {(cursorHistory.length > 0 || data.has_more) && ` · page ${pageNumber}`}
              {selected.size > 0 && ` · ${selected.size} selected across pages`}
            </span>
            <div className="flex gap-2">
              <button
                type="button"
                data-testid="requests-page-prev"
                disabled={cursorHistory.length === 0 || loading}
                onClick={goPrevPage}
                className="rounded-md border border-ink-200 px-2 py-1 text-xs text-ink-700 hover:bg-ink-100 disabled:opacity-50"
              >
                Previous
              </button>
              <button
                type="button"
                data-testid="requests-page-next"
                disabled={!data.has_more || loading}
                onClick={goNextPage}
                className="rounded-md border border-ink-200 px-2 py-1 text-xs text-ink-700 hover:bg-ink-100 disabled:opacity-50"
              >
                Next
              </button>
            </div>
          </div>
        )}

        {loading && <Loading />}
        {error && <ErrorBanner msg={error} />}
        {data &&
          (data.requests.length === 0 ? (
            <Empty msg="No matching requests." />
          ) : (
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase text-ink-500">
                <tr>
                  {canApprove && (
                    <th className="w-8 py-1 pr-2 font-normal">
                      <input
                        ref={selectAllRef}
                        type="checkbox"
                        data-testid="requests-select-all"
                        checked={allActionableSelected}
                        disabled={
                          bulkBusy || actionableIds.length === 0
                        }
                        onChange={toggleSelectAll}
                        aria-label="Select all actionable requests on this page"
                        className="rounded border-ink-300"
                      />
                    </th>
                  )}
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
                    busy={busy === r.id || bulkBusy}
                    canApprove={canApprove}
                    selected={selected.has(r.id)}
                    lockedSigners={lockedSigners}
                    onToggleSelect={() => toggleOne(r.id)}
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
  canApprove,
  selected,
  lockedSigners,
  onToggleSelect,
  onApprove,
  onReject,
}: {
  req: RequestStatusResponse;
  busy: boolean;
  canApprove: boolean;
  selected: boolean;
  lockedSigners: ReadonlySet<string>;
  onToggleSelect: () => void;
  onApprove: () => void;
  onReject: () => void;
}) {
  const navigate = useNavigate();
  const actionable = isActionableRequestStatus(req.status);
  const blocker = getRequestBlocker(req, lockedSigners);

  return (
    <tr
      className="cursor-pointer border-t border-ink-100 hover:bg-ink-50"
      onClick={() => navigate(`/requests/${req.id}`)}
    >
      {canApprove && (
        <td
          className="py-1 pr-2 align-top"
          onClick={(e) => e.stopPropagation()}
        >
          {actionable ? (
            <input
              type="checkbox"
              data-testid={`request-row-select-${req.id}`}
              checked={selected}
              disabled={busy}
              onChange={onToggleSelect}
              aria-label={`Select request ${req.id}`}
              className="rounded border-ink-300"
            />
          ) : null}
        </td>
      )}
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
      <td className="py-1 pr-3 align-top">
        <Badge tone={statusTone(req.status)}>{req.status}</Badge>
        {blocker && (
          <p
            className={`mt-1 max-w-[14rem] text-[10px] leading-snug ${
              blocker.kind === "signer_locked"
                ? "text-red-700"
                : blocker.kind === "rule_matched_stuck"
                  ? "text-amber-800"
                  : blocker.kind === "sign_failed"
                    ? "text-orange-800"
                    : "text-ink-600"
            }`}
          >
            {blocker.kind === "signer_locked"
              ? "Signer locked"
              : blocker.message}
          </p>
        )}
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
        {actionable && canApprove ? (
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
