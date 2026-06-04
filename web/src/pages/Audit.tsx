import { useState } from "react";
import {
  ALL_AUDIT_EVENT_TYPES,
  type AuditEventType,
  type ListAuditFilter,
} from "remote-signer-client";
import { AuditRecordRow } from "../components/AuditTimeline";
import {
  Card,
  Empty,
  ErrorBanner,
  Loading,
  PageHeader,
} from "../components/ui";
import { getCredentials } from "../lib/auth";
import { useApi } from "../lib/useApi";

const SEVERITIES = ["info", "warning", "critical"] as const;
type Severity = (typeof SEVERITIES)[number];

const PAGE_SIZE = 50;

/**
 * Full audit log explorer with filters aligned to GET /api/v1/audit.
 * By default omits api_request noise; operators can include HTTP traffic.
 */
export function Audit() {
  const [eventType, setEventType] = useState<AuditEventType | "">("");
  const [severity, setSeverity] = useState<Severity | "">("");
  const [apiKeyID, setAPIKeyID] = useState("");
  const [signerAddress, setSignerAddress] = useState("");
  const [signRequestID, setSignRequestID] = useState("");
  const [chainID, setChainID] = useState("");
  const [startTime, setStartTime] = useState("");
  const [endTime, setEndTime] = useState("");
  const [includeHTTP, setIncludeHTTP] = useState(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [cursor, setCursor] = useState<{ c: string; id: string } | null>(null);
  const [history, setHistory] = useState<Array<{ c: string; id: string }>>([]);

  const namesApi = useApi((c) => c.apiKeys.names());
  const currentApiKeyID = getCredentials()?.apiKeyID ?? "";
  const currentRole =
    namesApi.data?.keys.find((k) => k.id === currentApiKeyID)?.role ?? "";
  const showAdminFilters = currentRole === "admin" || currentRole === "dev";

  const filter: ListAuditFilter = {
    limit: PAGE_SIZE,
    ...(eventType ? { event_type: eventType } : {}),
    ...(severity ? { severity } : {}),
    ...(!includeHTTP ? { exclude_event_type: "api_request" } : {}),
    ...(showAdminFilters && apiKeyID ? { api_key_id: apiKeyID } : {}),
    ...(signerAddress ? { signer_address: signerAddress } : {}),
    ...(signRequestID ? { sign_request_id: signRequestID } : {}),
    ...(chainID ? { chain_id: chainID } : {}),
    ...(startTime ? { start_time: toRFC3339(startTime) } : {}),
    ...(endTime ? { end_time: toRFC3339(endTime) } : {}),
    ...(cursor ? { cursor: cursor.c, cursor_id: cursor.id } : {}),
  };

  const filterKey = JSON.stringify({
    eventType,
    severity,
    apiKeyID,
    signerAddress,
    signRequestID,
    chainID,
    startTime,
    endTime,
    includeHTTP,
    cursor: cursor?.c,
  });

  const { data, loading, error, reload } = useApi(
    (c) => c.audit.list(filter),
    [filterKey],
  );

  function resetCursor() {
    setCursor(null);
    setHistory([]);
    setExpandedId(null);
  }

  function next() {
    if (!data?.has_more || !data.next_cursor || !data.next_cursor_id) return;
    if (cursor) setHistory((h) => [...h, cursor]);
    setCursor({ c: data.next_cursor, id: data.next_cursor_id });
    setExpandedId(null);
  }

  function prev() {
    if (history.length === 0) {
      setCursor(null);
      return;
    }
    const last = history[history.length - 1];
    setHistory((h) => h.slice(0, -1));
    setCursor(last);
    setExpandedId(null);
  }

  const selectCls =
    "rounded-md border border-ink-300 bg-white px-2 py-1 text-sm text-ink-900";
  const inputCls =
    "rounded-md border border-ink-300 bg-white px-2 py-1 text-sm text-ink-900";

  const hasFilters =
    eventType ||
    severity ||
    apiKeyID ||
    signerAddress ||
    signRequestID ||
    chainID ||
    startTime ||
    endTime ||
    includeHTTP;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Audit log"
        subtitle="Every authenticated action and policy decision the daemon recorded."
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
          data-testid="audit-filter-bar"
          className="mb-4 flex flex-wrap items-end gap-3 rounded-md border border-ink-200 bg-ink-50 p-3"
        >
          <FilterField label="Event type">
            <select
              value={eventType}
              onChange={(e) => {
                setEventType(e.target.value as AuditEventType | "");
                resetCursor();
              }}
              className={selectCls}
            >
              <option value="">All</option>
              {ALL_AUDIT_EVENT_TYPES.map((t: AuditEventType) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
          </FilterField>

          <FilterField label="Severity">
            <select
              value={severity}
              onChange={(e) => {
                setSeverity(e.target.value as Severity | "");
                resetCursor();
              }}
              className={selectCls}
            >
              <option value="">All</option>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </FilterField>

          {showAdminFilters && (
            <FilterField label="API key">
              <select
                value={apiKeyID}
                onChange={(e) => {
                  setAPIKeyID(e.target.value);
                  resetCursor();
                }}
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
          )}

          <FilterField label="Signer">
            <input
              type="text"
              value={signerAddress}
              onChange={(e) => {
                setSignerAddress(e.target.value.trim());
                resetCursor();
              }}
              placeholder="0x…"
              className={`${inputCls} w-40 font-mono text-xs`}
            />
          </FilterField>

          <FilterField label="Sign request">
            <input
              type="text"
              value={signRequestID}
              onChange={(e) => {
                setSignRequestID(e.target.value.trim());
                resetCursor();
              }}
              placeholder="uuid"
              className={`${inputCls} w-36 font-mono text-xs`}
            />
          </FilterField>

          <FilterField label="Chain ID">
            <input
              type="text"
              inputMode="numeric"
              value={chainID}
              onChange={(e) => {
                setChainID(e.target.value.trim());
                resetCursor();
              }}
              placeholder="e.g. 1"
              className={`${inputCls} w-24`}
            />
          </FilterField>

          <FilterField label="From">
            <input
              type="datetime-local"
              value={startTime}
              onChange={(e) => {
                setStartTime(e.target.value);
                resetCursor();
              }}
              className={inputCls}
            />
          </FilterField>

          <FilterField label="To">
            <input
              type="datetime-local"
              value={endTime}
              onChange={(e) => {
                setEndTime(e.target.value);
                resetCursor();
              }}
              className={inputCls}
            />
          </FilterField>

          <label className="flex items-center gap-2 pb-1 text-xs text-ink-700">
            <input
              type="checkbox"
              checked={includeHTTP}
              onChange={(e) => {
                setIncludeHTTP(e.target.checked);
                resetCursor();
              }}
            />
            Include HTTP traffic
          </label>

          {hasFilters && (
            <button
              type="button"
              onClick={() => {
                setEventType("");
                setSeverity("");
                setAPIKeyID("");
                setSignerAddress("");
                setSignRequestID("");
                setChainID("");
                setStartTime("");
                setEndTime("");
                setIncludeHTTP(false);
                resetCursor();
              }}
              className="pb-1 text-xs text-ink-500 hover:text-ink-900"
            >
              Clear filters
            </button>
          )}
        </div>

        {loading && <Loading />}
        {error && <ErrorBanner msg={error} />}
        {data &&
          (data.records.length === 0 ? (
            <Empty msg="No matching audit events." />
          ) : (
            <>
              <table className="w-full text-left text-sm">
                <thead className="text-xs uppercase text-ink-500">
                  <tr>
                    <th className="py-1 pr-3 font-normal">When</th>
                    <th className="py-1 pr-3 font-normal">Event</th>
                    <th className="py-1 pr-3 font-normal">API key</th>
                    <th className="py-1 pr-3 font-normal">IP</th>
                    <th className="py-1 pr-3 font-normal">Signer</th>
                    <th className="py-1 pr-3 font-normal">Chain</th>
                    <th className="py-1 pr-3 font-normal">Severity</th>
                    <th className="py-1 font-normal text-right" />
                  </tr>
                </thead>
                <tbody>
                  {data.records.map((r) => (
                    <AuditRecordRow
                      key={r.id}
                      record={r}
                      expanded={expandedId === r.id}
                      onToggle={() =>
                        setExpandedId((cur) => (cur === r.id ? null : r.id))
                      }
                    />
                  ))}
                </tbody>
              </table>

              <div className="mt-4 flex items-center justify-between text-xs text-ink-500">
                <span>
                  Showing {data.records.length}
                  {data.total ? ` of ${data.total}` : ""} records
                  {!includeHTTP && (
                    <span className="ml-2 text-ink-400">
                      (HTTP traffic hidden)
                    </span>
                  )}
                </span>
                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={prev}
                    disabled={history.length === 0 && !cursor}
                    className="rounded-md border border-ink-200 px-2 py-1 text-xs text-ink-700 hover:bg-ink-100 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    ← Prev
                  </button>
                  <button
                    type="button"
                    onClick={next}
                    disabled={!data.has_more}
                    className="rounded-md border border-ink-200 px-2 py-1 text-xs text-ink-700 hover:bg-ink-100 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    Next →
                  </button>
                </div>
              </div>
            </>
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

/** datetime-local → RFC3339 for the API. */
function toRFC3339(local: string): string {
  if (!local) return "";
  const d = new Date(local);
  if (Number.isNaN(d.getTime())) return "";
  return d.toISOString();
}
