import { useState } from "react";
import type {
  AuditEventType,
  ListAuditFilter,
} from "remote-signer-client";
import {
  Badge,
  Card,
  Empty,
  ErrorBanner,
  Loading,
  PageHeader,
} from "../components/ui";
import { useApi } from "../lib/useApi";

const EVENT_TYPES: AuditEventType[] = [
  "auth_success",
  "auth_failure",
  "sign_request",
  "sign_complete",
  "sign_failed",
  "sign_rejected",
  "rule_matched",
  "approval_request",
  "approval_granted",
  "approval_denied",
  "rule_created",
  "rule_updated",
  "rule_deleted",
  "rate_limit_hit",
];

const SEVERITIES = ["info", "warning", "critical"] as const;
type Severity = (typeof SEVERITIES)[number];

const PAGE_SIZE = 50;

/**
 * Full audit log explorer. Filtered cursor-paginated table — daemon returns
 * a stable next_cursor + next_cursor_id pair we feed back on subsequent
 * fetches. Filter changes reset the cursor history.
 */
export function Audit() {
  const [eventType, setEventType] = useState<AuditEventType | "">("");
  const [severity, setSeverity] = useState<Severity | "">("");
  const [cursor, setCursor] = useState<{ c: string; id: string } | null>(null);
  // Stack of cursors we've consumed, so "Prev" pops back through history.
  // Cursor pagination is forward-only on the wire; the back stack is a
  // client-side convenience.
  const [history, setHistory] = useState<Array<{ c: string; id: string }>>([]);

  const filter: ListAuditFilter = {
    limit: PAGE_SIZE,
    ...(eventType ? { event_type: eventType } : {}),
    ...(severity ? { severity } : {}),
    ...(cursor ? { cursor: cursor.c, cursor_id: cursor.id } : {}),
  };

  const { data, loading, error, reload } = useApi(
    (c) => c.audit.list(filter),
    [eventType, severity, cursor?.c, cursor?.id],
  );

  function resetCursor() {
    setCursor(null);
    setHistory([]);
  }

  function next() {
    if (!data?.has_more || !data.next_cursor || !data.next_cursor_id) return;
    if (cursor) setHistory((h) => [...h, cursor]);
    setCursor({ c: data.next_cursor!, id: data.next_cursor_id! });
  }

  function prev() {
    if (history.length === 0) {
      setCursor(null);
      return;
    }
    const last = history[history.length - 1];
    setHistory((h) => h.slice(0, -1));
    setCursor(last);
  }

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
        <div className="mb-4 flex flex-wrap items-end gap-3">
          <div>
            <label className="mb-1 block text-[11px] uppercase tracking-wide text-ink-500">
              Event type
            </label>
            <select
              value={eventType}
              onChange={(e) => {
                setEventType(e.target.value as AuditEventType | "");
                resetCursor();
              }}
              className="rounded-md border border-ink-300 px-2 py-1 text-sm"
            >
              <option value="">all</option>
              {EVENT_TYPES.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="mb-1 block text-[11px] uppercase tracking-wide text-ink-500">
              Severity
            </label>
            <select
              value={severity}
              onChange={(e) => {
                setSeverity(e.target.value as Severity | "");
                resetCursor();
              }}
              className="rounded-md border border-ink-300 px-2 py-1 text-sm"
            >
              <option value="">all</option>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </div>
          {(eventType || severity) && (
            <button
              type="button"
              onClick={() => {
                setEventType("");
                setSeverity("");
                resetCursor();
              }}
              className="text-xs text-ink-500 hover:text-ink-900"
            >
              clear filters
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
                    <th className="py-1 pr-3 font-normal">Actor</th>
                    <th className="py-1 pr-3 font-normal">Signer</th>
                    <th className="py-1 font-normal">Severity</th>
                  </tr>
                </thead>
                <tbody>
                  {data.records.map((r) => (
                    <tr key={r.id} className="border-t border-ink-100">
                      <td className="py-1 pr-3 font-mono text-xs text-ink-700">
                        {r.timestamp}
                      </td>
                      <td className="py-1 pr-3">{r.event_type}</td>
                      <td className="py-1 pr-3 font-mono text-xs text-ink-700">
                        {r.api_key_id || "—"}
                      </td>
                      <td className="py-1 pr-3 font-mono text-xs text-ink-700">
                        {r.signer_address || "—"}
                      </td>
                      <td className="py-1">
                        <Badge tone={severityTone(r.severity)}>
                          {r.severity}
                        </Badge>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>

              <div className="mt-4 flex items-center justify-between text-xs text-ink-500">
                <span>
                  Showing {data.records.length}
                  {data.total ? ` of ${data.total}` : ""} records
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

function severityTone(sev: string): "neutral" | "yellow" | "red" {
  switch (sev) {
    case "critical":
      return "red";
    case "warning":
      return "yellow";
    default:
      return "neutral";
  }
}
