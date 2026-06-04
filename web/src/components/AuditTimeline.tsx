import { useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import type { AuditRecord } from "remote-signer-client";
import { Badge, shorten } from "./ui";

export function auditSeverityTone(
  sev: string,
): "neutral" | "yellow" | "red" {
  switch (sev) {
    case "critical":
      return "red";
    case "warning":
      return "yellow";
    default:
      return "neutral";
  }
}

export function formatAuditDetails(details: AuditRecord["details"]): string {
  if (details == null) return "";
  if (typeof details === "string") return details;
  try {
    return JSON.stringify(details, null, 2);
  } catch {
    return String(details);
  }
}

/** Compact table row for audit lists. */
export function AuditRecordRow({
  record,
  expanded,
  onToggle,
  showExpand = true,
}: {
  record: AuditRecord;
  expanded?: boolean;
  onToggle?: () => void;
  showExpand?: boolean;
}) {
  return (
    <>
      <tr
        className={
          showExpand
            ? "cursor-pointer border-t border-ink-100 hover:bg-ink-50"
            : "border-t border-ink-100"
        }
        onClick={showExpand ? onToggle : undefined}
        data-testid={`audit-row-${record.id}`}
      >
        <td className="py-1 pr-3 font-mono text-xs text-ink-700">
          {record.timestamp}
        </td>
        <td className="py-1 pr-3 text-xs">{record.event_type}</td>
        <td className="py-1 pr-3 font-mono text-xs text-ink-700">
          {record.api_key_id || "—"}
        </td>
        <td className="py-1 pr-3 font-mono text-xs text-ink-700">
          {record.actor_address || "—"}
        </td>
        <td className="py-1 pr-3 font-mono text-xs text-ink-700">
          {record.signer_address ? shorten(record.signer_address) : "—"}
        </td>
        <td className="py-1 pr-3 font-mono text-xs text-ink-700">
          {record.chain_id ?? "—"}
        </td>
        <td className="py-1 pr-3">
          <Badge tone={auditSeverityTone(record.severity)}>
            {record.severity}
          </Badge>
        </td>
        {showExpand && (
          <td className="py-1 text-right text-[11px] text-ink-400">
            {expanded ? "▾" : "▸"}
          </td>
        )}
      </tr>
      {expanded && (
        <tr className="border-t border-ink-100 bg-ink-50">
          <td colSpan={showExpand ? 8 : 7} className="px-3 py-2 text-xs">
            <AuditRecordDetail record={record} />
          </td>
        </tr>
      )}
    </>
  );
}

/** Full-field detail block for a single audit record. */
export function AuditRecordDetail({ record }: { record: AuditRecord }) {
  const detailsText = formatAuditDetails(record.details);

  return (
    <dl className="grid gap-2 sm:grid-cols-2">
      {record.sign_request_id && (
        <DetailItem label="Sign request">
          <Link
            to={`/requests/${record.sign_request_id}`}
            className="font-mono text-accent-600 hover:text-accent-500"
          >
            {shorten(record.sign_request_id, 8, 6)}
          </Link>
        </DetailItem>
      )}
      {record.rule_id && (
        <DetailItem label="Rule">
          <span className="font-mono text-xs">{record.rule_id}</span>
        </DetailItem>
      )}
      {(record.request_method || record.request_path) && (
        <DetailItem label="HTTP">
          <span className="font-mono">
            {[record.request_method, record.request_path]
              .filter(Boolean)
              .join(" ")}
          </span>
        </DetailItem>
      )}
      {record.chain_type && (
        <DetailItem label="Chain type">
          <span className="font-mono">{record.chain_type}</span>
        </DetailItem>
      )}
      {record.error_message && (
        <DetailItem label="Message" className="sm:col-span-2">
          <span className="break-all text-ink-800">{record.error_message}</span>
        </DetailItem>
      )}
      {detailsText && (
        <DetailItem label="Details" className="sm:col-span-2">
          <pre className="max-h-40 overflow-auto rounded border border-ink-200 bg-white p-2 font-mono text-[11px] text-ink-800">
            {detailsText}
          </pre>
        </DetailItem>
      )}
    </dl>
  );
}

function DetailItem({
  label,
  children,
  className = "",
}: {
  label: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={className}>
      <dt className="text-[10px] uppercase tracking-wide text-ink-500">
        {label}
      </dt>
      <dd className="mt-0.5 text-ink-900">{children}</dd>
    </div>
  );
}

/** Read-only audit timeline table (newest first). */
export function AuditTimelineTable({
  records,
  expandable = true,
}: {
  records: AuditRecord[];
  expandable?: boolean;
}) {
  const [expandedId, setExpandedId] = useState<string | null>(null);

  if (records.length === 0) {
    return (
      <p className="text-sm text-ink-500">No audit events for this scope.</p>
    );
  }

  return (
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
          {expandable && <th className="py-1 font-normal text-right" />}
        </tr>
      </thead>
      <tbody>
        {records.map((r) => (
          <AuditRecordRow
            key={r.id}
            record={r}
            showExpand={expandable}
            expanded={expandable && expandedId === r.id}
            onToggle={() =>
              setExpandedId((cur) => (cur === r.id ? null : r.id))
            }
          />
        ))}
      </tbody>
    </table>
  );
}
