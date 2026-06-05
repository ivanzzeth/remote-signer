import { useState, type ReactNode } from "react";

/**
 * Page-level shell every list page uses. Renders the title + subtitle and
 * gives a slot on the right for actions (refresh, filters, "new …", etc.).
 */
export function PageHeader({
  title,
  subtitle,
  actions,
}: {
  title: string;
  subtitle?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="flex items-start justify-between gap-4">
      <div>
        <h1 className="text-xl font-semibold text-ink-900">{title}</h1>
        {subtitle && (
          <p className="mt-0.5 text-sm text-ink-500">{subtitle}</p>
        )}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}

export function Card({
  title,
  children,
  actions,
  ...rest
}: {
  title?: string;
  children: ReactNode;
  actions?: ReactNode;
} & React.HTMLAttributes<HTMLElement>) {
  return (
    <section
      className="rounded-lg border border-ink-200 bg-white p-5"
      {...rest}
    >
      {(title || actions) && (
        <div className="mb-3 flex items-center justify-between">
          {title && (
            <h2 className="text-sm font-semibold text-ink-700">{title}</h2>
          )}
          {actions}
        </div>
      )}
      {children}
    </section>
  );
}

export function Row({
  k,
  v,
  mono,
}: {
  k: string;
  v: ReactNode;
  mono?: boolean;
}) {
  return (
    <div className="flex justify-between gap-3">
      <dt className="text-ink-500">{k}</dt>
      <dd className={mono ? "font-mono text-xs text-ink-900" : "text-ink-900"}>
        {v}
      </dd>
    </div>
  );
}

export function Loading() {
  return <div className="text-sm text-ink-500">Loading…</div>;
}

export function ErrorBanner({ msg }: { msg: string }) {
  return (
    <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-800">
      {msg}
    </div>
  );
}

export function Empty({ msg }: { msg: string }) {
  return <p className="text-sm text-ink-500">{msg}</p>;
}

export function Badge({
  tone = "neutral",
  children,
}: {
  tone?: "neutral" | "green" | "red" | "yellow";
  children: ReactNode;
}) {
  const toneClass = {
    neutral: "bg-ink-100 text-ink-700",
    green: "bg-green-100 text-green-800",
    red: "bg-red-100 text-red-800",
    yellow: "bg-yellow-100 text-yellow-800",
  }[tone];
  return (
    <span
      className={`inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide ${toneClass}`}
    >
      {children}
    </span>
  );
}

/** Shortens a long hex/string for table display ("0x1234…abcd"). */
export function shorten(s: string, head = 10, tail = 6): string {
  if (s.length <= head + tail + 1) return s;
  return `${s.slice(0, head)}…${s.slice(-tail)}`;
}

/**
 * Collapsible code/JSON block with a copy button. Default max-h is 96
 * (384px); pass a smaller `maxH` for compact mode. Pass `defaultOpen=true`
 * to start expanded (default: collapsed).
 *
 * The collapse/expand toggle and copy button are always visible in the
 * header bar so the operator never has to scroll to find them.
 */
export function CodeBlock({
  body,
  lang = "json",
  maxH = 96,
  defaultOpen = false,
  title,
}: {
  body: string;
  lang?: string;
  maxH?: number;
  defaultOpen?: boolean;
  title?: string;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(body);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard not available — ignore */
    }
  }

  return (
    <div>
      <div className="mb-1 flex items-center justify-between gap-2 text-[10px] uppercase tracking-wider text-ink-500">
        <div className="flex items-center gap-2 truncate">
          {title && <span className="truncate">{title}</span>}
          <span className="shrink-0 font-mono">{lang}</span>
        </div>
        <div className="flex shrink-0 items-center gap-1">
          <button
            type="button"
            onClick={() => setOpen((v) => !v)}
            className="rounded px-1.5 py-0.5 text-[10px] text-ink-500 hover:bg-ink-100"
          >
            {open ? "Collapse" : "Expand"}
          </button>
          <button
            type="button"
            onClick={copy}
            className="rounded px-1.5 py-0.5 text-[10px] text-ink-500 hover:bg-ink-100"
          >
            {copied ? "Copied!" : "Copy"}
          </button>
        </div>
      </div>
      <pre
        className={`overflow-auto rounded bg-ink-50 p-2 font-mono text-[11px] leading-snug text-ink-800 ${
          open ? "" : "max-h-[" + maxH * 4 + "px]"
        }`}
        style={!open ? { maxHeight: `${maxH * 4}px` } : undefined}
      >
        {body}
      </pre>
    </div>
  );
}
