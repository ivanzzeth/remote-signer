import { useEffect, useState } from "react";
import { APIError, type RequestSimulation } from "remote-signer-client";
import { Badge, Card } from "./ui";
import { getClient } from "../lib/auth";

/**
 * SimulationPreview renders the daemon's simulation snapshot for a
 * pending sign request — what the tx would actually do on-chain
 * (balance changes, decoded events, touched contracts, gas usage)
 * before the operator decides to manually approve.
 *
 * Lifecycle:
 *
 *   - `requestStatus` in {pending, authorizing}: poll every 3s. The
 *     simulation pipeline writes asynchronously, so the first poll
 *     after a fresh request often comes back 404 — render
 *     "evaluating" then keep trying.
 *   - status moves to a terminal state (signing/completed/rejected/
 *     failed): one last fetch, then stop polling. The historical
 *     snapshot stays visible so the operator can review what was
 *     simulated even after signing concluded.
 */
export function SimulationPreview({
  requestID,
  requestStatus,
}: {
  requestID: string;
  requestStatus: string;
}) {
  const [data, setData] = useState<RequestSimulation | null>(null);
  const [pending, setPending] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notFound, setNotFound] = useState(false);
  const [fetchedAt, setFetchedAt] = useState<number | null>(null);

  const polling =
    requestStatus === "pending" || requestStatus === "authorizing";

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | null = null;

    async function fetchOnce() {
      const client = getClient();
      if (!client) return;
      try {
        const sim = await client.evm.requests.getSimulation(requestID);
        if (cancelled) return;
        setData(sim);
        setPending(false);
        setError(null);
        setNotFound(false);
        setFetchedAt(Date.now());
      } catch (err) {
        if (cancelled) return;
        // 404 = "simulation not yet available". While the request
        // is still live the pipeline may yet write a row, so keep
        // the spinner. Once the request reaches a terminal state
        // with no row on disk, there will never be one — surface
        // that as a definitive "no snapshot" instead of an infinite
        // spinner (the common case for requests created before the
        // simulation-persistence code shipped).
        if (err instanceof APIError && err.statusCode === 404) {
          setError(null);
          setNotFound(true);
          setPending(polling);
        } else {
          // Any other error: stop the spinner. Showing "loading…"
          // and an error string side-by-side would just confuse
          // the operator.
          setPending(false);
          setError(err instanceof Error ? err.message : String(err));
        }
        setFetchedAt(Date.now());
      } finally {
        if (!cancelled && polling) {
          timer = setTimeout(fetchOnce, 3_000);
        }
      }
    }

    fetchOnce();
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, [requestID, polling]);

  return (
    <Card>
      <header className="mb-3 flex items-center justify-between gap-3">
        <h3 className="text-xs font-semibold uppercase tracking-wide text-ink-500">
          Simulation preview
        </h3>
        <div className="text-[11px] text-ink-500">
          {polling ? (
            <span>
              ↻ auto-refresh ·{" "}
              {fetchedAt ? `${secondsSince(fetchedAt)}s ago` : "loading…"}
            </span>
          ) : (
            <span>snapshot · run stopped</span>
          )}
        </div>
      </header>

      {error && (
        <div className="rounded-md border border-red-200 bg-red-50 p-2 text-xs text-red-800">
          {error}
        </div>
      )}

      {pending && !data && (
        <div className="flex items-center gap-2 text-sm text-ink-500">
          <span className="inline-block h-3 w-3 animate-spin rounded-full border-2 border-ink-300 border-t-accent-500" />
          Evaluating… first simulation takes a few seconds.
        </div>
      )}

      {!pending && !data && notFound && !error && (
        <div className="text-sm text-ink-500">
          No simulation recorded for this request.
        </div>
      )}

      {data && <SimDetail sim={data} />}
    </Card>
  );
}

function SimDetail({ sim }: { sim: RequestSimulation }) {
  return (
    <div className="space-y-4">
      {/* Decision row */}
      <dl className="grid grid-cols-2 gap-3 text-sm sm:grid-cols-4">
        <Field label="Decision">
          <Badge tone={decisionTone(sim)}>{decisionLabel(sim)}</Badge>
        </Field>
        <Field label="Revert?">
          {sim.success ? (
            <span className="text-green-700">No</span>
          ) : (
            <span className="text-red-700">
              Yes
              {sim.revert_reason && (
                <span className="ml-1 text-xs text-ink-500">
                  ({sim.revert_reason})
                </span>
              )}
            </span>
          )}
        </Field>
        <Field label="Gas used">
          <Mono>{sim.gas_used.toLocaleString()}</Mono>
        </Field>
        <Field label="Chain">
          <Mono>{sim.chain_id}</Mono>
        </Field>
      </dl>

      {sim.reason && (
        <div className="rounded-md border border-yellow-200 bg-yellow-50 p-2 text-xs text-yellow-900">
          {sim.reason}
        </div>
      )}

      <BalanceChanges value={sim.balance_changes} />
      <DecodedCalldata value={sim.decoded_calldata} />
      <EventsList value={sim.events} />
      <ContractsList contracts={sim.contracts} />
    </div>
  );
}

function BalanceChanges({ value }: { value: unknown }) {
  const changes = Array.isArray(value)
    ? (value as Array<Record<string, unknown>>)
    : [];
  if (changes.length === 0) return null;
  return (
    <section>
      <h4 className="mb-2 text-[11px] uppercase tracking-wide text-ink-500">
        Balance changes
      </h4>
      <ul className="space-y-1 text-sm">
        {changes.map((c, i) => {
          const dir = String(c.direction ?? "");
          const token = String(c.token ?? "native");
          const std = String(c.standard ?? "");
          const amount = String(c.amount ?? "");
          return (
            <li
              key={i}
              className="flex items-center gap-2 font-mono text-xs text-ink-800"
            >
              <span className={dir === "inflow" ? "text-green-700" : "text-red-700"}>
                {dir === "inflow" ? "🔺" : "🔻"}
                {" "}
                {amount}
              </span>
              <span className="text-ink-500">{std || token}</span>
              {std && std !== "native" && (
                <Mono className="text-[10px] text-ink-400">{token}</Mono>
              )}
            </li>
          );
        })}
      </ul>
    </section>
  );
}

function DecodedCalldata({ value }: { value: unknown }) {
  if (value == null) return null;
  const text =
    typeof value === "string"
      ? value
      : JSON.stringify(value, null, 2);
  if (!text || text === "{}" || text === "null") return null;
  return (
    <section>
      <h4 className="mb-2 text-[11px] uppercase tracking-wide text-ink-500">
        Decoded calldata
      </h4>
      <pre className="max-h-48 overflow-auto rounded border border-ink-200 bg-white p-2 font-mono text-[11px] text-ink-800">
        {text}
      </pre>
    </section>
  );
}

function EventsList({ value }: { value: unknown }) {
  const events = Array.isArray(value)
    ? (value as Array<Record<string, unknown>>)
    : [];
  if (events.length === 0) return null;
  return (
    <section>
      <h4 className="mb-2 text-[11px] uppercase tracking-wide text-ink-500">
        Events (decoded)
      </h4>
      <ol className="space-y-1 text-sm">
        {events.map((ev, i) => {
          const args = ev.args as Record<string, string> | undefined;
          return (
            <li key={i} className="font-mono text-xs text-ink-800">
              <span className="text-ink-500">{i + 1}.</span>{" "}
              <span className="text-ink-900">
                {String(ev.standard ?? "")}.{String(ev.event ?? "")}
              </span>
              {args && Object.keys(args).length > 0 && (
                <span className="ml-1 text-ink-600">
                  ({formatArgs(args)})
                </span>
              )}
            </li>
          );
        })}
      </ol>
    </section>
  );
}

function ContractsList({ contracts }: { contracts?: string[] }) {
  if (!contracts || contracts.length === 0) return null;
  return (
    <section>
      <h4 className="mb-2 text-[11px] uppercase tracking-wide text-ink-500">
        Contracts touched
      </h4>
      <ul className="space-y-0.5 text-sm">
        {contracts.map((addr) => (
          <li key={addr} className="font-mono text-xs text-ink-800">
            {addr}
          </li>
        ))}
      </ul>
    </section>
  );
}

// ── helpers ────────────────────────────────────────────────────────

function formatArgs(args: Record<string, string>): string {
  const entries = Object.entries(args);
  if (entries.length === 0) return "";
  return entries
    .map(([k, v]) => `${k}=${truncate(String(v), 14)}`)
    .join(", ");
}

function truncate(s: string, head: number): string {
  if (s.length <= head + 6) return s;
  return s.slice(0, head) + "…" + s.slice(-4);
}

function secondsSince(ts: number): number {
  return Math.max(0, Math.floor((Date.now() - ts) / 1000));
}

function decisionLabel(sim: RequestSimulation): string {
  switch (sim.decision) {
    case "allow":
      return "would auto-approve";
    case "deny":
      return "would reject";
    case "no_match":
      return "defer to manual";
    default:
      return sim.decision;
  }
}

function decisionTone(sim: RequestSimulation): "green" | "yellow" | "red" | "neutral" {
  switch (sim.decision) {
    case "allow":
      return "green";
    case "deny":
      return "red";
    case "no_match":
      return "yellow";
    default:
      return "neutral";
  }
}

function Field({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <dt className="mb-0.5 text-[10px] uppercase tracking-wide text-ink-500">
        {label}
      </dt>
      <dd>{children}</dd>
    </div>
  );
}

function Mono({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <span className={`font-mono text-xs text-ink-900 ${className ?? ""}`}>
      {children}
    </span>
  );
}
