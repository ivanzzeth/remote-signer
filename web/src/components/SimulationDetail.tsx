import { Link } from "react-router-dom";
import type { RevertDetailDTO, SimEventDTO } from "remote-signer-client";
import { Badge, Empty } from "./ui";

export type SimulationDetailInput = RevertDetailDTO & {
  success?: boolean;
  gas_used?: number;
  has_approval?: boolean;
  decision?: string;
  reason?: string;
  chain_id?: string;
  sign_request_id?: string;
  balance_changes?: unknown;
  events?: unknown;
  decoded_calldata?: unknown;
  contracts?: string[];
  raw_result?: unknown;
  simulated_at?: string;
  updated_at?: string;
};

export function SimulationDetail({
  data,
  showRaw = false,
}: {
  data: SimulationDetailInput;
  showRaw?: boolean;
}) {
  const events = normalizeEvents(data.events);
  const balanceChanges = normalizeBalanceChanges(data.balance_changes);

  return (
    <div className="space-y-4">
      <dl className="grid grid-cols-2 gap-3 text-sm sm:grid-cols-4">
        {data.decision && (
          <Field label="Decision">
            <Badge tone={decisionTone(data.decision)}>{decisionLabel(data.decision)}</Badge>
          </Field>
        )}
        {data.success !== undefined && (
          <Field label="Sim success">
            <Badge tone={data.success ? "green" : "red"}>
              {data.success ? "yes" : "no"}
            </Badge>
          </Field>
        )}
        {data.gas_used !== undefined && (
          <Field label="Gas used">
            <Mono>{data.gas_used.toLocaleString()}</Mono>
          </Field>
        )}
        {data.has_approval !== undefined && (
          <Field label="Approval">
            {data.has_approval ? "detected" : "no"}
          </Field>
        )}
        {data.chain_id && (
          <Field label="Chain">
            <Mono>{data.chain_id}</Mono>
          </Field>
        )}
      </dl>

      {data.sign_request_id && (
        <p className="text-xs text-ink-500">
          Request{" "}
          <Link
            to={`/requests/${data.sign_request_id}`}
            className="font-mono text-accent-600 hover:underline"
          >
            {data.sign_request_id}
          </Link>
        </p>
      )}

      {data.reason && (
        <div className="rounded-md border border-yellow-200 bg-yellow-50 p-2 text-xs text-yellow-900">
          {data.reason}
        </div>
      )}

      <RevertPanel data={data} />

      <DecodedCalldata value={data.decoded_calldata} />

      <BalanceChanges changes={balanceChanges} />

      <EventsList events={events} />

      <ContractsList contracts={data.contracts} />

      {(data.simulated_at || data.updated_at) && (
        <p className="text-[11px] text-ink-400">
          {data.simulated_at && <>simulated {formatTime(data.simulated_at)}</>}
          {data.simulated_at && data.updated_at && " · "}
          {data.updated_at && <>updated {formatTime(data.updated_at)}</>}
        </p>
      )}

      {showRaw && data.raw_result != null && (
        <section>
          <h4 className="mb-2 text-[11px] uppercase tracking-wide text-ink-500">
            Raw result
          </h4>
          <pre className="max-h-64 overflow-auto rounded border border-ink-200 bg-white p-2 font-mono text-[11px] text-ink-800">
            {JSON.stringify(data.raw_result, null, 2)}
          </pre>
        </section>
      )}
    </div>
  );
}

function RevertPanel({ data }: { data: RevertDetailDTO & { success?: boolean } }) {
  if (
    !data.revert_reason &&
    !data.revert_data &&
    !data.revert_signature &&
    data.success !== false
  ) {
    return null;
  }

  return (
    <section className="rounded-md border border-red-200 bg-red-50/60 p-3">
      <h4 className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-red-800">
        Revert
      </h4>
      <dl className="space-y-1 text-xs">
        {data.revert_signature && (
          <Row k="Signature" v={data.revert_signature} mono />
        )}
        {data.revert_reason && !data.revert_signature && (
          <Row k="Reason" v={data.revert_reason} />
        )}
        {data.revert_reason && data.revert_signature && (
          <Row k="Summary" v={data.revert_reason} />
        )}
        {data.revert_selector && (
          <Row k="Selector" v={data.revert_selector} mono />
        )}
        {data.revert_confidence && (
          <Row
            k="Confidence"
            v={
              <ConfidenceBadge
                confidence={data.revert_confidence}
                source={data.revert_source}
              />
            }
          />
        )}
        {data.revert_data && (
          <Row k="Raw data" v={<CopyMono value={data.revert_data} />} />
        )}
        {data.revert_candidates && data.revert_candidates.length > 1 && (
          <Row
            k="Candidates"
            v={data.revert_candidates.join(" · ")}
          />
        )}
        {data.revert_args && Object.keys(data.revert_args).length > 0 && (
          <Row
            k="Args"
            v={Object.entries(data.revert_args)
              .map(([k, v]) => `${k}=${v}`)
              .join(", ")}
            mono
          />
        )}
      </dl>
    </section>
  );
}

function BalanceChanges({
  changes,
}: {
  changes: Array<Record<string, unknown>>;
}) {
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
              <span
                className={
                  dir === "inflow" ? "text-green-700" : "text-red-700"
                }
              >
                {dir === "inflow" ? "▲" : "▼"} {amount}
              </span>
              <span className="text-ink-500">{std || token}</span>
            </li>
          );
        })}
      </ul>
    </section>
  );
}

function EventsList({ events }: { events: SimEventDTO[] }) {
  if (events.length === 0) {
    return <Empty msg="No decoded events." />;
  }

  const verified = events.filter(
    (e) => !e.confidence || e.confidence === "verified",
  );
  const inferred = events.filter((e) => e.confidence === "inferred");

  return (
    <section className="space-y-3">
      {verified.length > 0 && (
        <EventGroup title="Verified events" events={verified} />
      )}
      {inferred.length > 0 && (
        <EventGroup
          title="Inferred events (registry — may be wrong)"
          events={inferred}
          warn
        />
      )}
    </section>
  );
}

function EventGroup({
  title,
  events,
  warn,
}: {
  title: string;
  events: SimEventDTO[];
  warn?: boolean;
}) {
  return (
    <div>
      <h4
        className={`mb-2 text-[11px] uppercase tracking-wide ${warn ? "text-amber-700" : "text-ink-500"}`}
      >
        {title}
      </h4>
      <ol className="space-y-2 text-sm">
        {events.map((ev, i) => (
          <li
            key={`${ev.address}-${ev.event}-${i}`}
            className="rounded border border-ink-100 bg-ink-50/50 p-2 font-mono text-xs"
          >
            <div className="text-ink-900">
              {ev.standard}.{ev.event} @ {ev.address}
            </div>
            {ev.signature && (
              <div className="mt-0.5 text-[10px] text-ink-500">{ev.signature}</div>
            )}
            {ev.args && Object.keys(ev.args).length > 0 && (
              <div className="mt-1 text-ink-600">
                {formatArgs(ev.args)}
              </div>
            )}
            {ev.candidates && ev.candidates.length > 1 && (
              <div className="mt-1 text-[10px] text-amber-700">
                candidates: {ev.candidates.join(" | ")}
              </div>
            )}
          </li>
        ))}
      </ol>
    </div>
  );
}

function DecodedCalldata({ value }: { value: unknown }) {
  if (value == null) return null;
  const text =
    typeof value === "string" ? value : JSON.stringify(value, null, 2);
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

function ConfidenceBadge({
  confidence,
  source,
}: {
  confidence: string;
  source?: string;
}) {
  const tone =
    confidence === "verified"
      ? "green"
      : confidence === "inferred"
        ? "yellow"
        : "neutral";
  return (
    <span className="inline-flex items-center gap-1">
      <Badge tone={tone}>{confidence}</Badge>
      {source && <span className="text-ink-500">({source})</span>}
    </span>
  );
}

function CopyMono({ value }: { value: string }) {
  return (
    <button
      type="button"
      className="break-all text-left font-mono text-[11px] text-ink-800 hover:text-accent-600"
      onClick={() => void navigator.clipboard.writeText(value)}
      title="Click to copy"
    >
      {value}
    </button>
  );
}

function Row({
  k,
  v,
  mono,
}: {
  k: string;
  v: React.ReactNode;
  mono?: boolean;
}) {
  return (
    <div className="flex gap-2">
      <dt className="w-24 shrink-0 text-ink-500">{k}</dt>
      <dd className={mono ? "font-mono text-[11px] break-all" : ""}>{v}</dd>
    </div>
  );
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

function Mono({ children }: { children: React.ReactNode }) {
  return <span className="font-mono text-xs text-ink-900">{children}</span>;
}

function normalizeEvents(value: unknown): SimEventDTO[] {
  if (!Array.isArray(value)) return [];
  return value as SimEventDTO[];
}

function normalizeBalanceChanges(
  value: unknown,
): Array<Record<string, unknown>> {
  if (Array.isArray(value)) {
    return value as Array<Record<string, unknown>>;
  }
  return [];
}

function formatArgs(args: Record<string, string>): string {
  return Object.entries(args)
    .map(([k, v]) => `${k}=${truncate(String(v), 18)}`)
    .join(", ");
}

function truncate(s: string, head: number): string {
  if (s.length <= head + 6) return s;
  return s.slice(0, head) + "…" + s.slice(-4);
}

function formatTime(iso: string): string {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

function decisionLabel(decision: string): string {
  switch (decision) {
    case "allow":
      return "would auto-approve";
    case "deny":
      return "would reject";
    case "no_match":
      return "defer to manual";
    default:
      return decision;
  }
}

function decisionTone(
  decision: string,
): "green" | "yellow" | "red" | "neutral" {
  switch (decision) {
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
