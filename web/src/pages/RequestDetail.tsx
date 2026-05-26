import { useState, type ReactNode } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  APIError,
  type RequestStatus,
  type RequestStatusResponse,
} from "remote-signer-client";
import { Badge, Card, CodeBlock, ErrorBanner, Loading, shorten } from "../components/ui";
import { SimulationPreview } from "../components/SimulationPreview";
import { getClient } from "../lib/auth";
import { useApi } from "../lib/useApi";

/**
 * Request detail view. Pulls the daemon's authoritative
 * GET /api/v1/evm/requests/{id} response which (unlike list rows)
 * includes the raw chain payload, so we can decode + present a
 * transaction the way an operator wants to read one before signing.
 *
 * Non-transaction sign types (personal, typed_data, hash) are rendered
 * as pretty-printed JSON — the universe of shapes is small enough that
 * a JSON code block beats a half-decoded form that lies for some of
 * them.
 */
export function RequestDetail() {
  const { id = "" } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [mutationError, setMutationError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const { data, loading, error, reload } = useApi(
    (c) => c.evm.requests.get(id),
    [id],
  );

  async function approve() {
    const client = getClient();
    if (!client) return;
    setBusy(true);
    setMutationError(null);
    try {
      await client.evm.requests.approve(id, { approved: true });
      reload();
    } catch (e) {
      setMutationError(formatErr(e));
    } finally {
      setBusy(false);
    }
  }

  async function reject() {
    if (!confirm("Reject this request? It cannot be re-approved later.")) return;
    const client = getClient();
    if (!client) return;
    setBusy(true);
    setMutationError(null);
    try {
      await client.evm.requests.approve(id, { approved: false });
      reload();
    } catch (e) {
      setMutationError(formatErr(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6 pb-24">
      <div className="flex items-center justify-between">
        <Link
          to="/requests"
          className="text-xs text-accent-600 hover:text-accent-500"
        >
          ← all requests
        </Link>
        <button
          type="button"
          onClick={reload}
          className="rounded-md border border-ink-200 px-3 py-1 text-xs text-ink-700 hover:bg-ink-100"
        >
          Refresh
        </button>
      </div>

      {loading && <Loading />}
      {error && <ErrorBanner msg={error} />}
      {mutationError && <ErrorBanner msg={mutationError} />}

      {data && (
        <>
          <Hero req={data} />

          <Card title="Request">
            <FieldGrid>
              <Field label="Request ID">
                <Mono>{data.id}</Mono>
              </Field>
              <Field label="Sign type">{data.sign_type}</Field>
              <Field label="Chain">
                <Mono>{`${data.chain_type} / ${data.chain_id}`}</Mono>
              </Field>
              <Field label="API key">
                <Mono>{data.api_key_id}</Mono>
              </Field>
              {data.client_ip && (
                <Field label="Client IP">
                  <Mono>{data.client_ip}</Mono>
                </Field>
              )}
              <Field label="Created">
                <Mono>{data.created_at}</Mono>
              </Field>
              <Field label="Updated">
                <Mono>{data.updated_at}</Mono>
              </Field>
              {data.completed_at && (
                <Field label="Completed">
                  <Mono>{data.completed_at}</Mono>
                </Field>
              )}
            </FieldGrid>
          </Card>

          <Card title={payloadCardTitle(data)}>
            <PayloadView req={data} />
          </Card>

          {/* Simulation preview: only for transaction-shaped requests
              and only while there's any chance the snapshot is fresh
              (pending = simulation in flight; terminal states show
              the last snapshot once and stop polling). */}
          {data.sign_type === "transaction" && (
            <SimulationPreview requestID={data.id} requestStatus={data.status} />
          )}

          {hasOutcome(data) && (
            <Card title="Outcome">
              <OutcomeView req={data} />
            </Card>
          )}
        </>
      )}

      {data && (data.status === "pending" || data.status === "authorizing") && (
        <ActionBar
          busy={busy}
          onApprove={approve}
          onReject={reject}
          onCancel={() => navigate("/requests")}
        />
      )}
    </div>
  );
}

// --- Hero ------------------------------------------------------------

function Hero({ req }: { req: RequestStatusResponse }) {
  return (
    <section className="rounded-lg border border-ink-200 bg-white p-6">
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="text-[11px] uppercase tracking-wider text-ink-500">
            Signer
          </div>
          <div className="mt-1 break-all font-mono text-base text-ink-900">
            {req.signer_address}
          </div>
        </div>
        <Badge tone={statusTone(req.status)}>{req.status}</Badge>
      </div>
      <div className="mt-4 flex flex-wrap gap-x-6 gap-y-1 text-xs text-ink-500">
        <span>
          <span className="text-ink-400">Sign type</span>{" "}
          <span className="text-ink-700">{req.sign_type}</span>
        </span>
        <span>
          <span className="text-ink-400">Chain</span>{" "}
          <span className="font-mono text-ink-700">
            {req.chain_type}/{req.chain_id}
          </span>
        </span>
        <span>
          <span className="text-ink-400">When</span>{" "}
          <span className="font-mono text-ink-700">{req.created_at}</span>
        </span>
      </div>
    </section>
  );
}

// --- Field primitives ------------------------------------------------

function FieldGrid({ children }: { children: ReactNode }) {
  return (
    <dl className="divide-y divide-ink-100 text-sm">{children}</dl>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[140px_1fr] gap-4 py-2">
      <dt className="text-ink-500">{label}</dt>
      <dd className="min-w-0 break-all text-ink-900">{children}</dd>
    </div>
  );
}

function Mono({ children }: { children: ReactNode }) {
  return (
    <span className="font-mono text-xs tabular-nums text-ink-900">
      {children}
    </span>
  );
}

// --- Payload rendering ----------------------------------------------

function payloadCardTitle(req: RequestStatusResponse): string {
  if (req.sign_type === "transaction") return "Transaction";
  if (req.sign_type === "personal" || req.sign_type === "eip191")
    return "Message";
  if (req.sign_type === "typed_data") return "Typed data (EIP-712)";
  return "Payload";
}

function PayloadView({ req }: { req: RequestStatusResponse }) {
  if (!req.payload) {
    return <p className="text-sm text-ink-500">(payload not available)</p>;
  }
  if (req.sign_type === "transaction") {
    const tx = (req.payload as { transaction?: TxPayload }).transaction;
    if (tx) return <TransactionView tx={tx} />;
  }
  return <JsonBlock value={req.payload} />;
}

interface TxPayload {
  to?: string;
  value?: string;
  data?: string;
  nonce?: number;
  gas?: number | string;
  gasPrice?: string;
  gasTipCap?: string;
  gasFeeCap?: string;
  txType?: string;
}

function TransactionView({ tx }: { tx: TxPayload }) {
  const data = tx.data && tx.data !== "0x" ? tx.data : null;
  const value = formatValueParts(tx.value);
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        <Highlight label="Sending">
          <span className="text-lg font-semibold text-ink-900">
            {value.eth}
          </span>
          <span className="ml-1 text-sm text-ink-500">ETH</span>
          {value.wei !== value.eth && (
            <div className="mt-0.5 font-mono text-[11px] text-ink-500">
              {value.wei} wei
            </div>
          )}
        </Highlight>
        <Highlight label="To">
          {tx.to ? (
            <div className="break-all font-mono text-sm text-ink-900">
              {tx.to}
            </div>
          ) : (
            <div className="italic text-ink-500">contract creation</div>
          )}
        </Highlight>
      </div>

      <FieldGrid>
        <Field label="Type">
          <span className="rounded-md bg-ink-100 px-1.5 py-0.5 font-mono text-[11px] uppercase text-ink-700">
            {tx.txType || "legacy"}
          </span>
        </Field>
        {tx.nonce !== undefined && (
          <Field label="Nonce">
            <Mono>{String(tx.nonce)}</Mono>
          </Field>
        )}
        {tx.gas !== undefined && (
          <Field label="Gas limit">
            <Mono>{Number(tx.gas).toLocaleString()}</Mono>
          </Field>
        )}
        {tx.gasPrice && (
          <Field label="Gas price">
            <Mono>{formatGwei(tx.gasPrice)}</Mono>
          </Field>
        )}
        {tx.gasTipCap && (
          <Field label="Max priority fee">
            <Mono>{formatGwei(tx.gasTipCap)}</Mono>
          </Field>
        )}
        {tx.gasFeeCap && (
          <Field label="Max fee">
            <Mono>{formatGwei(tx.gasFeeCap)}</Mono>
          </Field>
        )}
      </FieldGrid>

      {data && (
        <div>
          <div className="mb-1 flex items-center justify-between">
            <div className="text-[11px] uppercase tracking-wider text-ink-500">
              Calldata
            </div>
            <div className="font-mono text-[11px] text-ink-500">
              {(data.length - 2) / 2} bytes
            </div>
          </div>
          <code className="block max-h-48 overflow-auto break-all rounded-md border border-ink-200 bg-ink-50 p-3 font-mono text-xs text-ink-800">
            {data}
          </code>
        </div>
      )}
    </div>
  );
}

function Highlight({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  return (
    <div className="rounded-md border border-ink-200 bg-ink-50 p-3">
      <div className="text-[11px] uppercase tracking-wider text-ink-500">
        {label}
      </div>
      <div className="mt-1">{children}</div>
    </div>
  );
}

function JsonBlock({ value }: { value: unknown }) {
  return (
    <CodeBlock
      body={JSON.stringify(value, null, 2)}
      lang="json"
      maxH={24}
      defaultOpen
    />
  );
}

// --- Outcome --------------------------------------------------------

function hasOutcome(req: RequestStatusResponse): boolean {
  return Boolean(
    req.approval_source ||
      req.rule_matched_id ||
      req.approved_by ||
      req.error_message ||
      req.signature ||
      req.signed_data,
  );
}

function OutcomeView({ req }: { req: RequestStatusResponse }) {
  return (
    <div className="space-y-3">
      <FieldGrid>
        {req.approval_source && (
          <Field label="Approved by">
            <ApprovalAttribution req={req} />
          </Field>
        )}
        {req.approved_at && (
          <Field label="Approved at">
            <Mono>{req.approved_at}</Mono>
          </Field>
        )}
      </FieldGrid>
      {req.error_message && (
        <div className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-800">
          {req.error_message}
        </div>
      )}
      {req.signature && <HexBlock label="Signature" value={req.signature} />}
      {req.signed_data && (
        <HexBlock label="Signed data" value={req.signed_data} />
      )}
    </div>
  );
}

// ApprovalAttribution renders a single clickable line that explains
// exactly who let this request through. Three shapes, one per
// approval_source value:
//
//   manual     "API key · admin"                   → /api-keys
//   rule       "Rule · NON_BURN"                   → /rules
//   simulation "Simulation budget · 0x21f4…A0B8"   → /budgets/sim:<addr>
//
// Each is a Link so operators can drill into the artifact that approved
// the spend without going through a search box.
function ApprovalAttribution({ req }: { req: RequestStatusResponse }) {
  const linkClass =
    "text-accent-600 hover:text-accent-500 hover:underline underline-offset-2";

  if (req.approval_source === "manual") {
    const id = req.approved_by || "—";
    return (
      <span className="text-sm">
        <span className="mr-1 text-ink-500">API key ·</span>
        <Link to="/api-keys" className={`font-mono ${linkClass}`}>
          {id}
        </Link>
      </span>
    );
  }

  if (req.approval_source === "rule") {
    const label = req.rule_matched_name || req.rule_matched_id || "—";
    return (
      <span className="text-sm">
        <span className="mr-1 text-ink-500">Rule ·</span>
        <Link to="/rules" className={linkClass}>
          {label}
        </Link>
        {req.rule_matched_id && req.rule_matched_name && (
          <span className="ml-2 font-mono text-[11px] text-ink-500">
            {req.rule_matched_id}
          </span>
        )}
      </span>
    );
  }

  if (req.approval_source === "simulation") {
    const addr = req.signer_address;
    // Simulation budgets are keyed by SHA256(rule_id, unit) in the
    // daemon, which the browser can't compute without knowing the
    // exact unit charged. The filter-by-signer view lands the operator
    // on the matching row (usually one per signer) so they're a click
    // away from the detail page.
    return (
      <span className="text-sm">
        <span className="mr-1 text-ink-500">Simulation budget ·</span>
        <Link
          to={`/budgets?signer=${encodeURIComponent(addr.toLowerCase())}`}
          className={`font-mono ${linkClass}`}
        >
          {shorten(addr)}
        </Link>
      </span>
    );
  }

  return <span className="text-sm text-ink-500">—</span>;
}

function HexBlock({ label, value }: { label: string; value: string }) {
  return (
    <CodeBlock
      body={value}
      lang="hex"
      maxH={12}
      defaultOpen
      title={label}
    />
  );
}

// --- Action bar -----------------------------------------------------

function ActionBar({
  busy,
  onApprove,
  onReject,
  onCancel,
}: {
  busy: boolean;
  onApprove: () => void;
  onReject: () => void;
  onCancel: () => void;
}) {
  return (
    <div className="fixed inset-x-0 bottom-0 z-10 border-t border-ink-200 bg-white/95 backdrop-blur">
      <div className="mx-auto flex max-w-5xl items-center justify-between gap-3 px-8 py-3">
        <div className="text-xs text-ink-500">
          Waiting for a decision — approve hands this off to the signer.
        </div>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={onCancel}
            className="rounded-md border border-ink-200 px-3 py-1.5 text-sm text-ink-700 hover:bg-ink-100"
          >
            Back
          </button>
          <button
            type="button"
            onClick={onReject}
            disabled={busy}
            className="rounded-md border border-red-300 px-3 py-1.5 text-sm text-red-700 hover:bg-red-50 disabled:opacity-50"
          >
            Reject
          </button>
          <button
            type="button"
            onClick={onApprove}
            disabled={busy}
            className="rounded-md bg-accent-500 px-4 py-1.5 text-sm font-medium text-white hover:bg-accent-600 disabled:opacity-50"
          >
            Approve
          </button>
        </div>
      </div>
    </div>
  );
}

// --- Formatting helpers --------------------------------------------

function formatValueParts(v: string | undefined): { eth: string; wei: string } {
  if (v === undefined || v === null) return { eth: "—", wei: "—" };
  const wei = toBigInt(v);
  if (wei === null) return { eth: v, wei: v };
  if (wei === 0n) return { eth: "0", wei: "0" };
  return { eth: formatUnits(wei, 18), wei: wei.toString() };
}

/** Wei as decimal or hex → "1 gwei". */
function formatGwei(v: string): string {
  const wei = toBigInt(v);
  if (wei === null) return v;
  return `${formatUnits(wei, 9)} gwei`;
}

function toBigInt(v: string): bigint | null {
  try {
    if (v.startsWith("0x") || v.startsWith("0X")) return BigInt(v);
    return BigInt(v);
  } catch {
    return null;
  }
}

/** Stringify a wei-scale bigint at the requested decimals, trimming trailing zeros. */
function formatUnits(value: bigint, decimals: number): string {
  const neg = value < 0n;
  const abs = neg ? -value : value;
  const divisor = 10n ** BigInt(decimals);
  const whole = abs / divisor;
  const frac = abs % divisor;
  if (frac === 0n) return (neg ? "-" : "") + whole.toString();
  const fracStr = frac.toString().padStart(decimals, "0").replace(/0+$/, "");
  return `${neg ? "-" : ""}${whole}.${fracStr}`;
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
