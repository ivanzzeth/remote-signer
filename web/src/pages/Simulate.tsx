import { useState } from "react";
import { APIError, type SimulateResponse } from "remote-signer-client";
import {
  Badge,
  Card,
  Empty,
  ErrorBanner,
  Loading,
  PageHeader,
} from "../components/ui";
import { getClient } from "../lib/auth";
import { useCanSignOrSimulate } from "../lib/rbac";
import { useApi } from "../lib/useApi";

/**
 * Standalone transaction simulation sandbox (POST /api/v1/evm/simulate).
 * Complements the per-request simulation preview on Request detail.
 */
export function Simulate() {
  const allowed = useCanSignOrSimulate();
  const statusApi = useApi((c) => c.evm.simulate.status(), []);
  const [chainID, setChainID] = useState("1");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [value, setValue] = useState("0");
  const [data, setData] = useState("0x");
  const [gas, setGas] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<SimulateResponse | null>(null);

  async function runSim() {
    const client = getClient();
    if (!client) return;
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const resp = await client.evm.simulate.simulate({
        chain_id: chainID.trim(),
        from: from.trim(),
        to: to.trim(),
        value: value.trim() || "0",
        data: data.trim() || "0x",
        ...(gas.trim() ? { gas: gas.trim() } : {}),
      });
      setResult(resp);
    } catch (e) {
      setError(formatErr(e));
    } finally {
      setBusy(false);
    }
  }

  if (!allowed) {
    return (
      <div className="space-y-4">
        <PageHeader title="Simulate" subtitle="Transaction simulation sandbox." />
        <ErrorBanner msg="Your API key role cannot run simulations." />
      </div>
    );
  }

  const inputCls =
    "w-full rounded-md border border-ink-300 px-2 py-1 font-mono text-sm text-ink-900";

  return (
    <div className="space-y-6" data-testid="simulate-page">
      <PageHeader
        title="Simulate"
        subtitle="Dry-run a transaction through the daemon's simulation engine before signing."
      />

      {statusApi.loading && <Loading />}
      {statusApi.data && (
        <Card title="Engine status">
          <dl className="grid gap-2 text-sm sm:grid-cols-2">
            <Row k="Enabled" v={String(statusApi.data.enabled)} />
            <Row k="Engine" v={statusApi.data.engine_version || "—"} mono />
            <Row
              k="Chains"
              v={Object.keys(statusApi.data.chains || {}).join(", ") || "—"}
              mono
            />
          </dl>
        </Card>
      )}

      <Card title="Transaction">
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          <LabelInput label="Chain ID" value={chainID} onChange={setChainID} />
          <LabelInput label="From" value={from} onChange={setFrom} mono />
          <LabelInput label="To" value={to} onChange={setTo} mono />
          <LabelInput label="Value (wei)" value={value} onChange={setValue} mono />
          <LabelInput label="Gas (optional)" value={gas} onChange={setGas} mono />
          <div className="md:col-span-2">
            <label className="mb-1 block text-[11px] uppercase tracking-wide text-ink-500">
              Calldata
            </label>
            <textarea
              value={data}
              onChange={(e) => setData(e.target.value)}
              rows={3}
              className={inputCls}
            />
          </div>
        </div>
        <div className="mt-4 flex gap-2">
          <button
            type="button"
            onClick={runSim}
            disabled={busy || !from.trim() || !to.trim()}
            className="rounded-md bg-accent-500 px-4 py-1.5 text-sm font-medium text-white hover:bg-accent-600 disabled:opacity-50"
          >
            {busy ? "Simulating…" : "Simulate"}
          </button>
        </div>
      </Card>

      {error && <ErrorBanner msg={error} />}

      {result && (
        <Card title="Result">
          <dl className="mb-4 grid gap-2 text-sm sm:grid-cols-3">
            <Row
              k="Success"
              v={
                <Badge tone={result.success ? "green" : "red"}>
                  {result.success ? "yes" : "no"}
                </Badge>
              }
            />
            <Row k="Gas used" v={String(result.gas_used)} mono />
            <Row
              k="Approval detected"
              v={result.has_approval ? "yes" : "no"}
            />
          </dl>
          {result.revert_reason && (
            <p className="mb-3 text-sm text-red-700">{result.revert_reason}</p>
          )}
          {result.balance_changes.length === 0 && result.events.length === 0 ? (
            <Empty msg="No balance changes or events decoded." />
          ) : (
            <div className="space-y-4 text-sm">
              {result.balance_changes.length > 0 && (
                <section>
                  <h4 className="mb-2 text-[11px] uppercase text-ink-500">
                    Balance changes
                  </h4>
                  <ul className="space-y-1 font-mono text-xs">
                    {result.balance_changes.map((c, i) => (
                      <li key={i}>
                        {c.direction} {c.amount} {c.standard || c.token}
                      </li>
                    ))}
                  </ul>
                </section>
              )}
              {result.events.length > 0 && (
                <section>
                  <h4 className="mb-2 text-[11px] uppercase text-ink-500">
                    Events
                  </h4>
                  <ul className="space-y-1 font-mono text-xs">
                    {result.events.map((ev, i) => (
                      <li key={i}>
                        {ev.standard}.{ev.event} @ {ev.address}
                      </li>
                    ))}
                  </ul>
                </section>
              )}
            </div>
          )}
        </Card>
      )}
    </div>
  );
}

function LabelInput({
  label,
  value,
  onChange,
  mono,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  mono?: boolean;
}) {
  return (
    <div>
      <label className="mb-1 block text-[11px] uppercase tracking-wide text-ink-500">
        {label}
      </label>
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className={`w-full rounded-md border border-ink-300 px-2 py-1 text-sm text-ink-900 ${mono ? "font-mono" : ""}`}
      />
    </div>
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
    <div>
      <dt className="text-[11px] uppercase text-ink-500">{k}</dt>
      <dd className={`mt-0.5 text-ink-900 ${mono ? "font-mono text-xs" : ""}`}>
        {v}
      </dd>
    </div>
  );
}

function formatErr(e: unknown): string {
  if (e instanceof APIError) return `HTTP ${e.statusCode}: ${e.message}`;
  if (e instanceof Error) return e.message;
  return String(e);
}
