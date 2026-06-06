import { useCallback, useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import {
  APIError,
  type ListSimulationsResponse,
  type SimulateResponse,
  type SimulationHistoryItem,
} from "remote-signer-client";
import { SimulationDetail } from "../components/SimulationDetail";
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
import { prefillFromRequest } from "../lib/simulatePrefill";
import { useApi } from "../lib/useApi";

type Tab = "simulate" | "history";

export function Simulate() {
  const allowed = useCanSignOrSimulate();
  const [searchParams] = useSearchParams();
  const [tab, setTab] = useState<Tab>("simulate");
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

  const [histDecision, setHistDecision] = useState("");
  const [histSuccess, setHistSuccess] = useState("");
  const [histChain, setHistChain] = useState("");
  const [histLoading, setHistLoading] = useState(false);
  const [histError, setHistError] = useState<string | null>(null);
  const [histData, setHistData] = useState<ListSimulationsResponse | null>(
    null,
  );
  const [selectedHist, setSelectedHist] =
    useState<SimulationHistoryItem | null>(null);

  const requestPrefill = searchParams.get("request_id");
  const [prefillLoading, setPrefillLoading] = useState(false);
  const [prefillError, setPrefillError] = useState<string | null>(null);
  const [prefillDone, setPrefillDone] = useState(false);

  useEffect(() => {
    if (!requestPrefill) {
      setPrefillLoading(false);
      setPrefillError(null);
      setPrefillDone(false);
      return;
    }

    const requestID = requestPrefill;
    let cancelled = false;
    setTab("simulate");
    setPrefillLoading(true);
    setPrefillError(null);
    setPrefillDone(false);

    async function loadPrefill() {
      const client = getClient();
      if (!client) return;
      try {
        const req = await client.evm.requests.get(requestID);
        if (cancelled) return;

        let decoded: unknown;
        try {
          const sim = await client.evm.requests.getSimulation(requestID);
          decoded = sim.decoded_calldata;
        } catch {
          decoded = undefined;
        }

        const fields = prefillFromRequest(req, decoded);
        if (!fields) {
          setPrefillError(
            req.sign_type !== "transaction"
              ? "Only transaction requests can be replayed here."
              : "Could not extract transaction fields from this request.",
          );
          return;
        }

        setChainID(fields.chainID);
        setFrom(fields.from);
        setTo(fields.to);
        setValue(fields.value);
        setData(fields.data);
        setGas(fields.gas);
        setPrefillDone(true);
      } catch (e) {
        if (!cancelled) {
          setPrefillError(formatErr(e));
        }
      } finally {
        if (!cancelled) {
          setPrefillLoading(false);
        }
      }
    }

    void loadPrefill();
    return () => {
      cancelled = true;
    };
  }, [requestPrefill]);

  const loadHistory = useCallback(
    async (cursor?: string, cursorId?: string) => {
      const client = getClient();
      if (!client) return;
      setHistLoading(true);
      setHistError(null);
      try {
        const resp = await client.evm.simulate.list({
          decision: histDecision || undefined,
          chain_id: histChain || undefined,
          success:
            histSuccess === ""
              ? undefined
              : histSuccess === "true",
          limit: 25,
          cursor,
          cursor_id: cursorId,
        });
        setHistData((prev: ListSimulationsResponse | null) =>
          cursor && prev
            ? {
                ...resp,
                simulations: [...prev.simulations, ...resp.simulations],
              }
            : resp,
        );
      } catch (e) {
        setHistError(formatErr(e));
      } finally {
        setHistLoading(false);
      }
    },
    [histDecision, histSuccess, histChain],
  );

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
        <PageHeader
          title="Simulations"
          subtitle="Your API key role cannot run simulations."
        />
        <ErrorBanner msg="Your API key role cannot run simulations." />
      </div>
    );
  }

  const inputCls =
    "w-full rounded-md border border-ink-300 px-2 py-1 font-mono text-sm text-ink-900";

  return (
    <div className="space-y-6" data-testid="simulate-page">
      <PageHeader
        title="Simulations"
        subtitle="Dry-run transactions and browse persisted simulation history."
        actions={
          <div className="flex rounded-md border border-ink-200 p-0.5 text-sm">
            <TabButton
              active={tab === "simulate"}
              onClick={() => setTab("simulate")}
              testId="simulations-tab-simulate"
            >
              Simulate
            </TabButton>
            <TabButton
              active={tab === "history"}
              onClick={() => {
                setTab("history");
                void loadHistory();
              }}
              testId="simulations-tab-history"
            >
              History
            </TabButton>
          </div>
        }
      />

      {requestPrefill && tab === "simulate" && (
        <div
          className={`rounded-md border px-3 py-2 text-sm ${
            prefillError
              ? "border-red-200 bg-red-50 text-red-900"
              : "border-accent-200 bg-accent-50 text-accent-900"
          }`}
        >
          {prefillLoading && "Loading transaction fields from request…"}
          {!prefillLoading && prefillError && (
            <>
              Prefill failed for request{" "}
              <Link
                to={`/requests/${requestPrefill}`}
                className="font-mono underline"
              >
                {requestPrefill}
              </Link>
              : {prefillError}
            </>
          )}
          {!prefillLoading && !prefillError && prefillDone && (
            <>
              Prefilled from request{" "}
              <Link
                to={`/requests/${requestPrefill}`}
                className="font-mono underline"
              >
                {requestPrefill}
              </Link>
              . Review the form and run Simulate.
            </>
          )}
        </div>
      )}

      {statusApi.loading && <Loading />}
      {statusApi.data && (
        <Card title="Engine status">
          <dl className="grid gap-2 text-sm sm:grid-cols-2">
            <StatRow k="Enabled" v={String(statusApi.data.enabled)} />
            <StatRow k="Engine" v={statusApi.data.engine_version || "—"} mono />
            <StatRow
              k="Chains"
              v={Object.keys(statusApi.data.chains || {}).join(", ") || "—"}
              mono
            />
          </dl>
        </Card>
      )}

      {tab === "simulate" && (
        <>
          <Card title="Transaction">
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
              <LabelInput label="Chain ID" value={chainID} onChange={setChainID} />
              <LabelInput label="From" value={from} onChange={setFrom} mono />
              <LabelInput label="To" value={to} onChange={setTo} mono />
              <LabelInput
                label="Value (wei)"
                value={value}
                onChange={setValue}
                mono
              />
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
                data-testid="simulations-run-button"
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
              <SimulationDetail data={result} showRaw />
            </Card>
          )}
        </>
      )}

      {tab === "history" && (
        <>
          <Card title="Filters">
            <div className="flex flex-wrap gap-3 text-sm">
              <FilterSelect
                label="Decision"
                value={histDecision}
                onChange={setHistDecision}
                options={[
                  ["", "any"],
                  ["deny", "deny"],
                  ["allow", "allow"],
                  ["no_match", "no_match"],
                ]}
              />
              <FilterSelect
                label="Success"
                value={histSuccess}
                onChange={setHistSuccess}
                options={[
                  ["", "any"],
                  ["false", "failed"],
                  ["true", "ok"],
                ]}
              />
              <LabelInput
                label="Chain ID"
                value={histChain}
                onChange={setHistChain}
              />
              <div className="flex items-end">
                <button
                  type="button"
                  onClick={() => void loadHistory()}
                  disabled={histLoading}
                  className="rounded-md border border-ink-300 px-3 py-1.5 text-sm hover:bg-ink-50 disabled:opacity-50"
                >
                  {histLoading ? "Loading…" : "Refresh"}
                </button>
              </div>
            </div>
          </Card>

          {histError && <ErrorBanner msg={histError} />}

          <Card title="Simulation history">
            {!histData && histLoading && <Loading />}
            {histData && histData.simulations.length === 0 && (
              <Empty msg="No simulation snapshots yet." />
            )}
            {histData && histData.simulations.length > 0 && (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead>
                    <tr className="border-b border-ink-200 text-[11px] uppercase text-ink-500">
                      <th className="py-2 pr-3">Updated</th>
                      <th className="py-2 pr-3">Request</th>
                      <th className="py-2 pr-3">Chain</th>
                      <th className="py-2 pr-3">Outcome</th>
                      <th className="py-2 pr-3">Revert</th>
                    </tr>
                  </thead>
                  <tbody>
                    {histData.simulations.map((row: SimulationHistoryItem) => (
                      <tr
                        key={row.sign_request_id}
                        className="cursor-pointer border-b border-ink-100 hover:bg-ink-50"
                        onClick={() => setSelectedHist(row)}
                      >
                        <td className="py-2 pr-3 font-mono text-xs">
                          {formatTime(row.updated_at)}
                        </td>
                        <td className="py-2 pr-3">
                          <Link
                            to={`/requests/${row.sign_request_id}`}
                            className="font-mono text-xs text-accent-600 hover:underline"
                            onClick={(e) => e.stopPropagation()}
                          >
                            {row.sign_request_id.slice(0, 8)}…
                          </Link>
                        </td>
                        <td className="py-2 pr-3 font-mono text-xs">
                          {row.chain_id}
                        </td>
                        <td className="py-2 pr-3">
                          <Badge tone={row.success ? "green" : "red"}>
                            {row.decision}
                          </Badge>
                        </td>
                        <td className="max-w-xs truncate py-2 pr-3 text-xs text-red-700">
                          {row.revert_reason || "—"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {histData?.has_more && (
              <div className="mt-3">
                <button
                  type="button"
                  disabled={histLoading}
                  onClick={() =>
                    void loadHistory(histData.next_cursor, histData.next_cursor_id)
                  }
                  className="text-sm text-accent-600 hover:underline disabled:opacity-50"
                >
                  Load more
                </button>
              </div>
            )}
          </Card>

          {selectedHist && (
            <Card
              title="History row"
              actions={
                <button
                  type="button"
                  className="text-xs text-ink-500 hover:text-ink-800"
                  onClick={() => setSelectedHist(null)}
                >
                  Close
                </button>
              }
            >
              <SimulationDetail
                data={{
                  success: selectedHist.success,
                  gas_used: selectedHist.gas_used,
                  decision: selectedHist.decision,
                  reason: selectedHist.reason,
                  chain_id: selectedHist.chain_id,
                  sign_request_id: selectedHist.sign_request_id,
                  revert_reason: selectedHist.revert_reason,
                  simulated_at: selectedHist.simulated_at,
                  updated_at: selectedHist.updated_at,
                }}
              />
              <p className="mt-3 text-xs text-ink-500">
                <Link
                  to={`/simulate?request_id=${selectedHist.sign_request_id}`}
                  className="text-accent-600 hover:underline"
                >
                  Simulate again
                </Link>
                {" · "}
                <Link
                  to={`/requests/${selectedHist.sign_request_id}`}
                  className="text-accent-600 hover:underline"
                >
                  Request detail
                </Link>{" "}
                for full balance/events snapshot.
              </p>
            </Card>
          )}
        </>
      )}
    </div>
  );
}

function TabButton({
  active,
  onClick,
  children,
  testId,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
  testId?: string;
}) {
  return (
    <button
      type="button"
      data-testid={testId}
      onClick={onClick}
      className={`rounded px-3 py-1 ${active ? "bg-white shadow-sm" : "text-ink-500"}`}
    >
      {children}
    </button>
  );
}

function FilterSelect({
  label,
  value,
  onChange,
  options,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: [string, string][];
}) {
  return (
    <div>
      <label className="mb-1 block text-[11px] uppercase tracking-wide text-ink-500">
        {label}
      </label>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="rounded-md border border-ink-300 px-2 py-1 text-sm"
      >
        {options.map(([v, l]) => (
          <option key={v} value={v}>
            {l}
          </option>
        ))}
      </select>
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

function StatRow({
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

function formatTime(iso: string): string {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

function formatErr(e: unknown): string {
  if (e instanceof APIError) return `HTTP ${e.statusCode}: ${e.message}`;
  if (e instanceof Error) return e.message;
  return String(e);
}
