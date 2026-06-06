import { Link } from "react-router-dom";
import { useEffect, useState } from "react";
import { APIError, type RequestSimulation } from "remote-signer-client";
import { Card } from "./ui";
import { SimulationDetail } from "./SimulationDetail";
import { getClient } from "../lib/auth";

/**
 * SimulationPreview renders the daemon's simulation snapshot for a
 * pending sign request.
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
        if (err instanceof APIError && err.statusCode === 404) {
          setError(null);
          setNotFound(true);
          setPending(polling);
        } else {
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
        <div className="flex items-center gap-3 text-[11px] text-ink-500">
          <Link
            to={`/simulate?request_id=${requestID}`}
            className="text-accent-600 hover:underline"
          >
            Simulate again
          </Link>
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

      {data && (
        <SimulationDetail
          data={{
            success: data.success,
            gas_used: data.gas_used,
            decision: data.decision,
            reason: data.reason,
            chain_id: data.chain_id,
            sign_request_id: data.sign_request_id,
            revert_reason: data.revert_reason,
            balance_changes: data.balance_changes,
            events: parseJsonField(data.events),
            decoded_calldata: data.decoded_calldata,
            contracts: data.contracts,
            raw_result: data.raw_result,
            simulated_at: data.simulated_at,
            updated_at: data.updated_at,
          }}
          showRaw
        />
      )}
    </Card>
  );
}

function parseJsonField(value: unknown): unknown {
  if (typeof value === "string") {
    try {
      return JSON.parse(value);
    } catch {
      return value;
    }
  }
  return value;
}

function secondsSince(ts: number): number {
  return Math.max(0, Math.floor((Date.now() - ts) / 1000));
}
