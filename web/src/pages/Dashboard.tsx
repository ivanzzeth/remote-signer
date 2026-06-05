import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  type BudgetEntry,
  type HealthResponse as SDKHealthResponse,
  type ListSignersResponse,
} from "remote-signer-client";
import { auditSeverityTone } from "../components/AuditTimeline";
import {
  Badge,
  Card,
  Empty,
  ErrorBanner,
  Loading,
  PageHeader,
  Row,
  shorten,
} from "../components/ui";
import { getClient, getCredentials } from "../lib/auth";
import { useCanApproveSigner, useCanReadAudit } from "../lib/rbac";
import { useApi } from "../lib/useApi";
import { ProgressBar, pctUsed } from "./Budgets";

const HOT_BUDGET_THRESHOLD_PCT = 50;
const HOT_BUDGET_TOP_N = 5;

// Local extension of the SDK's HealthResponse — the daemon adds a `security`
// block that the SDK type doesn't model yet (it's an operational summary,
// not part of the published health contract).
interface HealthResponse extends SDKHealthResponse {
  security?: {
    auto_lock_timeout?: string;
    sign_timeout?: string;
    audit_retention_days?: number;
    content_type_validation?: boolean;
  };
}

/**
 * Operator landing page. Combines three signals chosen because together they
 * answer "is this daemon healthy, and is my session actually authorised?":
 *
 *   1. /health — daemon is up
 *   2. /api/v1/audit (signed) — round-trip proves the auth pipeline works
 *   3. credential metadata — show api key id + pub key so the operator can
 *      cross-check against admin.key.pub on disk before trusting writes
 */
interface HotBudget {
  entry: BudgetEntry;
  pct: number;
}

export function Dashboard() {
  const creds = getCredentials();
  const health = useApi((c) => c.health() as Promise<HealthResponse>);
  const canReadAudit = useCanReadAudit();
  const canApproveSigner = useCanApproveSigner();
  const pendingRequests = useApi((c) =>
    c.evm.requests.list({ status: "pending", limit: 1 }),
  );
  const authorizingRequests = useApi((c) =>
    c.evm.requests.list({ status: "authorizing", limit: 1 }),
  );
  const pendingSigners = useApi<ListSignersResponse>(
    (c) => {
      if (!canApproveSigner) {
        return Promise.resolve({ signers: [], total: 0 });
      }
      return c.evm.signers.list({
        ownership_status: "pending_approval",
        limit: 1,
      });
    },
    [canApproveSigner],
  );
  const audit = useApi((c) =>
    c.audit.list({ limit: 8, exclude_event_type: "api_request" }),
  );

  // Single GET /api/v1/evm/budgets — surfaces both rule and simulation
  // budgets in one shot. Refreshes only on mount; /budgets has a Refresh
  // button for a live view.
  const [hotBudgets, setHotBudgets] = useState<HotBudget[] | null>(null);
  useEffect(() => {
    const client = getClient();
    if (!client) return;
    let mounted = true;
    (async () => {
      try {
        const resp = await client.evm.budgets.list();
        if (!mounted) return;
        const rows = resp.budgets.map((entry) => ({
          entry,
          pct: pctUsed(entry),
        }));
        rows.sort((a, b) => b.pct - a.pct);
        // Only show budgets at or past the threshold — silence the
        // dashboard when nothing is interesting.
        const hot = rows
          .filter((x) => x.pct >= HOT_BUDGET_THRESHOLD_PCT)
          .slice(0, HOT_BUDGET_TOP_N);
        setHotBudgets(hot);
      } catch {
        if (mounted) setHotBudgets([]);
      }
    })();
    return () => {
      mounted = false;
    };
  }, []);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Dashboard"
        subtitle="Liveness + recent activity for this remote-signer instance."
      />

      <section className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <Card title="Daemon">
          {health.loading && <Loading />}
          {health.error && <ErrorBanner msg={health.error} />}
          {health.data && (
            <dl className="space-y-1 text-sm">
              <Row k="Status" v={health.data.status} mono />
              <Row k="Version" v={health.data.version} mono />
              {health.data.security && (
                <>
                  <Row
                    k="Auto-lock"
                    v={health.data.security.auto_lock_timeout ?? "—"}
                    mono
                  />
                  <Row
                    k="Sign timeout"
                    v={health.data.security.sign_timeout ?? "—"}
                    mono
                  />
                  <Row
                    k="Audit retention"
                    v={
                      health.data.security.audit_retention_days != null
                        ? `${health.data.security.audit_retention_days} days`
                        : "—"
                    }
                    mono
                  />
                  <Row
                    k="Content-Type check"
                    v={
                      health.data.security.content_type_validation
                        ? "enabled"
                        : "disabled"
                    }
                    mono
                  />
                </>
              )}
            </dl>
          )}
        </Card>

        <Card title="This session">
          {creds ? (
            <dl className="space-y-1 text-sm">
              <Row k="API key id" v={creds.apiKeyID} mono />
              <Row k="Public key" v={shorten(creds.publicKeyHex)} mono />
            </dl>
          ) : (
            <ErrorBanner msg="not signed in" />
          )}
        </Card>
      </section>

      <Card
        title="Sign request queue"
        data-testid="dashboard-request-queue"
        actions={
          <Link
            to="/requests"
            className="text-xs text-accent-600 hover:text-accent-500"
          >
            all requests →
          </Link>
        }
      >
        <dl className="grid grid-cols-2 gap-4 text-sm sm:grid-cols-4">
          <div>
            <dt className="text-[10px] uppercase tracking-wide text-ink-500">
              Pending
            </dt>
            <dd className="mt-1 font-mono text-lg text-ink-900">
              {pendingRequests.loading
                ? "…"
                : (pendingRequests.data?.total ?? 0)}
            </dd>
          </div>
          <div>
            <dt className="text-[10px] uppercase tracking-wide text-ink-500">
              Authorizing
            </dt>
            <dd className="mt-1 font-mono text-lg text-ink-900">
              {authorizingRequests.loading
                ? "…"
                : (authorizingRequests.data?.total ?? 0)}
            </dd>
          </div>
        </dl>
        {(pendingRequests.error || authorizingRequests.error) && (
          <ErrorBanner
            msg={pendingRequests.error || authorizingRequests.error || ""}
          />
        )}
      </Card>

      {canApproveSigner && (
        <Card
          title="Signers pending approval"
          data-testid="dashboard-signer-approval-queue"
          actions={
            <Link
              to="/signers?ownership_status=pending_approval"
              className="text-xs text-accent-600 hover:text-accent-500"
            >
              review signers →
            </Link>
          }
        >
          <p className="mb-3 text-xs text-ink-600">
            Non-admin API keys create signers in{" "}
            <span className="font-mono">pending_approval</span> until an admin
            approves them here. This count is global — not limited to your
            session key.
          </p>
          <dl className="grid grid-cols-2 gap-4 text-sm sm:grid-cols-4">
            <div>
              <dt className="text-[10px] uppercase tracking-wide text-ink-500">
                Awaiting approval
              </dt>
              <dd className="mt-1 font-mono text-lg text-ink-900">
                {pendingSigners.loading
                  ? "…"
                  : (pendingSigners.data?.total ?? 0)}
              </dd>
            </div>
          </dl>
          {pendingSigners.error && <ErrorBanner msg={pendingSigners.error} />}
        </Card>
      )}

      {hotBudgets && hotBudgets.length > 0 && (
        <Card
          title={`Budgets at ≥${HOT_BUDGET_THRESHOLD_PCT}% used`}
          actions={
            <Link
              to="/budgets"
              className="text-xs text-accent-600 hover:text-accent-500"
            >
              all budgets →
            </Link>
          }
        >
          <ul className="space-y-2 text-sm">
            {hotBudgets.map(({ entry, pct }) => (
              <li
                key={entry.id}
                className="grid grid-cols-1 items-center gap-2 md:grid-cols-[1fr_8rem_4rem]"
              >
                <div>
                  <Link
                    to="/budgets"
                    className="text-ink-900 hover:text-accent-600"
                  >
                    {entry.kind === "rule"
                      ? entry.rule_name || entry.rule_id
                      : entry.signer_address
                        ? shorten(entry.signer_address)
                        : entry.rule_id}
                  </Link>
                  <span className="ml-2 font-mono text-[11px] text-ink-500">
                    {entry.kind === "simulation" ? "sim · " : ""}
                    {entry.unit}
                  </span>
                </div>
                <ProgressBar pct={pct} />
                <div className="text-right font-mono text-xs text-ink-700">
                  {pct.toFixed(0)}%
                </div>
              </li>
            ))}
          </ul>
        </Card>
      )}

      {canReadAudit && (
        <Card
          title="Recent audit events"
          actions={
            <Link
              to="/audit"
              className="text-xs text-accent-600 hover:text-accent-500"
            >
              full log →
            </Link>
          }
        >
          {audit.loading && <Loading />}
          {audit.error && <ErrorBanner msg={audit.error} />}
          {audit.data &&
            (audit.data.records.length === 0 ? (
              <Empty msg="No events yet." />
            ) : (
              <table className="w-full text-left text-sm">
                <thead className="text-xs uppercase text-ink-500">
                  <tr>
                    <th className="py-1 pr-3 font-normal">When</th>
                    <th className="py-1 pr-3 font-normal">Event</th>
                    <th className="py-1 pr-3 font-normal">API key</th>
                    <th className="py-1 pr-3 font-normal">IP</th>
                    <th className="py-1 font-normal">Severity</th>
                  </tr>
                </thead>
                <tbody>
                  {audit.data.records.map((r) => (
                    <tr key={r.id} className="border-t border-ink-100">
                      <td className="py-1 pr-3 font-mono text-xs text-ink-700">
                        {r.timestamp}
                      </td>
                      <td className="py-1 pr-3 text-xs">{r.event_type}</td>
                      <td className="py-1 pr-3 font-mono text-xs text-ink-700">
                        {r.api_key_id || "—"}
                      </td>
                      <td className="py-1 pr-3 font-mono text-xs text-ink-700">
                        {r.actor_address || "—"}
                      </td>
                      <td className="py-1">
                        <Badge tone={auditSeverityTone(r.severity)}>
                          {r.severity}
                        </Badge>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ))}
        </Card>
      )}
    </div>
  );
}
