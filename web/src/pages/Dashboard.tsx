import { useEffect, useState } from "react";
import {
  APIError,
  type HealthResponse as SDKHealthResponse,
  type ListAuditResponse,
} from "remote-signer-client";
import { getClient, getCredentials } from "../lib/auth";

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
 * First-pass operator overview. Three signals chosen because together they
 * answer "is this daemon healthy, and is my session actually authorised?":
 *
 *   1. /health (no auth) — daemon is up
 *   2. /api/v1/audit (signed) — round-trip proves the auth pipeline works
 *   3. credential metadata — show api key id + pub key so the operator can
 *      cross-check against admin.key.pub on disk before trusting writes
 *
 * Phase 8b will replace this with real metric cards (signers / rules /
 * pending requests / recent audit events).
 */
export function Dashboard() {
  const creds = getCredentials();
  const client = getClient();
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [healthError, setHealthError] = useState<string | null>(null);

  const [audit, setAudit] = useState<ListAuditResponse | null>(null);
  const [auditError, setAuditError] = useState<string | null>(null);

  useEffect(() => {
    if (!client) return;
    let mounted = true;
    // /health is unauthenticated but RemoteSignerClient.health() signs anyway
    // so we always have one consistent call path. The daemon accepts both.
    client
      .health()
      .then((r) => {
        if (mounted) setHealth(r as HealthResponse);
      })
      .catch((err) => {
        if (mounted) setHealthError(errMessage(err));
      });
    return () => {
      mounted = false;
    };
  }, [client]);

  useEffect(() => {
    if (!client) return;
    let mounted = true;
    client.audit
      .list({ limit: 5 })
      .then((r) => {
        if (mounted) setAudit(r);
      })
      .catch((err) => {
        if (!mounted) return;
        if (err instanceof APIError) {
          setAuditError(`HTTP ${err.statusCode}: ${err.message}`);
          return;
        }
        setAuditError(errMessage(err));
      });
    return () => {
      mounted = false;
    };
  }, [client]);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-ink-900">Dashboard</h1>
        <p className="text-sm text-ink-500">
          Liveness + recent activity for this remote-signer instance.
        </p>
      </div>

      <section className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <Card title="Daemon">
          {health ? (
            <dl className="space-y-1 text-sm">
              <Row k="Status" v={health.status} mono />
              <Row k="Version" v={health.version} mono />
              {health.security?.sign_timeout && (
                <Row k="Sign timeout" v={health.security.sign_timeout} mono />
              )}
            </dl>
          ) : healthError ? (
            <Error msg={healthError} />
          ) : (
            <Loading />
          )}
        </Card>

        <Card title="This session">
          {creds ? (
            <dl className="space-y-1 text-sm">
              <Row k="API key id" v={creds.apiKeyID} mono />
              <Row k="Public key" v={shorten(creds.publicKeyHex)} mono />
            </dl>
          ) : (
            <Error msg="not signed in" />
          )}
        </Card>
      </section>

      <Card title="Recent audit events">
        {audit ? (
          audit.records.length === 0 ? (
            <p className="text-sm text-ink-500">No events yet.</p>
          ) : (
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase text-ink-500">
                <tr>
                  <th className="py-1 pr-3 font-normal">When</th>
                  <th className="py-1 pr-3 font-normal">Event</th>
                  <th className="py-1 pr-3 font-normal">Actor</th>
                  <th className="py-1 font-normal">Severity</th>
                </tr>
              </thead>
              <tbody>
                {audit.records.map((r) => (
                  <tr key={r.id} className="border-t border-ink-100">
                    <td className="py-1 pr-3 font-mono text-xs text-ink-700">
                      {r.timestamp}
                    </td>
                    <td className="py-1 pr-3">{r.event_type}</td>
                    <td className="py-1 pr-3 font-mono text-xs text-ink-700">
                      {r.api_key_id || "—"}
                    </td>
                    <td className="py-1">{r.severity}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )
        ) : auditError ? (
          <Error msg={auditError} />
        ) : (
          <Loading />
        )}
      </Card>
    </div>
  );
}

function Card({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="rounded-lg border border-ink-200 bg-white p-5">
      <h2 className="mb-3 text-sm font-semibold text-ink-700">{title}</h2>
      {children}
    </section>
  );
}

function Row({ k, v, mono }: { k: string; v: string; mono?: boolean }) {
  return (
    <div className="flex justify-between gap-3">
      <dt className="text-ink-500">{k}</dt>
      <dd className={mono ? "font-mono text-xs text-ink-900" : "text-ink-900"}>
        {v}
      </dd>
    </div>
  );
}

function Loading() {
  return <div className="text-sm text-ink-500">Loading…</div>;
}

function Error({ msg }: { msg: string }) {
  return (
    <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-800">
      {msg}
    </div>
  );
}

function shorten(hex: string): string {
  if (hex.length <= 18) return hex;
  return `${hex.slice(0, 10)}…${hex.slice(-6)}`;
}

function errMessage(err: unknown): string {
  if (err instanceof Error) {
    return (err as Error).message;
  }
  if (typeof err === "string") return err;
  try {
    return JSON.stringify(err);
  } catch {
    return String(err);
  }
}
