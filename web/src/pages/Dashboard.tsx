import {
  type HealthResponse as SDKHealthResponse,
} from "remote-signer-client";
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
import { getCredentials } from "../lib/auth";
import { useApi } from "../lib/useApi";

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
export function Dashboard() {
  const creds = getCredentials();
  const health = useApi((c) => c.health() as Promise<HealthResponse>);
  const audit = useApi((c) => c.audit.list({ limit: 5 }));

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
              {health.data.security?.sign_timeout && (
                <Row
                  k="Sign timeout"
                  v={health.data.security.sign_timeout}
                  mono
                />
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

      <Card title="Recent audit events">
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
                  <th className="py-1 pr-3 font-normal">Actor</th>
                  <th className="py-1 font-normal">Severity</th>
                </tr>
              </thead>
              <tbody>
                {audit.data.records.map((r) => (
                  <tr key={r.id} className="border-t border-ink-100">
                    <td className="py-1 pr-3 font-mono text-xs text-ink-700">
                      {r.timestamp}
                    </td>
                    <td className="py-1 pr-3">{r.event_type}</td>
                    <td className="py-1 pr-3 font-mono text-xs text-ink-700">
                      {r.api_key_id || "—"}
                    </td>
                    <td className="py-1">
                      <Badge tone={severityTone(r.severity)}>
                        {r.severity}
                      </Badge>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ))}
      </Card>
    </div>
  );
}

function severityTone(sev: string): "neutral" | "yellow" | "red" {
  switch (sev) {
    case "critical":
      return "red";
    case "warning":
      return "yellow";
    default:
      return "neutral";
  }
}
