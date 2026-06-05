import { useState } from "react";
import { APIError, type IPWhitelistResponse } from "remote-signer-client";
import { Card, ErrorBanner, Loading } from "./ui";
import { useToast } from "./feedback";
import { getClient } from "../lib/auth";
import {
  useCanReadACLs,
  useCanResumeGuard,
} from "../lib/rbac";
import { useApi } from "../lib/useApi";

interface HealthSecurity {
  approval_guard?: {
    enabled?: boolean;
    paused?: boolean;
  };
}

/** Admin-only: IP whitelist readout + manual approval guard resume. */
export function AdminSecurityPanel() {
  const canReadACLs = useCanReadACLs();
  const canResumeGuard = useCanResumeGuard();
  const health = useApi(
    async (c) => {
      const h = await c.health();
      return h as typeof h & { security?: HealthSecurity };
    },
    [],
  );
  const acl = useApi(
    async (c) => {
      if (!canReadACLs) return null;
      return c.acls.getIPWhitelist();
    },
    [canReadACLs],
  );
  const [guardBusy, setGuardBusy] = useState(false);
  const [guardError, setGuardError] = useState<string | null>(null);
  const toast = useToast();

  if (!canReadACLs && !canResumeGuard) return null;

  const guardEnabled = health.data?.security?.approval_guard?.enabled === true;
  const guardPaused = health.data?.security?.approval_guard?.paused === true;

  async function resumeGuard() {
    const client = getClient();
    if (!client) return;
    setGuardBusy(true);
    setGuardError(null);
    try {
      await client.evm.guard.resume();
      toast({ tone: "success", title: "Approval guard resumed" });
      await health.reload();
    } catch (e) {
      setGuardError(formatErr(e));
    } finally {
      setGuardBusy(false);
    }
  }

  return (
    <div className="space-y-4" data-testid="admin-security-panel">
      {canResumeGuard && (
        <Card title="Manual approval guard">
          <p className="mb-3 text-sm text-ink-600">
            If the daemon paused manual-approval processing, resume it here.
            Enabled state comes from runtime settings (
            <span className="font-mono text-xs">Settings → security → approval_guard</span>
            ).
          </p>
          {health.loading && <Loading />}
          {health.error && <ErrorBanner msg={health.error} />}
          {!health.loading && !health.error && !guardEnabled && (
            <p
              className="text-sm text-ink-600"
              data-testid="guard-not-configured"
            >
              Approval guard is disabled in runtime settings. Enable it under{" "}
              <span className="font-mono text-xs">security.approval_guard.enabled</span>{" "}
              in the Settings editor below, then save.
            </p>
          )}
          {!health.loading && !health.error && guardEnabled && !guardPaused && (
            <p className="text-sm text-green-700" data-testid="guard-active">
              Guard is enabled and not paused.
            </p>
          )}
          {!health.loading && !health.error && guardEnabled && guardPaused && (
            <p className="mb-2 text-sm text-amber-700" data-testid="guard-paused">
              Guard is paused — signing is blocked until you resume.
            </p>
          )}
          {guardError && <ErrorBanner msg={guardError} />}
          {guardEnabled && (
            <button
              type="button"
              onClick={resumeGuard}
              disabled={guardBusy}
              data-testid="guard-resume"
              className="rounded-md border border-ink-200 px-3 py-1 text-xs text-ink-700 hover:bg-ink-100 disabled:opacity-50"
            >
              {guardBusy ? "Resuming…" : "Resume guard"}
            </button>
          )}
        </Card>
      )}

      {canReadACLs && (
        <Card title="IP whitelist (read-only)">
          {acl.loading && <Loading />}
          {acl.error && <ErrorBanner msg={acl.error} />}
          {acl.data && <ACLView data={acl.data} />}
        </Card>
      )}
    </div>
  );
}

function ACLView({ data }: { data: IPWhitelistResponse }) {
  return (
    <dl className="space-y-2 text-sm">
      <Row k="Enabled" v={String(data.enabled)} />
      <Row k="Trust proxy" v={String(data.trust_proxy)} />
      <div>
        <dt className="text-[11px] uppercase text-ink-500">Allowed IPs</dt>
        <dd className="mt-1 font-mono text-xs text-ink-800">
          {data.allowed_ips?.length
            ? data.allowed_ips.join("\n")
            : "(none — all IPs allowed when disabled)"}
        </dd>
      </div>
      {data.trusted_proxies?.length ? (
        <div>
          <dt className="text-[11px] uppercase text-ink-500">
            Trusted proxies
          </dt>
          <dd className="mt-1 font-mono text-xs text-ink-800">
            {data.trusted_proxies.join("\n")}
          </dd>
        </div>
      ) : null}
    </dl>
  );
}

function Row({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex gap-4">
      <dt className="w-28 text-ink-500">{k}</dt>
      <dd className="font-mono text-xs text-ink-900">{v}</dd>
    </div>
  );
}

function formatErr(e: unknown): string {
  if (e instanceof APIError) return `HTTP ${e.statusCode}: ${e.message}`;
  if (e instanceof Error) return e.message;
  return String(e);
}
