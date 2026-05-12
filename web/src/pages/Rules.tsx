import {
  Badge,
  Card,
  Empty,
  ErrorBanner,
  Loading,
  PageHeader,
} from "../components/ui";
import { useApi } from "../lib/useApi";

/**
 * Lists every rule (whitelist/blocklist) registered on the daemon. This
 * is the operator's first stop when a sign request was unexpectedly
 * denied or auto-approved — the rule set is the source of truth.
 */
export function Rules() {
  const { data, loading, error, reload } = useApi((c) => c.evm.rules.list());

  return (
    <div className="space-y-6">
      <PageHeader
        title="Rules"
        subtitle="EVM whitelist/blocklist policies that gate sign requests."
        actions={
          <button
            type="button"
            onClick={reload}
            className="rounded-md border border-ink-200 px-3 py-1 text-xs text-ink-700 hover:bg-ink-100"
          >
            Refresh
          </button>
        }
      />

      <Card>
        {loading && <Loading />}
        {error && <ErrorBanner msg={error} />}
        {data &&
          (data.rules.length === 0 ? (
            <Empty msg="No rules defined. Sign requests will be evaluated against the daemon's default policy (manual approval if configured)." />
          ) : (
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase text-ink-500">
                <tr>
                  <th className="py-1 pr-3 font-normal">Name</th>
                  <th className="py-1 pr-3 font-normal">Type</th>
                  <th className="py-1 pr-3 font-normal">Mode</th>
                  <th className="py-1 pr-3 font-normal">Source</th>
                  <th className="py-1 font-normal">Status</th>
                </tr>
              </thead>
              <tbody>
                {data.rules.map((r) => (
                  <tr key={r.id} className="border-t border-ink-100">
                    <td className="py-1 pr-3">
                      <div className="text-ink-900">{r.name}</div>
                      <div className="font-mono text-[11px] text-ink-500">
                        {r.id}
                      </div>
                    </td>
                    <td className="py-1 pr-3 font-mono text-xs text-ink-700">
                      {r.type}
                    </td>
                    <td className="py-1 pr-3">
                      <Badge tone={r.mode === "whitelist" ? "green" : "red"}>
                        {r.mode}
                      </Badge>
                    </td>
                    <td className="py-1 pr-3 text-xs text-ink-500">
                      {r.source}
                    </td>
                    <td className="py-1">
                      <Badge tone={r.enabled ? "green" : "neutral"}>
                        {r.enabled ? "enabled" : "disabled"}
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
