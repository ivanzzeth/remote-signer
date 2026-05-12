import {
  Badge,
  Card,
  Empty,
  ErrorBanner,
  Loading,
  PageHeader,
  shorten,
} from "../components/ui";
import { useApi } from "../lib/useApi";

/**
 * Lists every API key the daemon trusts. Role + enabled tell an operator
 * whether a stale key is still active; last_used_at is the quickest way to
 * spot keys that should probably be rotated or removed.
 */
export function ApiKeys() {
  const { data, loading, error, reload } = useApi((c) => c.apiKeys.list());

  return (
    <div className="space-y-6">
      <PageHeader
        title="API Keys"
        subtitle="Ed25519 keys authorised to sign API requests."
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
          (data.keys.length === 0 ? (
            <Empty msg="No API keys registered." />
          ) : (
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase text-ink-500">
                <tr>
                  <th className="py-1 pr-3 font-normal">ID / Name</th>
                  <th className="py-1 pr-3 font-normal">Role</th>
                  <th className="py-1 pr-3 font-normal">Source</th>
                  <th className="py-1 pr-3 font-normal">Last used</th>
                  <th className="py-1 font-normal">Status</th>
                </tr>
              </thead>
              <tbody>
                {data.keys.map((k) => (
                  <tr key={k.id} className="border-t border-ink-100">
                    <td className="py-1 pr-3">
                      <div className="font-mono text-xs text-ink-900">
                        {k.id}
                      </div>
                      {k.name && k.name !== k.id && (
                        <div className="text-[11px] text-ink-500">
                          {k.name}
                        </div>
                      )}
                    </td>
                    <td className="py-1 pr-3">
                      <Badge tone={k.role === "admin" ? "red" : "neutral"}>
                        {k.role}
                      </Badge>
                    </td>
                    <td className="py-1 pr-3 text-xs text-ink-500">
                      {k.source}
                    </td>
                    <td className="py-1 pr-3 font-mono text-[11px] text-ink-700">
                      {k.last_used_at ? shorten(k.last_used_at, 19, 0) : "—"}
                    </td>
                    <td className="py-1">
                      <Badge tone={k.enabled ? "green" : "neutral"}>
                        {k.enabled ? "enabled" : "disabled"}
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
