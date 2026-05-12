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
 * Lists every signer the daemon knows about. Address + key type are the
 * primary identifiers; enabled/locked are the two states an operator needs
 * to see at a glance before issuing a sign request.
 */
export function Signers() {
  const { data, loading, error, reload } = useApi((c) => c.evm.signers.list());

  return (
    <div className="space-y-6">
      <PageHeader
        title="Signers"
        subtitle="EVM signing keys this daemon can use to sign transactions and messages."
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
          (data.signers.length === 0 ? (
            <Empty msg="No signers configured. Add one via `remote-signer signer create` or the CLI keystore." />
          ) : (
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase text-ink-500">
                <tr>
                  <th className="py-1 pr-3 font-normal">Address</th>
                  <th className="py-1 pr-3 font-normal">Type</th>
                  <th className="py-1 pr-3 font-normal">Enabled</th>
                  <th className="py-1 font-normal">Locked</th>
                </tr>
              </thead>
              <tbody>
                {data.signers.map((s) => (
                  <tr key={s.address} className="border-t border-ink-100">
                    <td className="py-1 pr-3 font-mono text-xs text-ink-900">
                      {s.address}
                    </td>
                    <td className="py-1 pr-3 text-ink-700">{s.type}</td>
                    <td className="py-1 pr-3">
                      <Badge tone={s.enabled ? "green" : "neutral"}>
                        {s.enabled ? "enabled" : "disabled"}
                      </Badge>
                    </td>
                    <td className="py-1">
                      <Badge tone={s.locked ? "red" : "green"}>
                        {s.locked ? "locked" : "unlocked"}
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
