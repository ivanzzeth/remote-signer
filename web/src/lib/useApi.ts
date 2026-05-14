import { useEffect, useState } from "react";
import { APIError } from "remote-signer-client";
import { getClient } from "./auth";

export interface ApiState<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
  /** Bump to force a refetch. Useful for retry buttons / after mutations. */
  reload: () => void;
}

/**
 * Run a one-shot SDK fetch keyed off the credential-bound RemoteSignerClient.
 * The caller supplies a function that turns a live client into a promise; we
 * wrap it with the standard loading/error book-keeping so every list page
 * looks the same.
 *
 * `deps` works exactly like useEffect's deps array: include anything the
 * fetcher closes over (query filters, pagination cursors, etc.).
 */
export function useApi<T>(
  fetcher: (client: NonNullable<ReturnType<typeof getClient>>) => Promise<T>,
  deps: ReadonlyArray<unknown> = [],
): ApiState<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [nonce, setNonce] = useState(0);

  useEffect(() => {
    const client = getClient();
    if (!client) {
      // Not authenticated — surface as an error so the page renders
      // something rather than spinning forever. App.tsx already gates
      // routes on auth so this is a defensive branch.
      setLoading(false);
      setError("not signed in");
      return;
    }
    let mounted = true;
    setLoading(true);
    setError(null);
    fetcher(client)
      .then((r) => {
        if (mounted) {
          setData(r);
          setLoading(false);
        }
      })
      .catch((err) => {
        if (!mounted) return;
        setLoading(false);
        if (err instanceof APIError) {
          setError(`HTTP ${err.statusCode}: ${err.message}`);
          return;
        }
        setError(err instanceof Error ? err.message : String(err));
      });
    return () => {
      mounted = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, nonce]);

  return {
    data,
    error,
    loading,
    reload: () => setNonce((n) => n + 1),
  };
}
