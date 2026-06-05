import { useMemo } from "react";
import { buildLockedSignerSet } from "./requestQueue";
import { useApi } from "./useApi";

/** Addresses of signers currently locked in the daemon registry. */
export function useLockedSignerAddresses(): ReadonlySet<string> {
  const { data } = useApi((c) => c.evm.signers.list({ limit: 500 }));
  return useMemo(
    () => buildLockedSignerSet(data?.signers ?? []),
    [data?.signers],
  );
}
