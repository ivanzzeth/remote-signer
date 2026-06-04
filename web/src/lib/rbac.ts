import { getCredentials } from "./auth";
import { useApi } from "./useApi";

/** True when the signed-in key has admin or dev role (read_audit permission). */
export function useCanReadAudit(): boolean {
  const namesApi = useApi((c) => c.apiKeys.names());
  const currentRole =
    namesApi.data?.keys.find((k) => k.id === getCredentials()?.apiKeyID)
      ?.role ?? "";
  return currentRole === "admin" || currentRole === "dev";
}
