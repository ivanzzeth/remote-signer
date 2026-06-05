import { getCredentials } from "./auth";
import { useApi } from "./useApi";

export type AppRole = "admin" | "dev" | "agent" | "strategy" | "";

/** Resolved role for the signed-in API key (empty while loading). */
export function useCurrentRole(): AppRole {
  const namesApi = useApi((c) => c.apiKeys.names());
  const currentApiKeyID = getCredentials()?.apiKeyID ?? "";
  const role =
    namesApi.data?.keys.find((k) => k.id === currentApiKeyID)?.role ?? "";
  return role as AppRole;
}

export function useCanReadAudit(): boolean {
  const role = useCurrentRole();
  return role === "admin" || role === "dev";
}

/** PermApproveRequest — admin only at the HTTP layer. */
export function useCanApproveRequest(): boolean {
  return useCurrentRole() === "admin";
}

export function useCanManageAPIKeys(): boolean {
  return useCurrentRole() === "admin";
}

export function useCanManageSettings(): boolean {
  return useCurrentRole() === "admin";
}

export function useCanManageBudgets(): boolean {
  return useCurrentRole() === "admin";
}

export function useCanUnlockSigners(): boolean {
  return useCurrentRole() === "admin";
}

export function useCanApproveSigner(): boolean {
  return useCurrentRole() === "admin";
}

export function useCanReadACLs(): boolean {
  return useCurrentRole() === "admin";
}

export function useCanResumeGuard(): boolean {
  return useCurrentRole() === "admin";
}

/** apply_preset permission — registry refresh uses the same gate. */
export function useCanRefreshRegistry(): boolean {
  const role = useCurrentRole();
  return role === "admin" || role === "agent";
}

/** Agent edits to rules they do not own must go through propose. */
export function useShouldProposeRuleChanges(): boolean {
  return useCurrentRole() === "agent";
}

export function useCanSignOrSimulate(): boolean {
  const role = useCurrentRole();
  return role === "admin" || role === "dev" || role === "agent" || role === "strategy";
}
