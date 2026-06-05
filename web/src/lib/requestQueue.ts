import type { RequestStatus, RequestStatusResponse } from "remote-signer-client";

export const REQUEST_LIST_PAGE_SIZE = 100;

export function isActionableRequestStatus(status: RequestStatus): boolean {
  return status === "pending" || status === "authorizing";
}

export type RequestBlockerKind =
  | "signer_locked"
  | "rule_matched_stuck"
  | "no_rule"
  | "sign_failed";

export interface RequestBlocker {
  kind: RequestBlockerKind;
  message: string;
}

function normalizeSignFailureMessage(raw: string): RequestBlocker | null {
  const msg = raw.trim();
  if (!msg) return null;
  if (/locked/i.test(msg)) {
    return { kind: "signer_locked", message: msg };
  }
  return { kind: "sign_failed", message: msg };
}

export function buildLockedSignerSet(
  signers: ReadonlyArray<{ address: string; locked: boolean }>,
): ReadonlySet<string> {
  const locked = new Set<string>();
  for (const s of signers) {
    if (s.locked) locked.add(s.address.toLowerCase());
  }
  return locked;
}

export function getRequestBlocker(
  req: Pick<
    RequestStatusResponse,
    | "status"
    | "signer_address"
    | "rule_matched_id"
    | "last_no_match_reason"
    | "error_message"
  >,
  lockedSigners: ReadonlySet<string>,
): RequestBlocker | null {
  if (!isActionableRequestStatus(req.status)) return null;

  if (req.error_message?.trim()) {
    const fromErr = normalizeSignFailureMessage(req.error_message);
    if (fromErr) return fromErr;
  }

  if (lockedSigners.has(req.signer_address.toLowerCase())) {
    return {
      kind: "signer_locked",
      message:
        "Signer is locked — unlock it before approval can produce a signature.",
    };
  }

  if (req.status === "authorizing" && req.rule_matched_id) {
    return {
      kind: "rule_matched_stuck",
      message:
        "Whitelist rule already matched — signing did not finish (often a locked signer).",
    };
  }

  if (req.status === "authorizing" && req.last_no_match_reason) {
    return {
      kind: "no_rule",
      message: req.last_no_match_reason,
    };
  }

  return null;
}

export function summarizeLockedSignersInRequests(
  requests: ReadonlyArray<Pick<RequestStatusResponse, "signer_address" | "status">>,
  lockedSigners: ReadonlySet<string>,
): string[] {
  const addrs = new Set<string>();
  for (const req of requests) {
    if (!isActionableRequestStatus(req.status)) continue;
    const addr = req.signer_address.toLowerCase();
    if (lockedSigners.has(addr)) addrs.add(req.signer_address);
  }
  return [...addrs];
}
