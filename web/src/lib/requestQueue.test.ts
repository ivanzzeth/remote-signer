import { describe, expect, it } from "vitest";
import {
  buildLockedSignerSet,
  getRequestBlocker,
  isActionableRequestStatus,
  summarizeLockedSignersInRequests,
} from "./requestQueue";

const ADDR = "0x0000000000000000000000000000000000000001";

describe("requestQueue", () => {
  it("detects locked signer blocker", () => {
    const locked = buildLockedSignerSet([
      { address: ADDR, locked: true },
    ]);
    const blocker = getRequestBlocker(
      {
        status: "authorizing",
        signer_address: ADDR,
        rule_matched_id: "inst-1",
      },
      locked,
    );
    expect(blocker?.kind).toBe("signer_locked");
  });

  it("prefers locked over rule-matched hint", () => {
    const locked = buildLockedSignerSet([{ address: ADDR, locked: true }]);
    const blocker = getRequestBlocker(
      {
        status: "authorizing",
        signer_address: ADDR,
        rule_matched_id: "inst-1",
      },
      locked,
    );
    expect(blocker?.kind).toBe("signer_locked");
  });

  it("surfaces rule matched stuck when signer unlocked", () => {
    const blocker = getRequestBlocker(
      {
        status: "authorizing",
        signer_address: ADDR,
        rule_matched_id: "inst-1",
      },
      new Set(),
    );
    expect(blocker?.kind).toBe("rule_matched_stuck");
  });

  it("prefers persisted error_message over locked-signer set", () => {
    const blocker = getRequestBlocker(
      {
        status: "authorizing",
        signer_address: ADDR,
        error_message: "signing failed: signer is locked",
      },
      new Set(),
    );
    expect(blocker?.kind).toBe("signer_locked");
  });

  it("shows generic sign_failed for other persisted errors", () => {
    const blocker = getRequestBlocker(
      {
        status: "authorizing",
        signer_address: ADDR,
        error_message: "signing failed: RPC timeout",
      },
      new Set(),
    );
    expect(blocker?.kind).toBe("sign_failed");
  });

  it("summarizes unique locked signers in queue", () => {
    const locked = buildLockedSignerSet([{ address: ADDR, locked: true }]);
    const addrs = summarizeLockedSignersInRequests(
      [
        { status: "authorizing", signer_address: ADDR },
        { status: "authorizing", signer_address: ADDR },
        { status: "completed", signer_address: ADDR },
      ],
      locked,
    );
    expect(addrs).toEqual([ADDR]);
  });

  it("actionable statuses", () => {
    expect(isActionableRequestStatus("authorizing")).toBe(true);
    expect(isActionableRequestStatus("completed")).toBe(false);
  });
});
