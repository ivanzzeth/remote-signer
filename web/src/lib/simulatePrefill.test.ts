import { describe, expect, it } from "vitest";
import { prefillFromRequest } from "./simulatePrefill";

describe("prefillFromRequest", () => {
  const now = "2026-06-06T00:00:00.000Z";

  it("maps transaction payload fields", () => {
    const fields = prefillFromRequest({
      id: "req-1",
      api_key_id: "agent",
      chain_type: "evm",
      chain_id: "56",
      signer_address: "0x764602FeaD618416E42b48c633d90869fF19759E",
      sign_type: "transaction",
      status: "rejected",
      created_at: now,
      updated_at: now,
      payload: {
        transaction: {
          to: "0x8b844f885672f333bc0042cb669255f93a4c1e6b",
          value: "0",
          data: "0xdeadbeef",
          gas: 500000,
        },
      },
    });

    expect(fields).toEqual({
      chainID: "56",
      from: "0x764602FeaD618416E42b48c633d90869fF19759E",
      to: "0x8b844f885672f333bc0042cb669255f93a4c1e6b",
      value: "0",
      data: "0xdeadbeef",
      gas: "500000",
    });
  });

  it("falls back to decoded calldata snapshot", () => {
    const fields = prefillFromRequest(
      {
        id: "req-2",
        api_key_id: "agent",
        chain_type: "evm",
        chain_id: "1",
        signer_address: "0xabc",
        sign_type: "transaction",
        status: "rejected",
        created_at: now,
        updated_at: now,
        payload: { transaction: {} },
      },
      {
        to: "0xrouter",
        value: "1000",
        raw_data: "0x1234",
      },
    );

    expect(fields?.to).toBe("0xrouter");
    expect(fields?.data).toBe("0x1234");
  });

  it("returns null for non-transaction requests", () => {
    expect(
      prefillFromRequest({
        id: "req-3",
        api_key_id: "agent",
        chain_type: "evm",
        chain_id: "1",
        signer_address: "0xabc",
        sign_type: "personal",
        status: "completed",
        created_at: now,
        updated_at: now,
        payload: { message: "hello" },
      }),
    ).toBeNull();
  });
});
