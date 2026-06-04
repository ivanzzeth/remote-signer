import { describe, expect, it } from "vitest";
import { isHDWalletPrimary } from "./hdSigner";

describe("isHDWalletPrimary", () => {
  it("returns false for non-HD signers", () => {
    expect(
      isHDWalletPrimary({
        type: "keystore",
        address: "0xabc",
        hd_derivation_index: 0,
      }),
    ).toBe(false);
  });

  it("detects primary via derivation index 0", () => {
    expect(
      isHDWalletPrimary({
        type: "hd_wallet",
        address: "0xPrimary",
        primary_address: "0xOther",
        hd_derivation_index: 0,
      }),
    ).toBe(true);
  });

  it("detects primary when address matches primary_address", () => {
    expect(
      isHDWalletPrimary({
        type: "hd_wallet",
        address: "0xAbC",
        primary_address: "0xabc",
      }),
    ).toBe(true);
  });

  it("returns false for derived child addresses", () => {
    expect(
      isHDWalletPrimary({
        type: "hd_wallet",
        address: "0xchild",
        primary_address: "0xparent",
        hd_derivation_index: 3,
      }),
    ).toBe(false);
  });
});
