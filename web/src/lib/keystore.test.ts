// Unit tests for the browser-side keystore.
//
// Runs under Vitest with the jsdom-ish environment Vite provides — uses
// real WebCrypto (Node 20+ ships it as crypto.subtle on globalThis) and
// real @noble/hashes scrypt. The 2^18 scrypt N makes encrypt+decrypt
// take ~2-5s here too; the suite is small (handful of cases) so total
// runtime stays in the 30s ballpark. If that ever bites, drop SCRYPT_N
// to LightScryptN (2^12) in test-only mode and pin compat with the prod
// params via one explicit StandardScryptN round-trip.

import { describe, it, expect } from "vitest";
import {
  encryptSeed,
  decryptKeystore,
  validatePassword,
} from "./keystore";

const STRONG_PASSWORD = "Correct-Horse-9!";

function seed(bytes: number[]): Uint8Array {
  if (bytes.length !== 32) {
    throw new Error(`test seed must be 32 bytes, got ${bytes.length}`);
  }
  return new Uint8Array(bytes);
}

const TEST_SEED = seed([
  0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
  0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
  0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce,
  0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
]);

describe("validatePassword", () => {
  it("rejects too-short passwords", () => {
    expect(validatePassword("Aa1!aa")).toContain("at least 10");
  });

  it("rejects missing lowercase", () => {
    expect(validatePassword("ALL-UPPER-1!XX")).toContain("lowercase");
  });

  it("rejects missing uppercase", () => {
    expect(validatePassword("all-lower-1!xx")).toContain("uppercase");
  });

  it("rejects missing digit", () => {
    expect(validatePassword("NoDigits-here!XX")).toContain("digit");
  });

  it("rejects missing special character", () => {
    expect(validatePassword("Abcdefghij1234")).toContain("special character");
  });

  it("accepts a strong password", () => {
    expect(validatePassword(STRONG_PASSWORD)).toBeNull();
  });

  it("accepts unicode special characters (not just ASCII punctuation)", () => {
    // Locks the spec — "special" means "non-alphanumeric", not "punctuation
    // from a hardcoded list". Operators using locale-specific keyboards
    // shouldn't be forced into ASCII.
    expect(validatePassword("Abcdefghi1©")).toBeNull();
  });
});

describe("encryptSeed + decryptKeystore round-trip", () => {
  it("recovers the original seed with the correct password", async () => {
    const ks = await encryptSeed(TEST_SEED, STRONG_PASSWORD, "admin");
    expect(ks.version).toBe(3);
    expect(ks.key_type).toBe("ed25519");
    expect(ks.identifier).toBe("admin");

    const { seed, identifier } = await decryptKeystore(ks, STRONG_PASSWORD);
    expect(identifier).toBe("admin");
    expect(seed).toEqual(TEST_SEED);
  }, 30_000);

  it("rejects a wrong password with the verbatim 'wrong password' message", async () => {
    // Login.tsx pattern-matches against this exact string to render the
    // unlock-failed banner. Don't reword without grep'ing.
    const ks = await encryptSeed(TEST_SEED, STRONG_PASSWORD, "admin");
    await expect(decryptKeystore(ks, "Different-Pass-9!")).rejects.toThrow(
      "wrong password",
    );
  }, 30_000);

  it("survives JSON round-trip through the wire format", async () => {
    // Persistence in localStorage goes via JSON.stringify. Pin that the
    // serialized form decrypts identically to the in-memory object.
    const ks = await encryptSeed(TEST_SEED, STRONG_PASSWORD, "admin");
    const json = JSON.stringify(ks);
    const { seed } = await decryptKeystore(json, STRONG_PASSWORD);
    expect(seed).toEqual(TEST_SEED);
  }, 30_000);

  it("produces fresh salt/iv on each encryption (no replay)", async () => {
    // Two encryptions of the SAME seed under the SAME password MUST
    // produce different ciphertexts — otherwise an attacker who sees
    // two keystores can confirm they hold the same key.
    const a = await encryptSeed(TEST_SEED, STRONG_PASSWORD, "admin");
    const b = await encryptSeed(TEST_SEED, STRONG_PASSWORD, "admin");
    expect(a.crypto.kdfparams.salt).not.toBe(b.crypto.kdfparams.salt);
    expect(a.crypto.cipherparams.iv).not.toBe(b.crypto.cipherparams.iv);
    expect(a.crypto.ciphertext).not.toBe(b.crypto.ciphertext);
  }, 60_000);
});

describe("encryptSeed input validation", () => {
  it("rejects non-32-byte seeds", async () => {
    const short = new Uint8Array(31);
    await expect(encryptSeed(short, STRONG_PASSWORD, "admin")).rejects.toThrow(
      /32 bytes/,
    );
  });

  it("rejects weak passwords (defence in depth — UI also blocks them)", async () => {
    await expect(encryptSeed(TEST_SEED, "weak", "admin")).rejects.toThrow(
      /at least 10/,
    );
  });
});

describe("decryptKeystore input validation", () => {
  it("rejects an unsupported version", async () => {
    const ks = await encryptSeed(TEST_SEED, STRONG_PASSWORD, "admin");
    const tampered = { ...ks, version: 2 };
    await expect(decryptKeystore(tampered, STRONG_PASSWORD)).rejects.toThrow(
      /version/,
    );
  }, 30_000);

  it("rejects an unsupported key_type", async () => {
    // The admin path only handles Ed25519. A secp256k1 keystore would
    // decrypt to bytes that are the wrong format for the API auth path
    // downstream — fail at load time rather than silently corrupt
    // request signing.
    const ks = await encryptSeed(TEST_SEED, STRONG_PASSWORD, "admin");
    const tampered = { ...ks, key_type: "secp256k1" };
    await expect(decryptKeystore(tampered, STRONG_PASSWORD)).rejects.toThrow(
      /key_type/,
    );
  }, 30_000);

  it("rejects malformed JSON", async () => {
    await expect(decryptKeystore("not json", STRONG_PASSWORD)).rejects.toThrow();
  });
});
