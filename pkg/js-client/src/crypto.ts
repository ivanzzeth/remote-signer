/**
 * Cryptographic utilities for Ed25519 signing.
 *
 * Works in both browser and Node.js: uses crypto.getRandomValues (Web Crypto API, available in both)
 * and @noble/ed25519 / @noble/hashes (pure JavaScript, no Node-specific APIs).
 */

import * as ed25519 from "@noble/ed25519";
import { sha256 } from "@noble/hashes/sha256";

// @noble/ed25519 v2 has two flavours: sync (requires opt-in `etc.sha512Sync`)
// and async (uses WebCrypto under the hood, no setup needed). The sync setter
// was historically brittle across bundlers and duplicate-module-instance
// scenarios (file: deps, Vite, Jest); using the async API everywhere removes
// the entire class of "signature verification failed" bugs that come from
// `etc.sha512Sync` not being wired up by the time the first sign happens.

/**
 * Converts a private key from various formats to a 32-byte Ed25519 seed.
 * Accepts:
 *   - Uint8Array of length 32 (seed) or 64 (seed + pubkey)
 *   - hex string (with or without 0x), 64 or 128 chars
 *   - PKCS#8 PEM block (the format `remote-signer api-key keygen` emits)
 *   - bare base64: a PEM's body (PKCS#8 DER), a 32-byte seed, or a 64-byte key
 *
 * The bare-base64 form is what an operator has on a deployed daemon, where
 * there is no file to open — the same input `--api-key-base64` takes on the CLI.
 * ⚠️ Until 2026-09-10 pasting it here failed with "expected hex or PKCS#8 PEM
 * input", which does not hint that the thing you pasted is a supported format
 * in the very next tool over.
 */
export function parsePrivateKey(
  key: string | Uint8Array
): Uint8Array {
  if (key instanceof Uint8Array) {
    if (key.length === 32) {
      // Seed
      return key;
    } else if (key.length === 64) {
      // Full private key (seed + public key)
      return key.slice(0, 32);
    } else {
      throw new Error(
        `Invalid private key length: expected 32 or 64 bytes, got ${key.length}`
      );
    }
  }

  const trimmed = key.trim();

  // PKCS#8 PEM: -----BEGIN PRIVATE KEY-----\n<base64>\n-----END PRIVATE KEY-----
  // Ed25519 PKCS#8 DER is 48 bytes; the last 32 are the seed.
  if (trimmed.includes("BEGIN PRIVATE KEY")) {
    const match = trimmed.match(
      /-----BEGIN PRIVATE KEY-----([\s\S]+?)-----END PRIVATE KEY-----/
    );
    if (!match) {
      throw new Error("malformed PKCS#8 PEM block");
    }
    const b64 = match[1].replace(/\s+/g, "");
    const bin = atob(b64);
    const der = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) {
      der[i] = bin.charCodeAt(i);
    }
    if (der.length < 32) {
      throw new Error(`PKCS#8 DER too short: ${der.length} bytes`);
    }
    return der.slice(-32);
  }

  // Hex string (optionally 0x-prefixed).
  //
  // ⛔ Hex is tried before base64 and must stay that way: 64 hex characters are
  // also 64 valid base64 characters, and 64 % 4 === 0, so a hex seed decodes
  // cleanly as 48 bytes of base64. Checking base64 first would silently read
  // every hex key as a different key.
  const hex = trimmed.startsWith("0x") ? trimmed.slice(2) : trimmed;
  if (/^[0-9a-fA-F]+$/.test(hex) && (hex.length === 64 || hex.length === 128)) {
    const bytes = new Uint8Array(
      hex.match(/.{1,2}/g)?.map((byte) => parseInt(byte, 16)) || []
    );
    // 64 bytes is seed || pubkey; the seed is the first half.
    return bytes.length === 32 ? bytes : bytes.slice(0, 32);
  }

  return parseBareBase64(trimmed);
}

/**
 * Decodes a bare base64 private key: a PEM body (PKCS#8 DER), a 32-byte seed,
 * or a 64-byte key.
 *
 * ⚠️ Unlike the Go client, this does not check that a 64-byte key's public half
 * matches its seed — @noble/ed25519 v2 derives public keys asynchronously and
 * this function is synchronous. A mismatched blob is therefore accepted here
 * and fails at first use, when the server rejects the signature.
 */
function parseBareBase64(input: string): Uint8Array {
  const compact = input.replace(/\s+/g, "");
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(compact) || compact.length % 4 !== 0) {
    throw new Error(
      "expected hex, base64, or a PKCS#8 PEM block — got something that is none of those"
    );
  }

  let bin: string;
  try {
    bin = atob(compact);
  } catch {
    throw new Error("invalid base64 private key");
  }
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    bytes[i] = bin.charCodeAt(i);
  }

  if (bytes.length === 32) {
    return bytes;
  }
  if (bytes.length === 64) {
    return bytes.slice(0, 32);
  }
  // Anything longer is a PKCS#8 DER wrapper, whose last 32 bytes are the seed.
  if (bytes.length > 32) {
    return bytes.slice(-32);
  }
  throw new Error(
    `invalid base64 private key: ${bytes.length} bytes is neither a 32-byte seed, a 64-byte key, nor PKCS#8 DER`
  );
}

/**
 * Generates a random nonce for replay protection
 * Returns a 16-byte random value encoded as hex (32 characters)
 */
export function generateNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Signs a request using Ed25519 with nonce.
 * Format: {timestamp}|{nonce}|{method}|{path}|{sha256(body)}
 *
 * Async because we use ed25519.signAsync (WebCrypto-backed) to avoid the
 * sha512Sync opt-in dance — see the module header for the rationale.
 */
export async function signRequestWithNonce(
  privateKey: Uint8Array,
  timestamp: number,
  nonce: string,
  method: string,
  path: string,
  body: Uint8Array
): Promise<string> {
  const bodyHash = sha256(body);
  const message = `${timestamp}|${nonce}|${method}|${path}|${bytesToHex(bodyHash)}`;
  const messageBytes = new TextEncoder().encode(message);
  const signature = await ed25519.signAsync(messageBytes, privateKey);
  return btoa(String.fromCharCode(...Array.from(signature)));
}

/**
 * Returns the 32-byte Ed25519 public key for a given 32-byte seed.
 * Used by the web UI to display "you are X (pubkey=...)" so operators can
 * cross-check against admin.key.pub before trusting the session.
 */
export async function derivePublicKey(seed: Uint8Array): Promise<Uint8Array> {
  return await ed25519.getPublicKeyAsync(seed);
}

/** Hex-encodes a byte slice (lowercase, no 0x prefix). */
export function bytesToHex(b: Uint8Array): string {
  let out = "";
  for (const v of b) {
    out += v.toString(16).padStart(2, "0");
  }
  return out;
}
