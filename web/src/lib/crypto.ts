// Ed25519 helpers and request signing for the remote-signer daemon.
//
// Mirrors pkg/js-client/src/crypto.ts so the wire format stays in lock-step;
// kept locally to avoid pulling the full client SDK (and its Node-specific
// TLS helpers) into the browser bundle. The web bundle should stay slim —
// react + react-dom + @noble together are already ~150KB gzipped.

import * as ed25519 from "@noble/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { sha512 } from "@noble/hashes/sha512";

// @noble/ed25519's synchronous APIs require etc.sha512Sync to be wired up;
// noble bumped this to opt-in in v2 to avoid pulling sha512 into bundles
// that only need the async API. We use sync here because the calling code
// (signedFetch) is already inside an async function.
if (!(ed25519 as { etc?: { sha512Sync?: unknown } }).etc?.sha512Sync) {
  (
    ed25519 as unknown as {
      etc: {
        sha512Sync: (...m: Uint8Array[]) => Uint8Array;
        concatBytes: (...arrays: Uint8Array[]) => Uint8Array;
      };
    }
  ).etc.sha512Sync = (...m) =>
    sha512(
      (
        ed25519 as unknown as {
          etc: { concatBytes: (...a: Uint8Array[]) => Uint8Array };
        }
      ).etc.concatBytes(...m),
    );
}

/**
 * Parses a private key from either a hex string or a PKCS#8 PEM block
 * (the format `remote-signer api-key keygen` emits). Returns the 32-byte
 * Ed25519 seed; the caller is responsible for storing it securely.
 */
export function parsePrivateKey(input: string): Uint8Array {
  const trimmed = input.trim();

  // PKCS#8 PEM: -----BEGIN PRIVATE KEY-----\n<base64>\n-----END PRIVATE KEY-----
  if (trimmed.includes("BEGIN PRIVATE KEY")) {
    const match = trimmed.match(
      /-----BEGIN PRIVATE KEY-----([\s\S]+?)-----END PRIVATE KEY-----/,
    );
    if (!match) {
      throw new Error("malformed PKCS#8 PEM block");
    }
    const b64 = match[1].replace(/\s+/g, "");
    const der = base64Decode(b64);
    // Ed25519 PKCS#8 DER is 48 bytes total; the last 32 are the seed.
    // The header looks like:
    //   30 2e 02 01 00 30 05 06 03 2b 65 70 04 22 04 20 <32-byte seed>
    if (der.length < 32) {
      throw new Error(`PKCS#8 DER too short: ${der.length} bytes`);
    }
    return der.slice(-32);
  }

  // Hex string (optionally 0x-prefixed). Accept either a 32-byte seed
  // (64 hex chars) or a 64-byte expanded private key (128 hex chars);
  // the @noble API only needs the first 32 bytes.
  const hex = trimmed.replace(/^0x/i, "");
  if (!/^[0-9a-fA-F]+$/.test(hex)) {
    throw new Error("expected hex or PEM input");
  }
  if (hex.length !== 64 && hex.length !== 128) {
    throw new Error(
      `expected 64 or 128 hex chars, got ${hex.length}`,
    );
  }
  const bytes = hexDecode(hex);
  return bytes.length === 32 ? bytes : bytes.slice(0, 32);
}

/**
 * Derives the public key from a 32-byte Ed25519 seed. Returns 32 bytes.
 * Useful for displaying "you are admin (pubkey=...)" so the operator can
 * cross-check against admin.key.pub before trusting the session.
 */
export async function derivePublicKey(seed: Uint8Array): Promise<Uint8Array> {
  return await ed25519.getPublicKeyAsync(seed);
}

/**
 * Signs the canonical wire-format payload:
 *
 *   {timestamp}|{nonce}|{method}|{path}|{sha256(body) as hex}
 *
 * Identical to the Go verifier and pkg/js-client.
 */
export function signRequest(
  privateKey: Uint8Array,
  timestamp: number,
  nonce: string,
  method: string,
  path: string,
  body: Uint8Array,
): string {
  const bodyHash = bytesToHex(sha256(body));
  const message = `${timestamp}|${nonce}|${method}|${path}|${bodyHash}`;
  const sig = ed25519.sign(new TextEncoder().encode(message), privateKey);
  return base64Encode(sig);
}

/** Generates a fresh 16-byte hex nonce. */
export function generateNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
}

// -- byte / encoding helpers ------------------------------------------------

export function bytesToHex(b: Uint8Array): string {
  let out = "";
  for (const v of b) {
    out += v.toString(16).padStart(2, "0");
  }
  return out;
}

function hexDecode(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function base64Decode(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

function base64Encode(b: Uint8Array): string {
  let s = "";
  for (const v of b) {
    s += String.fromCharCode(v);
  }
  return btoa(s);
}
