/**
 * Cryptographic utilities for Ed25519 signing
 */

import * as ed25519 from "@noble/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { sha512 } from "@noble/hashes/sha512";

// -----------------------------------------------------------------------------
// Noble Ed25519 setup (Node.js/Jest)
// -----------------------------------------------------------------------------
//
// @noble/ed25519's synchronous APIs require `etc.sha512Sync` to be set.
// In some consumers (e.g. file: dependencies), multiple copies/instances of
// @noble/ed25519 can exist in the module graph. Initializing here ensures the
// instance used by this package is always configured.
if (!(ed25519 as any).etc?.sha512Sync) {
  (ed25519 as any).etc.sha512Sync = (...m: Uint8Array[]) =>
    sha512((ed25519 as any).etc.concatBytes(...m));
}

/**
 * Converts a private key from various formats to Uint8Array
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

  // String input - assume hex
  const hex = (key.startsWith("0x") ? key.slice(2) : key).trim();
  const bytes = new Uint8Array(
    hex.match(/.{1,2}/g)?.map((byte) => parseInt(byte, 16)) || []
  );

  if (bytes.length === 32) {
    return bytes;
  } else if (bytes.length === 64) {
    // Full private key, extract seed
    return bytes.slice(0, 32);
  } else {
    throw new Error(
      `Invalid private key length: expected 32 or 64 bytes (hex), got ${bytes.length}`
    );
  }
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
 * Signs a request using Ed25519 (legacy format without nonce)
 * Format: {timestamp}|{method}|{path}|{sha256(body)}
 */
export function signRequest(
  privateKey: Uint8Array,
  timestamp: number,
  method: string,
  path: string,
  body: Uint8Array
): string {
  const bodyHash = sha256(body);
  const message = `${timestamp}|${method}|${path}|${Array.from(bodyHash)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")}`;
  const messageBytes = new TextEncoder().encode(message);
  const signature = ed25519.sign(messageBytes, privateKey);
  return btoa(String.fromCharCode(...Array.from(signature)));
}

/**
 * Signs a request using Ed25519 with nonce
 * Format: {timestamp}|{nonce}|{method}|{path}|{sha256(body)}
 */
export function signRequestWithNonce(
  privateKey: Uint8Array,
  timestamp: number,
  nonce: string,
  method: string,
  path: string,
  body: Uint8Array
): string {
  const bodyHash = sha256(body);
  const message = `${timestamp}|${nonce}|${method}|${path}|${Array.from(
    bodyHash
  )
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")}`;
  const messageBytes = new TextEncoder().encode(message);
  const signature = ed25519.sign(messageBytes, privateKey);
  return btoa(String.fromCharCode(...Array.from(signature)));
}
