// In-memory credential store. The simplification PR8 chose: web UI never
// persists the private key. A page reload requires re-import; this matches
// the threat model where private keys live on disk encrypted (via
// `remote-signer keystore create`) and only the unwrapped bytes ever
// touch the browser.

import { derivePublicKey, bytesToHex } from "./crypto";

export interface Credentials {
  apiKeyID: string;
  privateKey: Uint8Array;
  publicKeyHex: string;
}

let current: Credentials | null = null;
const listeners = new Set<() => void>();

export function getCredentials(): Credentials | null {
  return current;
}

export async function setCredentials(
  apiKeyID: string,
  privateKey: Uint8Array,
): Promise<Credentials> {
  if (privateKey.length !== 32) {
    throw new Error(
      `private key seed must be 32 bytes, got ${privateKey.length}`,
    );
  }
  const pub = await derivePublicKey(privateKey);
  current = {
    apiKeyID,
    privateKey,
    publicKeyHex: bytesToHex(pub),
  };
  for (const l of listeners) l();
  return current;
}

export function clearCredentials(): void {
  // Zeroise the key bytes before dropping the reference so a memory dump
  // post-logout is less likely to leak the seed. Best-effort only — the JS
  // GC may have already copied bytes around by this point.
  if (current?.privateKey) {
    current.privateKey.fill(0);
  }
  current = null;
  for (const l of listeners) l();
}

/** Subscribe to credential changes; returns an unsubscribe function. */
export function subscribeAuth(fn: () => void): () => void {
  listeners.add(fn);
  return () => {
    listeners.delete(fn);
  };
}
