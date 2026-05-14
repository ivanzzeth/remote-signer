// In-memory credential store + RemoteSignerClient lifecycle.
//
// Phase-8 simplification: the web UI never persists the private key. A page
// reload requires re-import; this matches the threat model where keys live
// on disk encrypted (via `remote-signer keystore create`) and only the
// unwrapped seed ever touches the browser.
//
// All HTTP I/O goes through the linked SDK (`remote-signer-client`), so this
// module is the single owner of the client instance and broadcasts changes
// to React via subscribeAuth().

import {
  RemoteSignerClient,
  bytesToHex,
  derivePublicKey,
} from "remote-signer-client";

export interface Credentials {
  apiKeyID: string;
  privateKey: Uint8Array;
  publicKeyHex: string;
  client: RemoteSignerClient;
}

let current: Credentials | null = null;
const listeners = new Set<() => void>();

export function getCredentials(): Credentials | null {
  return current;
}

/** Convenience accessor for pages that only need the SDK client. */
export function getClient(): RemoteSignerClient | null {
  return current?.client ?? null;
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
  // The SDK signs each request itself; we just hand it the seed + id. baseURL
  // is empty so the SDK joins paths against the current page origin — same
  // host the SPA was served from, which is the daemon itself.
  const client = new RemoteSignerClient({
    baseURL: window.location.origin,
    apiKeyID,
    privateKey,
  });
  current = {
    apiKeyID,
    privateKey,
    publicKeyHex: bytesToHex(pub),
    client,
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
