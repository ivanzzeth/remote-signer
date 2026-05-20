// In-memory credential store + RemoteSignerClient lifecycle, with optional
// localStorage persistence of the password-encrypted keystore JSON.
//
// Threat model:
//
//   - The unwrapped 32-byte Ed25519 seed ONLY lives in memory while a
//     session is unlocked (in `current`). Page reload / tab close drops it.
//   - The encrypted keystore JSON CAN live in localStorage (see
//     persistKeystore). It's scrypt(N=2^18) + AES-CTR + keccak256 MAC, the
//     same shape ethsig/go-ethereum write to disk. An attacker with browser
//     access reads the ciphertext but still needs the password.
//   - Logout clears `current` but keeps the keystore JSON, so the operator
//     just re-enters the password on the next visit. "Reset keystore" wipes
//     localStorage and forces re-import.
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

// ──────────────────────────────────────────────────────────────────────
// localStorage persistence — encrypted keystore + the api-key id label
// ──────────────────────────────────────────────────────────────────────
//
// The keystore JSON itself is scrypt-encrypted; we store the JSON text
// and the operator-facing id (the api-key id, e.g. "admin") separately
// so the unlock screen can prefill the id without decrypting.

const KEYSTORE_LS_KEY = "remote-signer:web:keystore";
const KEYSTORE_ID_LS_KEY = "remote-signer:web:keystore-id";

/** Returns true if a persisted keystore exists in localStorage. */
export function hasStoredKeystore(): boolean {
  try {
    return localStorage.getItem(KEYSTORE_LS_KEY) !== null;
  } catch {
    // localStorage may throw in private-mode browsers; treat as absent.
    return false;
  }
}

/** Returns the stored keystore JSON text, or null if absent. */
export function getStoredKeystoreJSON(): string | null {
  try {
    return localStorage.getItem(KEYSTORE_LS_KEY);
  } catch {
    return null;
  }
}

/** Returns the stored api-key id label, or null if absent. */
export function getStoredKeystoreID(): string | null {
  try {
    return localStorage.getItem(KEYSTORE_ID_LS_KEY);
  } catch {
    return null;
  }
}

/**
 * Persists the keystore JSON + id label. Throws on quota / private-mode
 * errors so the UI can surface "couldn't save to this browser" to the
 * operator instead of silently losing the key on reload.
 */
export function persistKeystore(apiKeyID: string, keystoreJSON: string): void {
  localStorage.setItem(KEYSTORE_LS_KEY, keystoreJSON);
  localStorage.setItem(KEYSTORE_ID_LS_KEY, apiKeyID);
}

/** Removes the persisted keystore + id. No-op if absent. */
export function clearStoredKeystore(): void {
  try {
    localStorage.removeItem(KEYSTORE_LS_KEY);
    localStorage.removeItem(KEYSTORE_ID_LS_KEY);
  } catch {
    // best-effort
  }
}
