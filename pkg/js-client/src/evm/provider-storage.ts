/**
 * Storage abstraction for EIP-1193 provider state.
 *
 * The provider keeps a small amount of UX-critical state (which chain
 * the user picked, which account is active) that callers usually want
 * to outlive a single in-memory provider instance. In a browser
 * extension's MV3 service worker, "outlive" can mean "survive the next
 * SW suspension a few seconds from now"; in a long-running Node
 * service it can mean "outlive a process restart".
 *
 * The SDK owns load + persist; callers only plug in a backing store.
 *
 * Implementations only need synchronous-or-Promise getItem/setItem
 * over string keys. We deliberately model the API on the Web Storage
 * interface so a `globalThis.localStorage` works out of the box.
 */
export interface ProviderStorage {
  getItem(key: string): string | null | Promise<string | null>;
  setItem(key: string, value: string): void | Promise<void>;
  removeItem?(key: string): void | Promise<void>;
}

/**
 * Default in-memory store. Used when the caller doesn't provide one —
 * keeps the provider working without persistence so the SDK stays
 * usable in plain Node / tests with zero configuration.
 */
export class MemoryProviderStorage implements ProviderStorage {
  private store = new Map<string, string>();

  getItem(key: string): string | null {
    return this.store.get(key) ?? null;
  }

  setItem(key: string, value: string): void {
    this.store.set(key, value);
  }

  removeItem(key: string): void {
    this.store.delete(key);
  }
}

/**
 * Shape of the serialized provider state. Kept narrow so we don't bake
 * in fields that turn out to be wrong; extending later is cheap.
 */
export interface PersistedProviderState {
  /** Active chain ID as a decimal number. */
  chainId?: number;
  /** Active signer address (lowercased). */
  activeAddress?: string;
}

/** Default storage-key namespace if the caller doesn't override it. */
export const DEFAULT_PROVIDER_STORAGE_KEY = "remote-signer:eip1193";

export async function readPersistedState(
  storage: ProviderStorage,
  key: string
): Promise<PersistedProviderState | null> {
  try {
    const raw = await Promise.resolve(storage.getItem(key));
    if (!raw) return null;
    const parsed = JSON.parse(raw) as PersistedProviderState;
    // Light validation — bail rather than re-init with corrupt state.
    if (typeof parsed !== "object" || parsed === null) return null;
    if (parsed.chainId != null && typeof parsed.chainId !== "number") return null;
    if (parsed.activeAddress != null && typeof parsed.activeAddress !== "string") return null;
    return parsed;
  } catch {
    return null;
  }
}

export async function writePersistedState(
  storage: ProviderStorage,
  key: string,
  state: PersistedProviderState
): Promise<void> {
  try {
    await Promise.resolve(storage.setItem(key, JSON.stringify(state)));
  } catch {
    /* persistence is best-effort; in-memory state still works */
  }
}
