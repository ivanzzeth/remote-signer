/**
 * Provider state persistence via the ProviderStorage abstraction.
 *
 * Locks the contract callers (notably the browser extension's MV3
 * service worker) rely on: an EIP1193Provider configured with a
 * storage adapter must
 *   1. write {chainId, activeAddress} after every state-changing event
 *   2. rehydrate from that storage on the next create() — so a process
 *      restart / SW resume doesn't silently revert to the constructor
 *      defaults.
 */
import {
  EIP1193Provider,
  MemoryProviderStorage,
  RemoteSigner,
  EvmSignService,
  HttpTransport,
} from "../src";

function buildFakeSigners(addresses: string[], chainId = "1"): RemoteSigner[] {
  // The provider only touches `address`, `_chainID`, and `setChainID`
  // for the storage path. A minimal stub keeps the test honest about
  // what's being exercised.
  const fakeSign = {} as EvmSignService;
  return addresses.map((addr) => new RemoteSigner(fakeSign, addr, chainId));
}

const KEY = "rs-test:provider-state";

describe("EIP1193Provider × ProviderStorage", () => {
  it("persists chainId + activeAddress on a fresh create()", async () => {
    const storage = new MemoryProviderStorage();
    const signers = buildFakeSigners(["0xAaa", "0xBbb"]);

    const provider = await EIP1193Provider.create({
      signersSource: { type: "manual", signers },
      defaultChainId: 137,
      storage,
      storageKey: KEY,
    });

    // Give the fire-and-forget persist a tick.
    await new Promise((r) => setImmediate(r));

    const raw = storage.getItem(KEY) as string;
    expect(typeof raw).toBe("string");
    const parsed = JSON.parse(raw);
    expect(parsed.chainId).toBe(137);
    expect(parsed.activeAddress).toBe("0xaaa");
    expect(provider.chainId).toBe("0x89");
  });

  it("rehydrates chainId + activeAddress on a subsequent create()", async () => {
    const storage = new MemoryProviderStorage();
    storage.setItem(KEY, JSON.stringify({ chainId: 137, activeAddress: "0xbbb" }));
    const signers = buildFakeSigners(["0xAaa", "0xBbb"]);

    const provider = await EIP1193Provider.create({
      signersSource: { type: "manual", signers },
      // Constructor defaults that the persisted state must override:
      defaultChainId: 1,
      defaultAccountIndex: 0,
      storage,
      storageKey: KEY,
    });

    expect(provider.chainId).toBe("0x89");
    expect(provider.selectedAddress?.toLowerCase()).toBe("0xbbb");
  });

  it("writes back after switchAccount() so a later create() picks up the new active", async () => {
    const storage = new MemoryProviderStorage();
    const signers = buildFakeSigners(["0xAaa", "0xBbb"]);
    const provider = await EIP1193Provider.create({
      signersSource: { type: "manual", signers },
      defaultChainId: 1,
      storage,
      storageKey: KEY,
    });

    await provider.switchAccount("0xBbb");
    await new Promise((r) => setImmediate(r));

    const parsed = JSON.parse(storage.getItem(KEY) as string);
    expect(parsed.activeAddress).toBe("0xbbb");

    // Simulate a process restart: build a brand new provider from the
    // same storage and assert it lands on the persisted active signer.
    const reopened = await EIP1193Provider.create({
      signersSource: { type: "manual", signers: buildFakeSigners(["0xAaa", "0xBbb"]) },
      defaultChainId: 1,
      defaultAccountIndex: 0,
      storage,
      storageKey: KEY,
    });
    expect(reopened.selectedAddress?.toLowerCase()).toBe("0xbbb");
  });

  it("writes back after switchChain() so a later create() picks up the new chain", async () => {
    const storage = new MemoryProviderStorage();
    const signers = buildFakeSigners(["0xAaa"]);
    const provider = await EIP1193Provider.create({
      signersSource: { type: "manual", signers },
      defaultChainId: 1,
      storage,
      storageKey: KEY,
    });

    await provider.switchChain(137);
    await new Promise((r) => setImmediate(r));

    const parsed = JSON.parse(storage.getItem(KEY) as string);
    expect(parsed.chainId).toBe(137);

    const reopened = await EIP1193Provider.create({
      signersSource: { type: "manual", signers: buildFakeSigners(["0xAaa"]) },
      defaultChainId: 1,
      storage,
      storageKey: KEY,
    });
    expect(reopened.chainId).toBe("0x89");
  });

  it("returns to defaults when storage is absent", async () => {
    const signers = buildFakeSigners(["0xAaa"]);
    const provider = await EIP1193Provider.create({
      signersSource: { type: "manual", signers },
      defaultChainId: 1,
    });
    expect(provider.chainId).toBe("0x1");
    expect(provider.selectedAddress?.toLowerCase()).toBe("0xaaa");
  });

  it("ignores invalid persisted state without throwing", async () => {
    const storage = new MemoryProviderStorage();
    storage.setItem(KEY, "not-json");
    const signers = buildFakeSigners(["0xAaa"]);

    const provider = await EIP1193Provider.create({
      signersSource: { type: "manual", signers },
      defaultChainId: 1,
      storage,
      storageKey: KEY,
    });
    expect(provider.chainId).toBe("0x1");
    expect(provider.selectedAddress?.toLowerCase()).toBe("0xaaa");
  });
});
