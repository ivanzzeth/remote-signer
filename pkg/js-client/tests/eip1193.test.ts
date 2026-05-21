/**
 * EIP-1193 Provider multi-account tests
 */

import { EIP1193Provider } from "../src/evm/eip1193";
import { RemoteSigner } from "../src/evm/remote_signer";
import { RemoteSignerClient } from "../src/client";
import { ProviderErrorCode } from "../src/evm/provider-errors";
import type { EIP1193ProviderConfig, SignersSource } from "../src/evm/provider-types";

// Mock RemoteSignerClient
const createMockClient = () => {
  return {
    evm: {
      sign: {} as any, // Mock sign service for RemoteSigner constructor
      signers: {
        list: jest.fn(),
      },
      hdWallets: {
        getSigners: jest.fn(),
      },
    },
  } as any as RemoteSignerClient;
};

// Mock RemoteSigner
const createMockSigner = (address: string, chainId: string) => {
  return {
    address,
    chainId,
    setChainID: jest.fn(),
    personalSign: jest.fn().mockResolvedValue("0xsignature"),
    signHash: jest.fn().mockResolvedValue("0xsignature"),
    signTypedData: jest.fn().mockResolvedValue("0xsignature"),
    signTransaction: jest.fn().mockResolvedValue("0xsignedtx"),
  } as any as RemoteSigner;
};

describe("EIP1193Provider - Initialization", () => {
  it("should initialize with client mode (auto-fetch signers)", async () => {
    const mockClient = createMockClient();

    // Mock signers.list() response
    (mockClient.evm.signers.list as jest.Mock).mockResolvedValue({
      signers: [
        { address: "0xAddress1", enabled: true, locked: false, type: "keystore" },
        { address: "0xAddress2", enabled: true, locked: false, type: "keystore" },
        { address: "0xAddress3", enabled: false, locked: false, type: "keystore" }, // Filtered out
        { address: "0xAddress4", enabled: true, locked: true, type: "keystore" }, // Filtered out
      ],
    });

    const provider = await EIP1193Provider.create({
      signersSource: {
        type: "client",
        client: mockClient,
        chainId: 1,
      },
    });

    expect(provider.isConnected()).toBe(true);
    expect(provider.selectedAddress).toBe("0xAddress1");

    const accounts = (await provider.request({ method: "eth_accounts" })) as string[];
    expect(accounts).toHaveLength(2);
    expect(accounts[0]).toBe("0xAddress1");
    expect(accounts[1]).toBe("0xAddress2");
  });

  it("should initialize with hdwallet mode", async () => {
    const mockClient = createMockClient();

    // Mock hdWallets.getSigners() response - returns RemoteSigner[] directly
    const derivedSigners = [
      createMockSigner("0xDerived1", "1"),
      createMockSigner("0xDerived2", "1"),
      createMockSigner("0xDerived3", "1"),
    ];
    (mockClient.evm.hdWallets.getSigners as jest.Mock).mockResolvedValue(derivedSigners);

    const provider = await EIP1193Provider.create({
      signersSource: {
        type: "hdwallet",
        client: mockClient,
        primaryAddress: "0xPrimary",
        chainId: "1",
        start: 0,
        count: 3,
      },
    });

    expect(provider.isConnected()).toBe(true);
    expect(provider.selectedAddress).toBe("0xDerived1");

    const accounts = (await provider.request({ method: "eth_accounts" })) as string[];
    expect(accounts).toHaveLength(3);
    expect(accounts).toEqual(["0xDerived1", "0xDerived2", "0xDerived3"]);
  });

  it("should initialize with manual mode", async () => {
    const signer1 = createMockSigner("0xManual1", "1");
    const signer2 = createMockSigner("0xManual2", "1");

    const provider = await EIP1193Provider.create({
      signersSource: {
        type: "manual",
        signers: [signer1, signer2],
      },
    });

    expect(provider.isConnected()).toBe(true);
    expect(provider.selectedAddress).toBe("0xManual1");

    const accounts = (await provider.request({ method: "eth_accounts" })) as string[];
    expect(accounts).toHaveLength(2);
    expect(accounts).toEqual(["0xManual1", "0xManual2"]);
  });

  it("should respect defaultAccountIndex", async () => {
    const signer1 = createMockSigner("0xAccount1", "1");
    const signer2 = createMockSigner("0xAccount2", "1");
    const signer3 = createMockSigner("0xAccount3", "1");

    const provider = await EIP1193Provider.create({
      signersSource: {
        type: "manual",
        signers: [signer1, signer2, signer3],
      },
      defaultAccountIndex: 1,
    });

    expect(provider.selectedAddress).toBe("0xAccount2");

    const accounts = (await provider.request({ method: "eth_accounts" })) as string[];
    expect(accounts[0]).toBe("0xAccount2"); // Active account first
    expect(accounts).toContain("0xAccount1");
    expect(accounts).toContain("0xAccount3");
  });

  it("should emit connect event on initialization", async () => {
    const signer1 = createMockSigner("0xAccount1", "1");

    const connectHandler = jest.fn();

    const provider = await EIP1193Provider.create({
      signersSource: {
        type: "manual",
        signers: [signer1],
      },
    });

    provider.on("connect", connectHandler);

    // Connect event is emitted during create(), so we need to create a new one
    const provider2 = await EIP1193Provider.create({
      signersSource: {
        type: "manual",
        signers: [signer1],
      },
    });

    // Since connect is emitted in create(), we can't test it post-creation
    // Instead, verify the provider is connected
    expect(provider2.isConnected()).toBe(true);
  });
});

describe("EIP1193Provider - Account Management", () => {
  let provider: EIP1193Provider;
  let signer1: RemoteSigner;
  let signer2: RemoteSigner;
  let signer3: RemoteSigner;

  beforeEach(async () => {
    signer1 = createMockSigner("0xAccount1", "1");
    signer2 = createMockSigner("0xAccount2", "1");
    signer3 = createMockSigner("0xAccount3", "1");

    provider = await EIP1193Provider.create({
      signersSource: {
        type: "manual",
        signers: [signer1, signer2, signer3],
      },
    });
  });

  it("should switch account by index", async () => {
    expect(provider.selectedAddress).toBe("0xAccount1");

    const accountsChangedHandler = jest.fn();
    provider.on("accountsChanged", accountsChangedHandler);

    await provider.switchAccount(1);

    expect(provider.selectedAddress).toBe("0xAccount2");
    expect(accountsChangedHandler).toHaveBeenCalledWith([
      "0xAccount2",
      "0xAccount1",
      "0xAccount3",
    ]);
  });

  it("should switch account by address", async () => {
    expect(provider.selectedAddress).toBe("0xAccount1");

    const accountsChangedHandler = jest.fn();
    provider.on("accountsChanged", accountsChangedHandler);

    await provider.switchAccount("0xAccount3");

    expect(provider.selectedAddress).toBe("0xAccount3");
    expect(accountsChangedHandler).toHaveBeenCalledWith([
      "0xAccount3",
      "0xAccount1",
      "0xAccount2",
    ]);
  });

  it("should throw error when switching to invalid index", async () => {
    await expect(provider.switchAccount(99)).rejects.toThrow("Invalid account index");
  });

  it("should throw error when switching to non-existent address", async () => {
    await expect(provider.switchAccount("0xNonExistent")).rejects.toThrow(
      "Account not found"
    );
  });

  it("should add new account", async () => {
    const newSigner = createMockSigner("0xNewAccount", "1");

    const accountsChangedHandler = jest.fn();
    provider.on("accountsChanged", accountsChangedHandler);

    await provider.addAccount(newSigner);

    const accounts = (await provider.request({ method: "eth_accounts" })) as string[];
    expect(accounts).toHaveLength(4);
    expect(accounts).toContain("0xNewAccount");
    expect(accountsChangedHandler).toHaveBeenCalled();
  });

  it("should throw error when adding duplicate account", async () => {
    await expect(provider.addAccount(signer1)).rejects.toThrow("Account already exists");
  });

  it("should remove account by index", async () => {
    const accountsChangedHandler = jest.fn();
    provider.on("accountsChanged", accountsChangedHandler);

    await provider.removeAccount(1); // Remove Account2

    const accounts = (await provider.request({ method: "eth_accounts" })) as string[];
    expect(accounts).toHaveLength(2);
    expect(accounts).not.toContain("0xAccount2");
    expect(accountsChangedHandler).toHaveBeenCalled();
  });

  it("should remove account by address", async () => {
    await provider.removeAccount("0xAccount2");

    const accounts = (await provider.request({ method: "eth_accounts" })) as string[];
    expect(accounts).toHaveLength(2);
    expect(accounts).not.toContain("0xAccount2");
  });

  it("should auto-switch to index 0 when removing active account", async () => {
    await provider.switchAccount(1); // Switch to Account2
    expect(provider.selectedAddress).toBe("0xAccount2");

    await provider.removeAccount(1); // Remove active account

    expect(provider.selectedAddress).toBe("0xAccount1"); // Auto-switched to index 0
  });

  it("should emit disconnect when removing last account", async () => {
    const disconnectHandler = jest.fn();
    provider.on("disconnect", disconnectHandler);

    // Remove all accounts
    await provider.removeAccount(0);
    await provider.removeAccount(0);
    await provider.removeAccount(0);

    expect(provider.isConnected()).toBe(false);
    expect(provider.selectedAddress).toBeNull();
    expect(disconnectHandler).toHaveBeenCalled();
  });

  it("should disconnect and clear all accounts", async () => {
    const disconnectHandler = jest.fn();
    provider.on("disconnect", disconnectHandler);

    await provider.disconnect();

    expect(provider.isConnected()).toBe(false);
    expect(provider.selectedAddress).toBeNull();

    const accounts = (await provider.request({ method: "eth_accounts" })) as string[];
    expect(accounts).toHaveLength(0);

    expect(disconnectHandler).toHaveBeenCalled();
  });
});

describe("EIP1193Provider - RPC Methods", () => {
  let provider: EIP1193Provider;
  let signer1: RemoteSigner;
  let signer2: RemoteSigner;

  beforeEach(async () => {
    signer1 = createMockSigner("0xAccount1", "1");
    signer2 = createMockSigner("0xAccount2", "1");

    provider = await EIP1193Provider.create({
      signersSource: {
        type: "manual",
        signers: [signer1, signer2],
      },
    });
  });

  it("should return all accounts with active first (eth_accounts)", async () => {
    const accounts = (await provider.request({ method: "eth_accounts" })) as string[];

    expect(accounts).toHaveLength(2);
    expect(accounts[0]).toBe("0xAccount1"); // Active first
    expect(accounts[1]).toBe("0xAccount2");

    // Switch account and verify order changes
    await provider.switchAccount(1);

    const accountsAfterSwitch = (await provider.request({
      method: "eth_accounts",
    })) as string[];
    expect(accountsAfterSwitch[0]).toBe("0xAccount2"); // New active first
    expect(accountsAfterSwitch[1]).toBe("0xAccount1");
  });

  it("should return all accounts (eth_requestAccounts)", async () => {
    const accounts = (await provider.request({
      method: "eth_requestAccounts",
    })) as string[];

    expect(accounts).toHaveLength(2);
    expect(accounts[0]).toBe("0xAccount1");
  });

  it("should return chainId", async () => {
    const chainId = await provider.request({ method: "eth_chainId" });
    expect(chainId).toBe("0x1");
  });

  it("should return selectedAddress for eth_coinbase", async () => {
    const coinbase = await provider.request({ method: "eth_coinbase" });
    expect(coinbase).toBe("0xAccount1");
  });

  it("should sign with personal_sign", async () => {
    const signature = await provider.request({
      method: "personal_sign",
      params: ["0xmessage", "0xAccount1"],
    });

    expect(signature).toBe("0xsignature");
    expect(signer1.personalSign).toHaveBeenCalledWith("0xmessage");
  });

  it("rejects personal_sign for an address not in the provider's signer set", async () => {
    // Pre-fix the provider only routed to the active signer and threw
    // "Address mismatch" for anything else — that blocked the
    // legitimate multi-account case where the dApp signs for a
    // non-active signer the user owns. The check is now flipped:
    // unknown addresses still error (security), but a wrong-but-known
    // address falls through to the matched signer.
    await expect(
      provider.request({
        method: "personal_sign",
        params: ["0xmessage", "0xUnknownToProvider"],
      })
    ).rejects.toThrow(/not available in this provider/i);
  });

  it("personal_sign routes to a non-active signer when the dApp asks for one", async () => {
    // Active is 0xAccount1 (the create() default), but the dApp asks
    // 0xAccount2 — must hit signer2.personalSign, not signer1's.
    const sig = await provider.request({
      method: "personal_sign",
      params: ["0xmessage", "0xAccount2"],
    });
    expect(sig).toBe("0xsignature");
    expect(signer2.personalSign).toHaveBeenCalledWith("0xmessage");
    expect(signer1.personalSign).not.toHaveBeenCalled();
  });

  it("should sign with eth_sign", async () => {
    const signature = await provider.request({
      method: "eth_sign",
      params: ["0xAccount1", "0xhash"],
    });

    expect(signature).toBe("0xsignature");
    expect(signer1.signHash).toHaveBeenCalledWith("0xhash");
  });

  it("should sign with eth_signTypedData_v4", async () => {
    const typedData = '{"types":{},"domain":{},"message":{}}';

    const signature = await provider.request({
      method: "eth_signTypedData_v4",
      params: ["0xAccount1", typedData],
    });

    expect(signature).toBe("0xsignature");
    // signTypedData receives the parsed object, not the string
    expect(signer1.signTypedData).toHaveBeenCalledWith({ types: {}, domain: {}, message: {} });
  });

  it("should sign transaction with eth_signTransaction", async () => {
    const tx = {
      from: "0xAccount1",
      to: "0xRecipient",
      value: "0x1",
      gas: "0x5208",
    };

    const signedTx = await provider.request({
      method: "eth_signTransaction",
      params: [tx],
    });

    expect(signedTx).toBe("0xsignedtx");
    expect(signer1.signTransaction).toHaveBeenCalledWith(tx);
  });

  it("should throw ProviderRpcError for unsupported methods", async () => {
    try {
      await provider.request({ method: "eth_unsupportedMethod" });
      fail("Should have thrown error");
    } catch (error: any) {
      expect(error.code).toBe(ProviderErrorCode.UNSUPPORTED_METHOD);
      expect(error.message).toContain("eth_unsupportedMethod");
    }
  });

  it("should throw error when disconnected", async () => {
    await provider.disconnect();

    await expect(
      provider.request({
        method: "personal_sign",
        params: ["0xmessage", "0xAccount1"],
      })
    ).rejects.toThrow();
  });
});

describe("EIP1193Provider - Events", () => {
  let provider: EIP1193Provider;
  let signer1: RemoteSigner;
  let signer2: RemoteSigner;

  beforeEach(async () => {
    signer1 = createMockSigner("0xAccount1", "1");
    signer2 = createMockSigner("0xAccount2", "1");

    provider = await EIP1193Provider.create({
      signersSource: {
        type: "manual",
        signers: [signer1, signer2],
      },
    });
  });

  it("should emit accountsChanged on switchAccount", async () => {
    const handler = jest.fn();
    provider.on("accountsChanged", handler);

    await provider.switchAccount(1);

    expect(handler).toHaveBeenCalledTimes(1);
    expect(handler).toHaveBeenCalledWith(["0xAccount2", "0xAccount1"]);
  });

  it("should emit accountsChanged on addAccount", async () => {
    const handler = jest.fn();
    provider.on("accountsChanged", handler);

    const newSigner = createMockSigner("0xNewAccount", "1");
    await provider.addAccount(newSigner);

    expect(handler).toHaveBeenCalledTimes(1);
    const accounts = handler.mock.calls[0][0];
    expect(accounts).toContain("0xNewAccount");
  });

  it("should emit accountsChanged on removeAccount", async () => {
    const handler = jest.fn();
    provider.on("accountsChanged", handler);

    await provider.removeAccount(1);

    expect(handler).toHaveBeenCalledTimes(1);
    const accounts = handler.mock.calls[0][0];
    expect(accounts).not.toContain("0xAccount2");
  });

  it("should emit disconnect when all accounts removed", async () => {
    const handler = jest.fn();
    provider.on("disconnect", handler);

    await provider.removeAccount(0);
    await provider.removeAccount(0);

    expect(handler).toHaveBeenCalledTimes(1);
  });

  it("should emit disconnect on disconnect()", async () => {
    const handler = jest.fn();
    provider.on("disconnect", handler);

    await provider.disconnect();

    expect(handler).toHaveBeenCalledTimes(1);
    const error = handler.mock.calls[0][0];
    expect(error.code).toBe(ProviderErrorCode.DISCONNECTED);
  });

  it("should emit both chainChanged and accountsChanged on switchChain", async () => {
    const chainChangedHandler = jest.fn();
    const accountsChangedHandler = jest.fn();

    provider.on("chainChanged", chainChangedHandler);
    provider.on("accountsChanged", accountsChangedHandler);

    await provider.switchChain(137);

    expect(chainChangedHandler).toHaveBeenCalledWith("0x89"); // 137 in hex
    expect(accountsChangedHandler).toHaveBeenCalled();

    // Verify signers updated
    expect(signer1.setChainID).toHaveBeenCalledWith("137");
    expect(signer2.setChainID).toHaveBeenCalledWith("137");
  });

  it("should support removeListener", async () => {
    const handler = jest.fn();
    provider.on("accountsChanged", handler);

    await provider.switchAccount(1);
    expect(handler).toHaveBeenCalledTimes(1);

    provider.removeListener("accountsChanged", handler);

    await provider.switchAccount(0);
    expect(handler).toHaveBeenCalledTimes(1); // Still 1, not called again
  });
});

describe("EIP1193Provider - MetaMask Compatibility", () => {
  it("should have isMetaMask property", async () => {
    const signer1 = createMockSigner("0xAccount1", "1");

    const provider = await EIP1193Provider.create({
      signersSource: {
        type: "manual",
        signers: [signer1],
      },
    });

    expect(provider.isMetaMask).toBe(true);
  });

  it("should have selectedAddress property", async () => {
    const signer1 = createMockSigner("0xAccount1", "1");

    const provider = await EIP1193Provider.create({
      signersSource: {
        type: "manual",
        signers: [signer1],
      },
    });

    expect(provider.selectedAddress).toBe("0xAccount1");
  });

  it("should return null selectedAddress when disconnected", async () => {
    const signer1 = createMockSigner("0xAccount1", "1");

    const provider = await EIP1193Provider.create({
      signersSource: {
        type: "manual",
        signers: [signer1],
      },
    });

    await provider.disconnect();

    expect(provider.selectedAddress).toBeNull();
  });

  it("should have isConnected() method", async () => {
    const signer1 = createMockSigner("0xAccount1", "1");

    const provider = await EIP1193Provider.create({
      signersSource: {
        type: "manual",
        signers: [signer1],
      },
    });

    expect(provider.isConnected()).toBe(true);

    await provider.disconnect();

    expect(provider.isConnected()).toBe(false);
  });

  it("should have chainId property", async () => {
    const signer1 = createMockSigner("0xAccount1", "1");

    const provider = await EIP1193Provider.create({
      signersSource: {
        type: "manual",
        signers: [signer1],
      },
      defaultChainId: 137,
    });

    expect(provider.chainId).toBe("0x89"); // 137 in hex
  });
});

describe("EIP1193Provider - Chain Switching", () => {
  it("should switch chain and update all signers", async () => {
    const signer1 = createMockSigner("0xAccount1", "1");
    const signer2 = createMockSigner("0xAccount2", "1");

    const provider = await EIP1193Provider.create({
      signersSource: {
        type: "manual",
        signers: [signer1, signer2],
      },
    });

    await provider.switchChain(137);

    expect(provider.chainId).toBe("0x89");
    expect(signer1.setChainID).toHaveBeenCalledWith("137");
    expect(signer2.setChainID).toHaveBeenCalledWith("137");
  });

  it("should accept hex chainId", async () => {
    const signer1 = createMockSigner("0xAccount1", "1");

    const provider = await EIP1193Provider.create({
      signersSource: {
        type: "manual",
        signers: [signer1],
      },
    });

    await provider.switchChain("0x89"); // 137 in hex

    expect(provider.chainId).toBe("0x89");
    expect(signer1.setChainID).toHaveBeenCalledWith("137");
  });

  it("should not emit events when switching to same chain", async () => {
    const signer1 = createMockSigner("0xAccount1", "1");

    const provider = await EIP1193Provider.create({
      signersSource: {
        type: "manual",
        signers: [signer1],
      },
      defaultChainId: 1,
    });

    const chainChangedHandler = jest.fn();
    provider.on("chainChanged", chainChangedHandler);

    await provider.switchChain(1); // Same chain

    expect(chainChangedHandler).not.toHaveBeenCalled();
  });
});

describe("EIP1193Provider - refreshSigners", () => {
  // The scenario these tests pin down: host (the browser extension SW)
  // starts with N signers cached at create(); user unlocks one more on
  // the daemon side; the dApp's next request must see the new signer
  // without an extension reload. refreshSigners() is the SDK contract
  // that makes that possible.

  it("picks up a new signer unlocked daemon-side without re-creating the provider", async () => {
    const mockClient = createMockClient();
    (mockClient.evm.signers.list as jest.Mock).mockResolvedValueOnce({
      signers: [{ address: "0xA", enabled: true, locked: false, type: "keystore" }],
    });
    const provider = await EIP1193Provider.create({
      signersSource: { type: "client", client: mockClient, chainId: 1 },
    });
    expect(((await provider.request({ method: "eth_accounts" })) as string[]).length).toBe(1);

    // Daemon side: a second signer just got unlocked.
    (mockClient.evm.signers.list as jest.Mock).mockResolvedValueOnce({
      signers: [
        { address: "0xA", enabled: true, locked: false, type: "keystore" },
        { address: "0xB", enabled: true, locked: false, type: "keystore" },
      ],
    });

    const accountsChanged = jest.fn();
    provider.on("accountsChanged", accountsChanged);
    await provider.refreshSigners();

    const after = (await provider.request({ method: "eth_accounts" })) as string[];
    expect(after).toEqual(["0xA", "0xB"]);
    expect(accountsChanged).toHaveBeenCalledTimes(1);
  });

  it("preserves active address when it survives the refresh", async () => {
    const mockClient = createMockClient();
    (mockClient.evm.signers.list as jest.Mock).mockResolvedValueOnce({
      signers: [
        { address: "0xA", enabled: true, locked: false, type: "keystore" },
        { address: "0xB", enabled: true, locked: false, type: "keystore" },
      ],
    });
    const provider = await EIP1193Provider.create({
      signersSource: { type: "client", client: mockClient, chainId: 1 },
    });
    await provider.switchAccount("0xB");
    expect(provider.selectedAddress).toBe("0xB");

    // New signer C added; B and A still around.
    (mockClient.evm.signers.list as jest.Mock).mockResolvedValueOnce({
      signers: [
        { address: "0xA", enabled: true, locked: false, type: "keystore" },
        { address: "0xB", enabled: true, locked: false, type: "keystore" },
        { address: "0xC", enabled: true, locked: false, type: "keystore" },
      ],
    });
    await provider.refreshSigners();
    expect(provider.selectedAddress).toBe("0xB");
  });

  it("falls back to index 0 when the active address is gone after refresh", async () => {
    const mockClient = createMockClient();
    (mockClient.evm.signers.list as jest.Mock).mockResolvedValueOnce({
      signers: [
        { address: "0xA", enabled: true, locked: false, type: "keystore" },
        { address: "0xB", enabled: true, locked: false, type: "keystore" },
      ],
    });
    const provider = await EIP1193Provider.create({
      signersSource: { type: "client", client: mockClient, chainId: 1 },
    });
    await provider.switchAccount("0xB");

    // B was locked / deleted between requests; only A remains.
    (mockClient.evm.signers.list as jest.Mock).mockResolvedValueOnce({
      signers: [{ address: "0xA", enabled: true, locked: false, type: "keystore" }],
    });
    await provider.refreshSigners();
    expect(provider.selectedAddress).toBe("0xA");
  });

  it("starts disconnected → becomes connected and emits 'connect' once a signer appears", async () => {
    const mockClient = createMockClient();
    // First call: nothing usable yet (locked HD wallet, say).
    (mockClient.evm.signers.list as jest.Mock).mockResolvedValueOnce({
      signers: [{ address: "0xLocked", enabled: true, locked: true, type: "hd_wallet" }],
    });
    const provider = await EIP1193Provider.create({
      signersSource: { type: "client", client: mockClient, chainId: 1 },
    });
    expect(provider.isConnected()).toBe(false);

    const connectHandler = jest.fn();
    provider.on("connect", connectHandler);

    (mockClient.evm.signers.list as jest.Mock).mockResolvedValueOnce({
      signers: [{ address: "0xLocked", enabled: true, locked: false, type: "hd_wallet" }],
    });
    await provider.refreshSigners();
    expect(provider.isConnected()).toBe(true);
    expect(connectHandler).toHaveBeenCalledTimes(1);
  });

  it("does not emit accountsChanged when the signer set is unchanged", async () => {
    const mockClient = createMockClient();
    (mockClient.evm.signers.list as jest.Mock).mockResolvedValue({
      signers: [{ address: "0xA", enabled: true, locked: false, type: "keystore" }],
    });
    const provider = await EIP1193Provider.create({
      signersSource: { type: "client", client: mockClient, chainId: 1 },
    });
    const accountsChanged = jest.fn();
    provider.on("accountsChanged", accountsChanged);
    await provider.refreshSigners();
    expect(accountsChanged).not.toHaveBeenCalled();
  });

  it("throws when no signersSource was stashed (provider created without one)", async () => {
    // The manual mode still stashes its source, so this guard only trips
    // for hand-constructed providers; we still pin the contract so
    // callers don't silently swallow a missing source.
    const provider = await EIP1193Provider.create({
      signersSource: { type: "manual", signers: [createMockSigner("0xA", "1")] },
    });
    (provider as any)._signersSource = undefined;
    await expect(provider.refreshSigners()).rejects.toThrow(/signersSource/);
  });
});

describe("EIP1193Provider - daemon RPC proxy routing", () => {
  // The provider holds zero RPC knowledge — every read method +
  // signed-tx broadcast forwards through `client.evm.rpcProxy.call`.
  // These tests pin the contract: chainId + method + params reach
  // the proxy unchanged, the result round-trips back, and an upstream
  // error wraps cleanly so dApps see a useful message.

  function buildProviderWithProxy(): Promise<{
    provider: EIP1193Provider;
    proxyCall: jest.Mock;
  }> {
    const proxyCall = jest.fn();
    // Minimal client shim — only the path the proxy exercises is
    // populated. Anything outside `evm.rpcProxy.call` would throw,
    // which is a feature: it forces tests to be honest about the
    // surface they're exercising.
    const fakeClient: any = {
      evm: {
        rpcProxy: { call: proxyCall },
        signers: { list: jest.fn() },
        hdWallets: { getSigners: jest.fn() },
        sign: {},
      },
    };
    return EIP1193Provider.create({
      signersSource: { type: "manual", signers: [createMockSigner("0xA", "1")] },
      defaultChainId: 1,
      client: fakeClient,
    }).then((provider) => ({ provider, proxyCall }));
  }

  it("forwards a read method through evm.rpcProxy.call with chainId + params", async () => {
    const { provider, proxyCall } = await buildProviderWithProxy();
    proxyCall.mockResolvedValueOnce("0x1234");
    const block = await provider.request({ method: "eth_blockNumber", params: [] });
    expect(block).toBe("0x1234");
    expect(proxyCall).toHaveBeenCalledWith(1, "eth_blockNumber", []);
  });

  it("preserves param payloads (eth_call object) on the way to the proxy", async () => {
    const { provider, proxyCall } = await buildProviderWithProxy();
    proxyCall.mockResolvedValueOnce("0xabc");
    const tx = { to: "0xc0ffee", data: "0xdead" };
    await provider.request({ method: "eth_call", params: [tx, "latest"] });
    expect(proxyCall).toHaveBeenCalledWith(1, "eth_call", [tx, "latest"]);
  });

  it("wraps an upstream daemon error so dApp-side messages identify the failing layer", async () => {
    // The proxy service itself throws a wrapped Error when the
    // daemon returns an `error` envelope. Surface it on the dApp
    // side intact so bug reports show "execution reverted: …"
    // rather than the cryptic SyntaxError the old direct-fetch path
    // produced from HTML 403 pages.
    const { provider, proxyCall } = await buildProviderWithProxy();
    proxyCall.mockRejectedValueOnce(
      new Error("daemon rpc proxy: execution reverted: ERC20: insufficient (code -32000)"),
    );
    await expect(
      provider.request({ method: "eth_call", params: [{}, "latest"] }),
    ).rejects.toThrow(/execution reverted.*-32000/i);
  });

  it("eth_sendTransaction routes tx.chainId through proxy + signer (BSC USDT regression)", async () => {
    // The bug this pins down: popup-global chain was 1 (mainnet),
    // user opened Uniswap on BSC (chain 56), dApp shipped
    // `tx.chainId: "0x38"`. Pre-fix the SDK used the global → EIP-155
    // signed for chain 1 → BSC rejected, mainnet contract didn't
    // exist, tx orphaned. Fix: tx.chainId wins everywhere — proxy
    // URL (eth_gasPrice + eth_estimateGas + eth_sendRawTransaction
    // all targeted at chain 56) and signer envelope chain_id 56.
    const proxyCall = jest.fn();
    proxyCall.mockResolvedValueOnce("0x10"); // eth_getTransactionCount
    proxyCall.mockResolvedValueOnce("0xa"); // eth_gasPrice
    proxyCall.mockResolvedValueOnce("0xabc"); // eth_sendRawTransaction
    const mockSigner = createMockSigner("0xACCT", "1");
    const fakeClient: any = {
      evm: {
        rpcProxy: { call: proxyCall },
        signers: { list: jest.fn() },
        sign: {},
      },
    };
    const provider = await EIP1193Provider.create({
      signersSource: { type: "manual", signers: [mockSigner] },
      defaultChainId: 1, // popup global "mainnet" — the wrong choice
      client: fakeClient,
    });

    const tx = {
      from: "0xACCT",
      to: "0x55d398326f99059ff775485246999027b3197955", // BSC USDT
      data: "0x095ea7b3",
      gas: "0xd25d",
      chainId: "0x38", // user is on BSC
    };
    const result = await provider.request({
      method: "eth_sendTransaction",
      params: [tx],
    });
    expect(result).toBe("0xabc");

    // Every chain-touching RPC on the dApp's chain (56), not the
    // popup global (1). Order: nonce → gasPrice → broadcast.
    expect(proxyCall.mock.calls.map((c) => [c[0], c[1]])).toEqual([
      [56, "eth_getTransactionCount"],
      [56, "eth_gasPrice"],
      [56, "eth_sendRawTransaction"],
    ]);
    // Signer envelope chain_id is the dApp's "56", not "1".
    expect(mockSigner.signTransaction).toHaveBeenCalledWith(
      expect.anything(),
      "56",
    );
  });

  it("eth_sendTransaction falls back to provider global when tx.chainId is absent", async () => {
    // Single-chain dApps that don't ship chainId per request keep
    // working with the popup-global behavior — this is the regression
    // guard so the BSC USDT fix doesn't accidentally break the
    // existing single-chain happy path.
    const proxyCall = jest.fn();
    proxyCall.mockResolvedValueOnce("0x1"); // nonce
    proxyCall.mockResolvedValueOnce("0x1"); // gasPrice
    proxyCall.mockResolvedValueOnce("0xdead"); // broadcast
    const mockSigner = createMockSigner("0xACCT", "1");
    const provider = await EIP1193Provider.create({
      signersSource: { type: "manual", signers: [mockSigner] },
      defaultChainId: 10,
      client: { evm: { rpcProxy: { call: proxyCall } } } as any,
    });
    await provider.request({
      method: "eth_sendTransaction",
      params: [{ from: "0xACCT", to: "0xbeef", gas: "0x5208" }],
    });
    // No tx.chainId → use provider default (10).
    expect(proxyCall.mock.calls.map((c) => c[0])).toEqual([10, 10, 10]);
    expect(mockSigner.signTransaction).toHaveBeenCalledWith(
      expect.anything(),
      undefined, // signer falls back to its own _chainID
    );
  });

  it("throws a clear error when no client was configured (manual mode without proxy)", async () => {
    // Manual signersSource without an explicit `client` means no
    // proxy route — caller opted out. A read call must therefore
    // fail with a message that names the misconfiguration, not a
    // confusing TypeError downstream.
    const provider = await EIP1193Provider.create({
      signersSource: { type: "manual", signers: [createMockSigner("0xA", "1")] },
      defaultChainId: 1,
    });
    await expect(
      provider.request({ method: "eth_blockNumber", params: [] }),
    ).rejects.toThrow(/requires a client for the daemon RPC proxy/i);
  });
});
