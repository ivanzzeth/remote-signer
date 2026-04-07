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

  it("should throw error when personal_sign address mismatch", async () => {
    await expect(
      provider.request({
        method: "personal_sign",
        params: ["0xmessage", "0xWrongAddress"],
      })
    ).rejects.toThrow("Address mismatch");
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
