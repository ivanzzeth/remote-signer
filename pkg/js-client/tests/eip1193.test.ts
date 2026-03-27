import { EIP1193Provider } from "../src/evm/eip1193";
import { RemoteSigner } from "../src/evm/remote_signer";
import type { EvmSignService } from "../src/evm/sign";
import type { SignRequest } from "../src/evm/sign";

// ---------------------------------------------------------------------------
// Mock EvmSignService
// ---------------------------------------------------------------------------

function createMockSignService(): EvmSignService {
  return {
    execute: jest.fn(async (req: SignRequest) => {
      switch (req.sign_type) {
        case "personal":
          return { request_id: "req-1", status: "completed" as const, signature: "0x" + "ab".repeat(65) };
        case "typed_data":
          return { request_id: "req-2", status: "completed" as const, signature: "0x" + "cd".repeat(65) };
        case "hash":
          return { request_id: "req-3", status: "completed" as const, signature: "0x" + "ef".repeat(65) };
        case "transaction":
          return { request_id: "req-4", status: "completed" as const, signed_data: "0x02f8" + "00".repeat(50) };
        default:
          throw new Error(`Unexpected sign_type: ${req.sign_type}`);
      }
    }),
    executeAsync: jest.fn(),
  } as unknown as EvmSignService;
}

// ---------------------------------------------------------------------------
// Mock RPC (via fetch)
// ---------------------------------------------------------------------------

const mockRpcResponses: Record<string, unknown> = {
  eth_getTransactionCount: "0x5",
  eth_estimateGas: "0x5208",
  eth_gasPrice: "0x3B9ACA00",
  eth_getBalance: "0x56BC75E2D63100000",
  eth_blockNumber: "0x134e82a",
  eth_call: "0x",
  eth_getCode: "0x",
  eth_sendRawTransaction: "0x" + "aa".repeat(32),
  eth_getBlockByNumber: { baseFeePerGas: "0x3B9ACA00" },
};

const originalFetch = global.fetch;

beforeAll(() => {
  global.fetch = jest.fn(async (_url: string | URL | Request, init?: RequestInit) => {
    const body = JSON.parse(init?.body as string);
    const result = mockRpcResponses[body.method];
    if (result === undefined) {
      return {
        ok: true,
        json: async () => ({
          jsonrpc: "2.0", id: body.id,
          error: { code: -32601, message: `Method not found: ${body.method}` },
        }),
      } as Response;
    }
    return {
      ok: true,
      json: async () => ({ jsonrpc: "2.0", id: body.id, result }),
    } as Response;
  }) as jest.Mock;
});

afterAll(() => {
  global.fetch = originalFetch;
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const ADDRESS = "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18";

describe("EIP1193Provider", () => {
  let provider: EIP1193Provider;
  let signService: EvmSignService;
  let signer: RemoteSigner;

  beforeEach(async () => {
    signService = createMockSignService();
    signer = new RemoteSigner(signService, ADDRESS, "1");
    provider = await EIP1193Provider.create({
      signer,
      defaultChainId: 1,
      rpcOverrides: { 1: "https://eth.example.com", 137: "https://polygon.example.com" },
    });
  });

  // -- Account methods --

  test("eth_requestAccounts returns signer address", async () => {
    expect(await provider.request({ method: "eth_requestAccounts" })).toEqual([ADDRESS]);
  });

  test("eth_accounts returns signer address", async () => {
    expect(await provider.request({ method: "eth_accounts" })).toEqual([ADDRESS]);
  });

  // -- Chain methods --

  test("eth_chainId returns hex chain ID", async () => {
    expect(await provider.request({ method: "eth_chainId" })).toBe("0x1");
  });

  test("net_version returns decimal chain ID", async () => {
    expect(await provider.request({ method: "net_version" })).toBe("1");
  });

  // -- Properties --

  test("selectedAddress returns address", () => {
    expect(provider.selectedAddress).toBe(ADDRESS);
  });

  test("isMetaMask is true", () => {
    expect(provider.isMetaMask).toBe(true);
  });

  test("isConnected returns true", () => {
    expect(provider.isConnected()).toBe(true);
  });

  // -- personal_sign --

  test("personal_sign decodes hex message to UTF-8", async () => {
    const hexMessage = "0x48656c6c6f"; // "Hello"
    const sig = await provider.request({ method: "personal_sign", params: [hexMessage, ADDRESS] });
    expect(sig).toBe("0x" + "ab".repeat(65));
    expect(signService.execute).toHaveBeenCalledWith(
      expect.objectContaining({ chain_id: "1", sign_type: "personal", payload: { message: "Hello" } }),
    );
  });

  test("personal_sign passes plain text as-is", async () => {
    const plainMessage = "Hello, World!";
    const sig = await provider.request({ method: "personal_sign", params: [plainMessage, ADDRESS] });
    expect(sig).toBe("0x" + "ab".repeat(65));
    expect(signService.execute).toHaveBeenCalledWith(
      expect.objectContaining({ chain_id: "1", sign_type: "personal", payload: { message: "Hello, World!" } }),
    );
  });

  // -- eth_sign --

  test("eth_sign calls signer.signHash", async () => {
    const hash = "0x" + "11".repeat(32);
    const sig = await provider.request({ method: "eth_sign", params: [ADDRESS, hash] });
    expect(sig).toBe("0x" + "ef".repeat(65));
  });

  // -- eth_signTypedData_v4 --

  test("eth_signTypedData_v4 with object", async () => {
    const typedData = {
      types: { EIP712Domain: [], Test: [{ name: "value", type: "uint256" }] },
      primaryType: "Test",
      domain: { name: "Test", chainId: "1" },
      message: { value: "42" },
    };
    const sig = await provider.request({ method: "eth_signTypedData_v4", params: [ADDRESS, typedData] });
    expect(sig).toBe("0x" + "cd".repeat(65));
  });

  test("eth_signTypedData_v4 with JSON string", async () => {
    const typedData = {
      types: { EIP712Domain: [], Test: [{ name: "value", type: "uint256" }] },
      primaryType: "Test",
      domain: { name: "Test", chainId: "1" },
      message: { value: "42" },
    };
    const sig = await provider.request({ method: "eth_signTypedData_v4", params: [ADDRESS, JSON.stringify(typedData)] });
    expect(sig).toBe("0x" + "cd".repeat(65));
  });

  // -- eth_sendTransaction --

  test("eth_sendTransaction fills nonce/gas, signs, and broadcasts", async () => {
    const txHash = await provider.request({
      method: "eth_sendTransaction",
      params: [{ from: ADDRESS, to: "0x" + "12".repeat(20), value: "0xDE0B6B3A7640000", data: "0x" }],
    });

    expect(txHash).toBe("0x" + "aa".repeat(32));
    expect(signService.execute).toHaveBeenCalledWith(
      expect.objectContaining({
        sign_type: "transaction",
        payload: expect.objectContaining({
          transaction: expect.objectContaining({ nonce: 5, gas: 21000 }),
        }),
      }),
    );
  });

  // -- wallet_switchEthereumChain --

  test("wallet_switchEthereumChain updates chain ID and signer", async () => {
    const events: string[] = [];
    provider.on("chainChanged", (id) => events.push(id as string));

    await provider.request({ method: "wallet_switchEthereumChain", params: [{ chainId: "0x89" }] });

    expect(await provider.request({ method: "eth_chainId" })).toBe("0x89");
    expect(await provider.request({ method: "net_version" })).toBe("137");
    expect(signer.chainID).toBe("137"); // signer updated too
    expect(events).toEqual(["0x89"]);
  });

  test("wallet_switchEthereumChain same chain is noop", async () => {
    const events: string[] = [];
    provider.on("chainChanged", (id) => events.push(id as string));

    await provider.request({ method: "wallet_switchEthereumChain", params: [{ chainId: "0x1" }] });
    expect(events).toEqual([]);
  });

  test("signing uses updated chain ID after switch", async () => {
    await provider.request({ method: "wallet_switchEthereumChain", params: [{ chainId: "0x89" }] });
    await provider.request({ method: "personal_sign", params: ["hello", ADDRESS] });

    expect(signService.execute).toHaveBeenCalledWith(
      expect.objectContaining({ chain_id: "137" }),
    );
  });

  // -- RPC proxy --

  test("eth_getBalance is proxied to RPC", async () => {
    expect(await provider.request({ method: "eth_getBalance", params: [ADDRESS, "latest"] }))
      .toBe("0x56BC75E2D63100000");
  });

  test("unsupported RPC method returns error", async () => {
    await expect(provider.request({ method: "eth_foobar" }))
      .rejects.toThrow("Method not found");
  });

  // -- Events --

  test("on/removeListener work correctly", () => {
    const listener = jest.fn();
    provider.on("test", listener);
    // @ts-expect-error - accessing private for testing
    provider._emit("test", "data");
    expect(listener).toHaveBeenCalledWith("data");

    provider.removeListener("test", listener);
    // @ts-expect-error
    provider._emit("test", "data2");
    expect(listener).toHaveBeenCalledTimes(1);
  });

  test("removeAllListeners clears all", () => {
    const listener = jest.fn();
    provider.on("a", listener);
    provider.on("b", listener);
    provider.removeAllListeners();
    // @ts-expect-error
    provider._emit("a", "x");
    // @ts-expect-error
    provider._emit("b", "y");
    expect(listener).not.toHaveBeenCalled();
  });

  // -- Legacy methods --

  test("enable() returns accounts", async () => {
    expect(await provider.enable()).toEqual([ADDRESS]);
  });

  test("sendAsync calls request and returns via callback", (done) => {
    provider.sendAsync({ id: 1, method: "eth_chainId" }, (error, result: any) => {
      expect(error).toBeNull();
      expect(result.result).toBe("0x1");
      expect(result.jsonrpc).toBe("2.0");
      done();
    });
  });
});

describe("RemoteSigner.setChainID", () => {
  test("chainID is mutable via setChainID", () => {
    const signService = createMockSignService();
    const signer = new RemoteSigner(signService, ADDRESS, "1");
    expect(signer.chainID).toBe("1");

    signer.setChainID("137");
    expect(signer.chainID).toBe("137");
  });

  test("signing uses new chainID after setChainID", async () => {
    const signService = createMockSignService();
    const signer = new RemoteSigner(signService, ADDRESS, "1");
    signer.setChainID("42161"); // Arbitrum
    await signer.personalSign("hello");

    expect(signService.execute).toHaveBeenCalledWith(
      expect.objectContaining({ chain_id: "42161" }),
    );
  });
});
