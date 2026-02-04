import type { RemoteSignerClient, SignRequest } from "@remote-signer/client";

export type Json =
  | null
  | boolean
  | number
  | string
  | Json[]
  | { [key: string]: Json };

export interface KeyringAccount {
  [key: string]: Json;
  id: string; // UUID
  address: string; // EVM address
  type: string; // e.g. 'eip155:eoa'
  methods: string[]; // supported JSON-RPC methods
  options: Record<string, Json>;
}

export interface KeyringSubmitRequest {
  id: string;
  scope: string;
  account: string;
  request: {
    method: string;
    params?: Json;
  };
}

export interface KeyringResponse {
  [key: string]: Json;
  pending: false;
  result: Json;
}

export interface KeyringState {
  accounts: KeyringAccount[];
  // Optional default chain id for requests when MetaMask doesn't provide it yet.
  defaultChainId?: string;
}

export const DEFAULT_KEYRING_STATE: KeyringState = {
  accounts: [],
};

export class RemoteSignerKeyring {
  private readonly getClient: () => Promise<RemoteSignerClient>;
  private readonly getSignerAddress: () => Promise<string>;
  private readonly getKeyringState: () => Promise<KeyringState>;
  private readonly updateKeyringState: (newState: Partial<KeyringState>) => Promise<void>;

  public constructor(args: {
    getClient: () => Promise<RemoteSignerClient>;
    getSignerAddress: () => Promise<string>;
    getKeyringState: () => Promise<KeyringState>;
    updateKeyringState: (newState: Partial<KeyringState>) => Promise<void>;
  }) {
    this.getClient = args.getClient;
    this.getSignerAddress = args.getSignerAddress;
    this.getKeyringState = args.getKeyringState;
    this.updateKeyringState = args.updateKeyringState;
  }

  public async listAccounts(): Promise<KeyringAccount[]> {
    const state = await this.getKeyringState();
    return state.accounts;
  }

  public async getAccount(id: string): Promise<KeyringAccount> {
    const state = await this.getKeyringState();
    const acct = state.accounts.find((a) => a.id === id);
    if (!acct) {
      throw new Error(`Account not found: ${id}`);
    }
    return acct;
  }

  public async createAccount(options?: Record<string, Json>): Promise<KeyringAccount> {
    const addressOpt = options?.address;
    if (typeof addressOpt !== "string" || !addressOpt) {
      throw new Error("createAccount requires options.address");
    }

    const id = crypto.randomUUID();
    const acct: KeyringAccount = {
      id,
      address: addressOpt,
      type: "eip155:eoa",
      methods: [
        "personal_sign",
        "eth_sign",
        "eth_signTypedData",
        "eth_signTypedData_v3",
        "eth_signTypedData_v4",
        "eth_signTransaction",
      ],
      options: options ?? {},
    };

    const state = await this.getKeyringState();
    await this.updateKeyringState({ accounts: [...state.accounts, acct] });
    return acct;
  }

  public async deleteAccount(id: string): Promise<void> {
    const state = await this.getKeyringState();
    const next = state.accounts.filter((a) => a.id !== id);
    if (next.length === state.accounts.length) {
      throw new Error(`Account not found: ${id}`);
    }
    await this.updateKeyringState({ accounts: next });
  }

  public async submitRequest(req: KeyringSubmitRequest): Promise<KeyringResponse> {
    if (!req?.request?.method) {
      throw new Error("Invalid keyring request: missing request.method");
    }

    const method = req.request.method;
    const params = req.request.params;

    // For now MetaMask provides the signer address in params for many methods,
    // but we also support deriving it from configured state.
    const configuredSigner = await this.getSignerAddress();

    const client = await this.getClient();
    const chainId = (await this.getKeyringState()).defaultChainId ?? "1";

    const signReq: SignRequest = {
      chain_id: chainId,
      signer_address: configuredSigner,
      sign_type: "personal",
      payload: {},
    } as any;

    if (method === "personal_sign" || method === "eth_sign") {
      const { message } = parseSignMessageParams(params);
      signReq.sign_type = "personal";
      (signReq as any).payload = { message };
    } else if (
      method === "eth_signTypedData" ||
      method === "eth_signTypedData_v3" ||
      method === "eth_signTypedData_v4"
    ) {
      const { typedData } = parseTypedDataParams(params);
      signReq.sign_type = "typed_data";
      (signReq as any).payload = { typed_data: typedData };
    } else if (method === "eth_signTransaction") {
      const { tx } = parseTransactionParams(params);
      signReq.sign_type = "transaction";
      (signReq as any).payload = { transaction: tx };
    } else {
      throw new Error(`Unsupported keyring method: ${method}`);
    }

    const resp = await client.sign(signReq, true);
    if (!resp.signature) {
      throw new Error("Remote signer returned empty signature");
    }
    return { pending: false, result: resp.signature };
  }
}

function parseSignMessageParams(params: Json | undefined): { message: string } {
  if (!Array.isArray(params)) {
    throw new Error("Invalid params: expected array");
  }
  const [p0, p1] = params as Json[];
  const msg = typeof p0 === "string" ? p0 : undefined;
  const addr = typeof p1 === "string" ? p1 : undefined;
  if (!msg || !addr) {
    throw new Error("Invalid params for personal_sign/eth_sign");
  }

  // MetaMask often passes message as hex. Convert to UTF-8 when it looks like hex.
  if (msg.startsWith("0x") && isHex(msg)) {
    return { message: hexToUtf8(msg) };
  }
  return { message: msg };
}

function parseTypedDataParams(params: Json | undefined): { typedData: any } {
  if (!Array.isArray(params)) {
    throw new Error("Invalid params: expected array");
  }
  const [p0, p1] = params as Json[];
  // typical: [address, typedData]
  const typed = p1;
  if (!typed) {
    throw new Error("Invalid params for eth_signTypedData*: missing typed data");
  }
  if (typeof typed === "string") {
    try {
      return { typedData: JSON.parse(typed) };
    } catch {
      throw new Error("Invalid typed data: expected JSON string");
    }
  }
  if (typeof typed === "object") {
    return { typedData: typed };
  }
  throw new Error("Invalid typed data");
}

function parseTransactionParams(params: Json | undefined): { tx: any } {
  if (!Array.isArray(params)) {
    throw new Error("Invalid params: expected array");
  }
  const [txObj] = params as Json[];
  if (!txObj || typeof txObj !== "object") {
    throw new Error("Invalid params for eth_signTransaction: expected tx object");
  }
  const tx: any = txObj;
  if (!tx.txType) {
    throw new Error("Transaction requires txType (e.g. 'legacy')");
  }
  return { tx };
}

function isHex(s: string): boolean {
  const hex = s.startsWith("0x") ? s.slice(2) : s;
  return hex.length % 2 === 0 && /^[0-9a-fA-F]*$/.test(hex);
}

function hexToUtf8(hexWith0x: string): string {
  const hex = hexWith0x.startsWith("0x") ? hexWith0x.slice(2) : hexWith0x;
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return new TextDecoder().decode(bytes);
}
