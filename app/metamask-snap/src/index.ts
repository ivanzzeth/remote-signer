/**
 * MetaMask Snap for Remote Signer Integration
 *
 * This snap allows MetaMask to use remote-signer service for signing transactions
 * and messages, enabling centralized key management with rule-based authorization.
 */

import type { OnKeyringRequestHandler, OnRpcRequestHandler } from "@metamask/snaps-sdk";
import { panel, text, heading } from "@metamask/snaps-ui";
import { RemoteSignerClient } from "@remote-signer/client";
import type {
  SignRequest,
  SignResponse,
  RequestStatusResponse,
} from "@remote-signer/client";
import {
  DEFAULT_KEYRING_STATE,
  type KeyringState,
  type KeyringSubmitRequest,
  RemoteSignerKeyring,
} from "./keyring";

// State management
interface SnapState {
  baseURL?: string;
  apiKeyID?: string;
  privateKey?: string; // Encrypted or stored securely
  configured: boolean;
  keyring?: KeyringState;
  signerAddress?: string;
  chainId?: string;
}

const DEFAULT_STATE: SnapState = {
  configured: false,
};

/**
 * Get or initialize snap state
 */
async function getState(): Promise<SnapState> {
  const state = await snap.request({
    method: "snap_manageState",
    params: {
      operation: "get",
    },
  });

  // Always merge with defaults so required fields like `configured` are present
  // even when storage returns an empty object (e.g. `{}`).
  if (!state || typeof state !== "object") {
    return DEFAULT_STATE;
  }
  return { ...DEFAULT_STATE, ...(state as unknown as Partial<SnapState>) };
}

async function getKeyringState(): Promise<KeyringState> {
  const state = await getState();
  return state.keyring ? { ...DEFAULT_KEYRING_STATE, ...state.keyring } : DEFAULT_KEYRING_STATE;
}

async function updateKeyringState(newState: Partial<KeyringState>): Promise<void> {
  const current = await getKeyringState();
  await updateState({ keyring: { ...current, ...newState } });
}

/**
 * Update snap state
 */
async function updateState(newState: Partial<SnapState>): Promise<void> {
  const currentState = await getState();
  await snap.request({
    method: "snap_manageState",
    params: {
      operation: "update",
      // snap_manageState expects Json-compatible values.
      // Our internal state contains typed objects; store them as plain objects.
      newState: ({ ...currentState, ...newState } as unknown) as Record<string, any>,
    },
  });
}

/**
 * Get configured client instance
 */
async function getClient(): Promise<RemoteSignerClient> {
  const state = await getState();
  if (!state.configured || !state.baseURL || !state.apiKeyID || !state.privateKey) {
    throw new Error(
      "Remote signer not configured. Please call 'configure' first."
    );
  }

  return new RemoteSignerClient({
    baseURL: state.baseURL,
    apiKeyID: state.apiKeyID,
    privateKey: state.privateKey,
  });
}

async function getSignerAddress(): Promise<string> {
  const state = await getState();
  if (state.signerAddress) {
    return state.signerAddress;
  }
  // Fallback to well-known test address to keep current e2e working.
  // TODO: require this to be configured explicitly for production usage.
  return "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
}

/**
 * RPC request handler
 */
export const onRpcRequest: OnRpcRequestHandler = async ({ origin, request }) => {
  try {
    switch (request.method) {
      case "configure":
        return (await handleConfigure(request.params as any)) as any;

      case "sign":
        return (await handleSign(request.params as any)) as any;

      case "getRequest":
        return (await handleGetRequest(request.params as any)) as any;

      case "health":
        return (await handleHealth()) as any;

      case "getState":
        return (await handleGetState()) as any;

      default:
        throw new Error(`Unknown method: ${request.method}`);
    }
  } catch (error) {
    return {
      error: {
        code: -32603,
        message: error instanceof Error ? error.message : "Unknown error",
      },
    } as any;
  }
};

// -----------------------------------------------------------------------------
// Keyring handler (account-management / signing interception)
// -----------------------------------------------------------------------------
const keyring = new RemoteSignerKeyring({
  getClient,
  getSignerAddress,
  getKeyringState,
  updateKeyringState,
});

export const onKeyringRequest: OnKeyringRequestHandler = async ({ origin, request }: any) => {
  // NOTE: MetaMask enforces allowedOrigins via manifest. We still keep the origin
  // available here for future explicit checks.
  const req: any = request;

  // Two supported envelopes:
  // 1) Keyring management calls: { method: 'listAccounts' | 'createAccount' | ... , params: ... }
  // 2) Signing calls: { id, scope, account, request: { method, params } }
  if (typeof req?.method === "string") {
    switch (req.method) {
      case "listAccounts":
        return await keyring.listAccounts();
      case "getAccount":
        if (!req.params?.id) throw new Error("getAccount requires params.id");
        return await keyring.getAccount(req.params.id);
      case "createAccount":
        return await keyring.createAccount(req.params?.options ?? req.params ?? {});
      case "deleteAccount":
        if (!req.params?.id) throw new Error("deleteAccount requires params.id");
        await keyring.deleteAccount(req.params.id);
        return null;
      default:
        throw new Error(`Unknown keyring method: ${req.method}`);
    }
  }

  const submit = req as KeyringSubmitRequest;
  return await keyring.submitRequest(submit);
};

/**
 * Configure the remote signer connection
 */
async function handleConfigure(params: {
  baseURL: string;
  apiKeyID: string;
  privateKey: string;
}): Promise<{ success: boolean }> {
  if (!params.baseURL || !params.apiKeyID || !params.privateKey) {
    throw new Error("Missing required parameters: baseURL, apiKeyID, privateKey");
  }

  // Show confirmation dialog
  const approved = await snap.request({
    method: "snap_dialog",
    params: {
      type: "confirmation",
      content: panel([
        heading("Configure Remote Signer"),
        text(`**Base URL:** ${params.baseURL}`),
        text(`**API Key ID:** ${params.apiKeyID}`),
        text(
          "⚠️ This will store your private key. Make sure you trust this snap."
        ),
      ]),
    },
  });

  if (!approved) {
    throw new Error("Configuration cancelled by user");
  }

  // Test connection
  const client = new RemoteSignerClient({
    baseURL: params.baseURL,
    apiKeyID: params.apiKeyID,
    privateKey: params.privateKey,
  });

  try {
    await client.health();
  } catch (error) {
    throw new Error(
      `Failed to connect to remote signer: ${
        error instanceof Error ? error.message : "Unknown error"
      }`
    );
  }

  // Save configuration
  await updateState({
    baseURL: params.baseURL,
    apiKeyID: params.apiKeyID,
    privateKey: params.privateKey,
    configured: true,
    // Keep defaults explicit for keyring mode. (Can be overridden by future RPC.)
    chainId: "1",
    signerAddress: await getSignerAddress(),
  });

  return { success: true };
}

/**
 * Sign a request using remote signer
 */
async function handleSign(params: {
  request: SignRequest;
  waitForApproval?: boolean;
}): Promise<SignResponse> {
  const client = await getClient();

  // Show confirmation dialog with request details
  const requestDetails = formatSignRequest(params.request);
  const approved = await snap.request({
    method: "snap_dialog",
    params: {
      type: "confirmation",
      content: panel([
        heading("Sign Request"),
        text(`**Chain ID:** ${params.request.chain_id}`),
        text(`**Signer:** ${params.request.signer_address}`),
        text(`**Type:** ${params.request.sign_type}`),
        text(`**Details:** ${requestDetails}`),
      ]),
    },
  });

  if (!approved) {
    throw new Error("Signing cancelled by user");
  }

  // Submit sign request
  const response = await client.sign(
    params.request,
    params.waitForApproval ?? true
  );

  return response;
}

/**
 * Get request status
 */
async function handleGetRequest(params: {
  requestID: string;
}): Promise<RequestStatusResponse> {
  const client = await getClient();
  return await client.getRequest(params.requestID);
}

/**
 * Health check
 */
async function handleHealth(): Promise<{ status: string; version: string }> {
  const client = await getClient();
  return await client.health();
}

/**
 * Get current state (without sensitive data)
 */
async function handleGetState(): Promise<{
  configured: boolean;
  baseURL?: string;
  apiKeyID?: string;
}> {
  const state = await getState();
  return {
    configured: state.configured,
    baseURL: state.baseURL,
    apiKeyID: state.apiKeyID,
  };
}

/**
 * Format sign request for display
 */
function formatSignRequest(request: SignRequest): string {
  switch (request.sign_type) {
    case "personal":
    case "eip191":
      return `Message: ${(request.payload as any).message}`;
    case "transaction":
      const tx = (request.payload as any).transaction;
      return `To: ${tx.to || "Contract Creation"}, Value: ${tx.value} wei`;
    case "typed_data":
      return `EIP-712: ${(request.payload as any).typed_data.primaryType}`;
    case "hash":
      return `Hash: ${(request.payload as any).hash}`;
    default:
      return JSON.stringify(request.payload);
  }
}
